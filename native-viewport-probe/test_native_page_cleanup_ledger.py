"""In-memory filesystem and resource faults only: no OS/device mutation."""
from __future__ import annotations

from contextlib import contextmanager
import copy
from dataclasses import dataclass
import hashlib
import json
import unittest

from native_page_cleanup_ledger import (
    AuthorityError, CleanupLedger, CorruptLedger, Observation, PersistenceError,
    RecoveryCheckpoint, ResourceIdentity, canonical_json, decode_record,
)


EVIDENCE = "a" * 64
BASELINE = "b" * 64
CLOCK_ID = "boot:11111111-1111-1111-1111-111111111111"
IDENTITY = ResourceIdentity("process", "test-device", "123",
                            "11111111-1111-1111-1111-111111111111:456")
OWNER = "coordinator"

# This expected header is generated from caller-known identity, not read from
# the mutable store under test. Tests that protect a later committed prefix use
# the explicit checkpoint returned before tampering/failure instead.
HEADER_CHECKPOINT = RecoveryCheckpoint("1" * 32, 0, hashlib.sha256(canonical_json(dict(
    version=1, sequence=0, previous_hash="0" * 64, event="opened",
    data=dict(ledger_id="1" * 32, clock_id=CLOCK_ID), remaining=[]))).hexdigest())


def recover_ledger(store, clock, clock_id, *, checkpoint=HEADER_CHECKPOINT):
    return CleanupLedger.recover(store, clock, clock_id, checkpoint=checkpoint)


@dataclass
class File:
    data: bytes = b""
    synced: bytes | None = None


@dataclass
class Handle:
    file: File
    closed: bool = False


class FakeStore:
    """Atomic rename and explicit durability modeled separately from visibility."""

    def __init__(self, *, chunk_size=47):
        self.files = {}
        self.durable = {}
        self.chunk_size = chunk_size
        self.log = []
        self.fault = None
        self.held = False
        self.reverse_listing = False
        self.extra_names = []

    def clone(self):
        result = FakeStore(chunk_size=self.chunk_size)
        result.files = copy.deepcopy(self.files)
        result.durable = copy.deepcopy(self.durable)
        return result

    @contextmanager
    def exclusive(self):
        if self.held:
            raise AuthorityError("exclusive store lease is already held")
        self.held = True
        try:
            yield
        finally:
            self.held = False

    def _perform(self, name, action):
        self.log.append(name)
        index = len(self.log)
        if self.fault == (index, "before"):
            raise OSError(f"injected before {name} boundary {index}")
        result = action()
        if self.fault == (index, "after"):
            raise OSError(f"injected after {name} boundary {index}")
        return result

    def names(self):
        result = list(self.files) + self.extra_names
        return list(reversed(result)) if self.reverse_listing else result

    def read(self, name):
        return self.files[name].data

    def create(self, name):
        def action():
            if name in self.files:
                raise FileExistsError(name)
            self.files[name] = File()
            return Handle(self.files[name])
        return self._perform("create", action)

    def write(self, handle, payload):
        def action():
            if handle.closed:
                raise OSError("closed handle")
            chunk = payload[:self.chunk_size]
            handle.file.data += chunk
            return len(chunk)
        return self._perform("write", action)

    def fsync_file(self, handle):
        return self._perform("fsync_file", lambda: setattr(handle.file, "synced", handle.file.data))

    def close(self, handle):
        def action():
            if handle.closed:
                raise OSError("handle already closed")
            handle.closed = True
        return self._perform("close", action)

    def rename_no_replace(self, source, destination):
        def action():
            if destination in self.files:
                raise FileExistsError(destination)
            self.files[destination] = self.files.pop(source)
        return self._perform("rename", action)

    def fsync_directory(self):
        def action():
            self.durable = {name: file.synced if file.synced is not None else b""
                            for name, file in self.files.items()}
        return self._perform("fsync_directory", action)

    def crash(self):
        self.files = {name: File(data, data) for name, data in self.durable.items()}
        self.fault = None
        self.log = []
        self.held = False

    def records(self):
        return [decode_record(self.files[name].data) for name in sorted(self.files)
                if name.endswith(".json")]


class World:
    def __init__(self, store):
        self.store = store
        self.present = True
        self.calls = 0
        self.authorizations = []

    def observe(self, target):
        return Observation(target, target if self.present else None,
                           "present" if self.present else "absent", True, EVIDENCE)

    def remove(self, authorization):
        # The fake mutator itself independently checks the durable intent. No
        # actual process is touched; a boolean models external resource state.
        intents = independent_chain_oracle(self.store.durable)["records"]
        assert intents[-1]["event"] == "cleanup_intent"
        assert intents[-1]["hash"] == authorization.intent_record_sha256
        assert intents[-1]["data"]["intent_id"] == authorization.intent_id
        assert authorization.identity == IDENTITY
        assert self.store.held
        self.calls += 1
        self.authorizations.append(authorization)
        self.present = False
        return {"command_return_is_not_cleanup_proof": True}


def setup_ledger():
    store = FakeStore()
    clock = [1]
    ledger = CleanupLedger.create(store, lambda: clock[0], CLOCK_ID, ledger_id="1" * 32)
    resource = ledger.register(IDENTITY, OWNER)
    store.log = []
    return store, clock, ledger, resource


def rehash(record):
    record = copy.deepcopy(record)
    record.pop("hash", None)
    record["hash"] = hashlib.sha256(canonical_json(record)).hexdigest()
    return canonical_json(record)


def independent_chain_oracle(files):
    """Independent wire/hash/state oracle; does not use module decoding/replay."""
    def wire(value):
        return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                           separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")
    def pairs(values):
        result = {}
        for key, value in values:
            assert key not in result, "duplicate key"
            result[key] = value
        return result
    records, resources, evidence = [], {}, {}
    previous, errors, finalized = "0" * 64, 0, False
    names = sorted(name for name in files if name.endswith(".json"))
    assert names and names == [f"{i:020d}.json" for i in range(len(names))]
    for sequence, name in enumerate(names):
        payload = files[name]
        record = json.loads(payload.decode("ascii"), object_pairs_hook=pairs)
        assert wire(record) == payload
        assert set(record) == {"version", "sequence", "previous_hash", "event", "data", "remaining", "hash"}
        assert type(record["version"]) is int and record["version"] == 1
        assert type(record["sequence"]) is int and record["sequence"] == sequence
        assert record["previous_hash"] == previous
        unsigned = {key: value for key, value in record.items() if key != "hash"}
        assert hashlib.sha256(wire(unsigned)).hexdigest() == record["hash"]
        assert not finalized
        event, data = record["event"], record["data"]
        if sequence == 0:
            assert event == "opened"
        elif event == "registered":
            resource_id = hashlib.sha256(wire(data["identity"])).hexdigest()
            assert resource_id not in resources
            resources[resource_id] = dict(data, complete=False)
        elif event == "primary_error":
            errors += 1
        elif event == "cleanup_error":
            assert data["owner"] == resources[data["resource"]]["owner"]
            errors += 1
        elif event == "cleanup_intent":
            resource = resources[data["resource"]]
            assert not resource["complete"] and data["owner"] == resource["owner"]
            assert type(data["authorized_at_ns"]) is int and type(data["deadline_ns"]) is int
            assert data["authorized_at_ns"] < data["deadline_ns"]
        elif event == "cleanup_observed":
            resource = resources[data["resource"]]
            assert data["owner"] == resource["owner"] and not resource["complete"]
            assert data["observation"]["target"] == resource["identity"]
            evidence[data["resource"]] = (record["hash"], data["observation"])
        elif event == "cleanup_decision":
            resource = resources[data["resource"]]
            observation_hash, observation = evidence.pop(data["resource"])
            assert data["owner"] == resource["owner"] and data["observation_sha256"] == observation_hash
            assert type(data["success"]) is bool and type(data["decided_at_ns"]) is int
            assert type(data["deadline_ns"]) is int and data["deadline_ns"] > 0
            expected = observation["conclusive"] is True and observation["target"] == resource["identity"]
            if resource["postcondition"] == "absent":
                expected = expected and observation["status"] == "absent" and observation["actual"] is None
            else:
                expected = (expected and observation["status"] == "restored"
                            and observation["actual"] == resource["identity"]
                            and observation["state_sha256"] == resource["baseline_sha256"])
            expected = expected and data["decided_at_ns"] < data["deadline_ns"]
            assert data["success"] == expected
            resource["complete"] = expected
            errors += int(not expected)
        elif event == "finalized":
            assert all(value["complete"] for value in resources.values())
            assert data["result"] == ("cleaned_with_errors" if errors else "cleaned")
            finalized = True
        else:
            raise AssertionError("unrecognized event in independent oracle")
        assert record["remaining"] == sorted(key for key, value in resources.items() if not value["complete"])
        previous = record["hash"]
        records.append(record)
    return dict(records=records, finalized=finalized,
                remaining=sorted(key for key, value in resources.items() if not value["complete"]))


class CanonicalAuthorityTests(unittest.TestCase):
    def test_canonical_json_rejects_non_authority_types(self):
        for value in (1.0, float("nan"), (), {1: "value"}, -1, 2**63):
            with self.subTest(value=value), self.assertRaises(AuthorityError):
                canonical_json(value)
        self.assertEqual(canonical_json({"b": True, "a": "\u03b2"}),
                         b'{"a":"\\u03b2","b":true}\n')

    def test_record_wire_rejects_duplicates_whitespace_bom_nul_and_torn_data(self):
        store, _, _, _ = setup_ledger()
        payload = store.files["00000000000000000000.json"].data
        mutations = [payload[:-1], payload + b"\n", b"\xef\xbb\xbf" + payload,
                     payload.replace(b"{", b"{ ", 1), payload[:20], payload + b"\0",
                     payload.replace(b'"version":1', b'"version":1,"version":1')]
        for mutation in mutations:
            with self.subTest(mutation=mutation[:30]), self.assertRaises(CorruptLedger):
                decode_record(mutation)

    def test_exact_record_types_reject_boolean_sequence_and_version(self):
        store, _, _, _ = setup_ledger()
        record = store.records()[0]
        for key, value in (("sequence", False), ("version", True), ("remaining", [False]),
                           ("event", True), ("data", [])):
            changed = dict(record, **{key: value})
            store.files["00000000000000000000.json"].data = rehash(changed)
            with self.subTest(key=key), self.assertRaises((CorruptLedger, AuthorityError)):
                recover_ledger(store, lambda: 1, CLOCK_ID)

    def test_process_identity_cannot_be_pid_only_or_uncertain(self):
        for key, incarnation in (("123", "unknown"), ("0", IDENTITY.incarnation),
                                  ("0123", IDENTITY.incarnation), (True, IDENTITY.incarnation),
                                  ("123", None), ("123", "boot:456")):
            with self.subTest(key=key, incarnation=incarnation), self.assertRaises(AuthorityError):
                ResourceIdentity("process", "test-device", key, incarnation)

    def test_observation_requires_strict_certainty_and_complete_identity(self):
        for change in (dict(conclusive=1), dict(evidence_sha256="A" * 64),
                       dict(status="absent"), dict(target=True), dict(status="restored")):
            values = dict(target=IDENTITY, actual=IDENTITY, status="present",
                          conclusive=True, evidence_sha256=EVIDENCE)
            values.update(change)
            with self.subTest(change=change), self.assertRaises(AuthorityError):
                Observation(**values)


class ReplayTests(unittest.TestCase):
    def test_independent_oracle_rejects_missing_or_forged_terminal_decisions(self):
        store, _, ledger, resource = setup_ledger()
        world = World(store)
        ledger.attempt_cleanup(resource, OWNER, deadline_ns=100,
                               observe=world.observe, mutate=world.remove)
        ledger.finalize()
        originals = independent_chain_oracle(store.durable)["records"]
        def wire(value):
            return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
        for mutation in ("missing", "wrong-observation", "late-success", "wrong-success-type"):
            records = copy.deepcopy(originals)
            decision = next(record for record in records if record["event"] == "cleanup_decision")
            if mutation == "missing":
                records.remove(decision)
            elif mutation == "wrong-observation":
                decision["data"]["observation_sha256"] = "0" * 64
            elif mutation == "late-success":
                decision["data"]["decided_at_ns"] = decision["data"]["deadline_ns"]
            else:
                decision["data"]["success"] = 1
            files, previous = {}, "0" * 64
            for sequence, record in enumerate(records):
                record["sequence"], record["previous_hash"] = sequence, previous
                unsigned = {key: value for key, value in record.items() if key != "hash"}
                previous = hashlib.sha256(wire(unsigned)).hexdigest()
                record["hash"] = previous
                files[f"{sequence:020d}.json"] = wire(record)
            with self.subTest(mutation=mutation):
                with self.assertRaises(AssertionError):
                    independent_chain_oracle(files)
                candidate = FakeStore()
                candidate.files = {name: File(payload, payload) for name, payload in files.items()}
                with self.assertRaises(CorruptLedger):
                    recover_ledger(candidate, lambda: 1, CLOCK_ID)

    def test_checkpoint_identity_sequence_and_hash_are_exact_authority(self):
        store, _, ledger, _ = setup_ledger()
        checkpoint = ledger.checkpoint
        for changed in (RecoveryCheckpoint("2" * 32, checkpoint.sequence, checkpoint.record_sha256),
                        RecoveryCheckpoint(checkpoint.ledger_id, checkpoint.sequence + 1, checkpoint.record_sha256),
                        RecoveryCheckpoint(checkpoint.ledger_id, checkpoint.sequence, "0" * 64)):
            with self.subTest(checkpoint=changed), self.assertRaises(CorruptLedger):
                recover_ledger(store, lambda: 1, CLOCK_ID, checkpoint=changed)
        with self.assertRaises(AuthorityError):
            RecoveryCheckpoint(checkpoint.ledger_id, True, checkpoint.record_sha256)

    def test_nonempty_unanchored_ledger_is_never_recovered_or_accepted_as_new(self):
        store, _, _, _ = setup_ledger()
        with self.assertRaises(AuthorityError):
            CleanupLedger.recover(store, lambda: 1, CLOCK_ID)
        with self.assertRaises(AuthorityError):
            CleanupLedger.create(store, lambda: 1, CLOCK_ID)

    def test_deleted_committed_suffix_cannot_erase_anchored_obligations(self):
        store, _, ledger, _ = setup_ledger()
        checkpoint = ledger.checkpoint
        store.files.pop("00000000000000000001.json")
        with self.assertRaises(CorruptLedger):
            recover_ledger(store, lambda: 1, CLOCK_ID, checkpoint=checkpoint)

    def test_prior_checkpoint_retains_all_valid_suffix_obligations(self):
        store, _, ledger, resource = setup_ledger()
        recovered = recover_ledger(store, lambda: 1, CLOCK_ID, checkpoint=HEADER_CHECKPOINT)
        self.assertEqual(recovered.remaining, (resource,))
        self.assertEqual(recovered.checkpoint, ledger.checkpoint)
        with self.assertRaises(AuthorityError):
            recovered.finalize()
    def test_recovery_accepts_unordered_enumeration_but_not_reordered_records(self):
        store, _, ledger, _ = setup_ledger()
        store.reverse_listing = True
        self.assertEqual(recover_ledger(store, lambda: 1, CLOCK_ID).remaining, ledger.remaining)
        first, second = "00000000000000000000.json", "00000000000000000001.json"
        store.files[first], store.files[second] = store.files[second], store.files[first]
        with self.assertRaises(CorruptLedger):
            recover_ledger(store, lambda: 1, CLOCK_ID)

    def test_missing_duplicate_unexpected_and_hash_forged_records_fail(self):
        baseline, _, _, _ = setup_ledger()
        mutations = (
            lambda store: store.files.pop("00000000000000000000.json"),
            lambda store: store.files.update({"00000000000000000002.json": copy.deepcopy(
                store.files["00000000000000000001.json"])}),
            lambda store: store.files.update({"not-evidence.txt": File(b"x")}),
            lambda store: store.extra_names.append("00000000000000000000.json"),
            lambda store: setattr(store.files["00000000000000000001.json"], "data",
                                  store.files["00000000000000000001.json"].data.replace(b"coordinator", b"substitute")),
        )
        for mutation in mutations:
            store = baseline.clone()
            mutation(store)
            with self.subTest(mutation=mutation), self.assertRaises(CorruptLedger):
                recover_ledger(store, lambda: 1, CLOCK_ID)

    def test_remaining_obligations_are_recomputed_not_trusted(self):
        store, _, _, _ = setup_ledger()
        record = store.records()[1]
        record["remaining"] = []
        store.files["00000000000000000001.json"].data = rehash(record)
        with self.assertRaises(CorruptLedger):
            recover_ledger(store, lambda: 1, CLOCK_ID)

    def test_changed_clock_domain_never_grants_cleanup_authority(self):
        store, _, _, _ = setup_ledger()
        with self.assertRaises(AuthorityError):
            recover_ledger(store, lambda: 1, "another-boot")

    def test_torn_unpublished_temporary_record_is_not_authority(self):
        store, _, ledger, _ = setup_ledger()
        store.files[".pending-" + "f" * 32] = File(b'{"partial":')
        recovered = recover_ledger(store, lambda: 1, CLOCK_ID)
        self.assertEqual(recovered.remaining, ledger.remaining)
        self.assertIn(".pending-" + "f" * 32, store.files)
        self.assertFalse(recovered.successful)

    def test_live_operations_recheck_earlier_records_not_only_tail(self):
        store, _, ledger, resource = setup_ledger()
        store.files["00000000000000000000.json"].data = b"torn header"
        world = World(store)
        with self.assertRaises(CorruptLedger):
            ledger.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                   observe=world.observe, mutate=world.remove)
        self.assertEqual(world.calls, 0)

    def test_stale_instances_and_competing_lease_cannot_mutate(self):
        store, _, ledger, resource = setup_ledger()
        other = recover_ledger(store, lambda: 1, CLOCK_ID)
        ledger.primary_failure("unrelated primary operation failed")
        world = World(store)
        with self.assertRaises(AuthorityError):
            other.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                  observe=world.observe, mutate=world.remove)
        with store.exclusive(), self.assertRaises(AuthorityError):
            ledger.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                   observe=world.observe, mutate=world.remove)
        self.assertEqual(world.calls, 0)


class CleanupProtocolTests(unittest.TestCase):
    def test_exact_observation_after_durable_intent_is_the_only_success(self):
        store, _, ledger, resource = setup_ledger()
        world = World(store)
        self.assertTrue(ledger.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                              observe=world.observe, mutate=world.remove))
        self.assertEqual(world.calls, 1)
        self.assertFalse(ledger.successful)
        self.assertEqual(ledger.remaining, ())
        self.assertTrue(ledger.finalize())
        recovered = recover_ledger(store, lambda: 1, CLOCK_ID)
        self.assertTrue(recovered.finalized and recovered.successful)
        with self.assertRaises(AuthorityError):
            ledger.primary_failure("cannot append after finalization")

    def test_successful_command_return_without_postcondition_is_failure(self):
        store, _, ledger, resource = setup_ledger()
        world = World(store)
        self.assertFalse(ledger.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                               observe=world.observe, mutate=lambda _: True))
        self.assertEqual(ledger.remaining, (resource,))
        self.assertEqual(ledger.errors["cleanup"][-1]["stage"], "postcondition")
        with self.assertRaises(AuthorityError):
            ledger.finalize()

    def test_exact_already_absent_resource_requires_no_mutation(self):
        store, _, ledger, resource = setup_ledger()
        world = World(store)
        world.present = False
        self.assertTrue(ledger.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                              observe=world.observe, mutate=world.remove))
        self.assertEqual(world.calls, 0)
        self.assertNotIn("cleanup_intent", [record["event"] for record in store.records()])
        self.assertTrue(ledger.finalize())

    def test_duplicate_slot_ownership_is_rejected_even_after_cleanup(self):
        store, _, ledger, resource = setup_ledger()
        reused = ResourceIdentity("process", IDENTITY.namespace, IDENTITY.key,
                                  "11111111-1111-1111-1111-111111111111:999")
        for identity, owner in ((IDENTITY, OWNER), (IDENTITY, "other-owner"), (reused, OWNER)):
            with self.subTest(identity=identity, owner=owner), self.assertRaises(AuthorityError):
                ledger.register(identity, owner)
        world = World(store)
        ledger.attempt_cleanup(resource, OWNER, deadline_ns=100, observe=world.observe, mutate=world.remove)
        with self.assertRaises(AuthorityError):
            ledger.register(reused, "other-owner")

    def test_wrong_owner_uncertain_identity_and_pid_reuse_never_mutate(self):
        reused = ResourceIdentity("process", IDENTITY.namespace, IDENTITY.key,
                                  "11111111-1111-1111-1111-111111111111:999")
        observations = (
            Observation(IDENTITY, IDENTITY, "present", False, EVIDENCE),
            Observation(IDENTITY, reused, "present", True, EVIDENCE),
            Observation(reused, reused, "present", True, EVIDENCE),
            Observation(IDENTITY, None, "unknown", False, EVIDENCE),
            True,
        )
        for value in observations:
            store, _, ledger, resource = setup_ledger()
            world = World(store)
            with self.subTest(value=value):
                self.assertFalse(ledger.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                                       observe=lambda _: value, mutate=world.remove))
                self.assertEqual(world.calls, 0)
                self.assertEqual(ledger.remaining, (resource,))
                self.assertNotIn("cleanup_intent", [record["event"] for record in store.records()])
        store, _, ledger, resource = setup_ledger()
        world = World(store)
        with self.assertRaises(AuthorityError):
            ledger.attempt_cleanup(resource, "wrong-owner", deadline_ns=100,
                                   observe=world.observe, mutate=world.remove)
        self.assertEqual(world.calls, 0)

    def test_authority_is_rechecked_after_intent_before_mutation(self):
        store, _, ledger, resource = setup_ledger()
        world = World(store)
        count = [0]
        def observe(target):
            count[0] += 1
            return world.observe(target) if count[0] == 1 else Observation(
                target, None, "unknown", False, EVIDENCE)
        self.assertFalse(ledger.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                               observe=observe, mutate=world.remove))
        self.assertEqual(world.calls, 0)
        self.assertIn("cleanup_intent", [record["event"] for record in store.records()])

    def test_deadline_exhaustion_before_and_during_intent_blocks_mutation(self):
        for during_intent in (False, True):
            store, clock, ledger, resource = setup_ledger()
            world = World(store)
            if during_intent:
                original_sync = store.fsync_directory
                def late_sync():
                    original_sync()
                    clock[0] = 100
                store.fsync_directory = late_sync
            else:
                clock[0] = 100
            with self.subTest(during_intent=during_intent):
                self.assertFalse(ledger.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                                       observe=world.observe, mutate=world.remove))
                self.assertEqual(world.calls, 0)
                self.assertEqual(ledger.errors["cleanup"][-1]["stage"], "deadline")
                with self.assertRaises(AuthorityError):
                    ledger.finalize()

    def test_primary_and_cleanup_errors_survive_successful_cleanup(self):
        store, _, ledger, resource = setup_ledger()
        world = World(store)
        ledger.primary_failure("primary launch failed")
        def mutation(authorization):
            world.remove(authorization)
            raise OSError("cleanup command reported failure")
        self.assertTrue(ledger.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                              observe=world.observe, mutate=mutation))
        self.assertFalse(ledger.finalize())
        recovered = recover_ledger(store, lambda: 1, CLOCK_ID)
        self.assertTrue(recovered.finalized)
        self.assertFalse(recovered.successful)
        self.assertEqual(recovered.errors["primary"], ["primary launch failed"])
        self.assertEqual(recovered.errors["cleanup"][0]["stage"], "mutation")

    def test_late_observation_keeps_exact_cleanup_truth_but_never_reports_success(self):
        for after_mutation in (False, True):
            store, clock, ledger, resource = setup_ledger()
            world = World(store)
            if not after_mutation:
                world.present = False
            def observe(target):
                if not world.present:
                    clock[0] = 100
                return world.observe(target)
            with self.subTest(after_mutation=after_mutation):
                self.assertFalse(ledger.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                                       observe=observe, mutate=world.remove))
                self.assertEqual(ledger.remaining, (resource,))
                self.assertEqual(world.calls, int(after_mutation))
                self.assertTrue(any(error["stage"] == "deadline" for error in ledger.errors["cleanup"]))
                with self.assertRaises(AuthorityError):
                    ledger.finalize()
                self.assertTrue(ledger.attempt_cleanup(resource, OWNER, deadline_ns=200,
                                                      observe=world.observe, mutate=world.remove))
                self.assertFalse(ledger.finalize())

    def test_clock_and_deadline_require_exact_integers(self):
        for invalid in (True, 1.0, -1, 2**63):
            store, clock, ledger, resource = setup_ledger()
            world = World(store)
            clock[0] = invalid
            with self.subTest(clock=invalid), self.assertRaises(AuthorityError):
                ledger.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                       observe=world.observe, mutate=world.remove)
            self.assertEqual(world.calls, 0)

    def test_observer_failure_after_mutation_leaves_recoverable_obligation(self):
        store, _, ledger, resource = setup_ledger()
        world = World(store)
        def observe(target):
            if not world.present:
                raise OSError("postcondition evidence unavailable")
            return world.observe(target)
        self.assertFalse(ledger.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                               observe=observe, mutate=world.remove))
        self.assertEqual(ledger.remaining, (resource,))
        recovered = recover_ledger(store, lambda: 1, CLOCK_ID)
        self.assertTrue(recovered.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                                 observe=world.observe, mutate=world.remove))
        self.assertEqual(world.calls, 1)
        self.assertFalse(recovered.finalize())

    def test_rollback_requires_exact_target_and_original_state_hash(self):
        store = FakeStore()
        ledger = CleanupLedger.create(store, lambda: 1, CLOCK_ID)
        identity = ResourceIdentity("configuration", "test-device", "rotation", "session-1")
        resource = ledger.register(identity, OWNER, postcondition="restored", baseline_sha256=BASELINE)
        state = ["c" * 64]
        calls = []
        def observe(target):
            return Observation(target, target, "restored" if state[0] == BASELINE else "present",
                               True, EVIDENCE, state[0])
        def restore(authorization):
            calls.append(authorization)
            state[0] = BASELINE
        self.assertTrue(ledger.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                              observe=observe, mutate=restore))
        self.assertEqual(len(calls), 1)
        self.assertTrue(ledger.finalize())

    def test_finalization_waits_for_every_resource(self):
        store, _, ledger, resource = setup_ledger()
        second = ResourceIdentity("display", "session-1", "20", "generation-1")
        other = ledger.register(second, OWNER)
        world = World(store)
        ledger.attempt_cleanup(resource, OWNER, deadline_ns=100, observe=world.observe, mutate=world.remove)
        with self.assertRaises(AuthorityError):
            ledger.finalize()
        self.assertEqual(ledger.remaining, (other,))
        ledger.attempt_cleanup(other, OWNER, deadline_ns=100,
                               observe=lambda target: Observation(target, None, "absent", True, EVIDENCE),
                               mutate=lambda _: self.fail("already absent must not mutate"))
        self.assertTrue(ledger.finalize())


class CrashBoundaryTests(unittest.TestCase):
    def test_crash_after_durable_registration_before_checkpoint_delivery_retains_suffix(self):
        store = FakeStore(chunk_size=100000)
        ledger = CleanupLedger.create(store, lambda: 1, CLOCK_ID, ledger_id="1" * 32)
        prior = ledger.checkpoint
        store.log = []
        store.fault = (6, "after")
        with self.assertRaises(PersistenceError):
            ledger.register(IDENTITY, OWNER)
        with self.assertRaises(AuthorityError):
            _ = ledger.checkpoint
        store.crash()
        recovered = recover_ledger(store, lambda: 1, CLOCK_ID, checkpoint=prior)
        self.assertEqual(recovered.remaining, (IDENTITY.resource_id,))
        with self.assertRaises(AuthorityError):
            recovered.finalize()

    def test_late_observation_fsync_crash_never_discharges_without_terminal_record(self):
        store, clock, ledger, resource = setup_ledger()
        checkpoint = ledger.checkpoint
        world = World(store)
        sync = store.fsync_directory
        def crash_after_late_observation():
            sync()
            if store.records()[-1]["event"] == "cleanup_observed":
                clock[0] = 100
                raise OSError("crash after late observation fsync before decision")
        store.fsync_directory = crash_after_late_observation
        with self.assertRaises(PersistenceError):
            ledger.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                   observe=world.observe, mutate=world.remove)
        store.fsync_directory = sync
        store.crash()
        oracle = independent_chain_oracle(store.durable)
        self.assertEqual(oracle["remaining"], [resource])
        recovered = recover_ledger(store, lambda: clock[0], CLOCK_ID, checkpoint=checkpoint)
        self.assertEqual(recovered.remaining, (resource,))
        with self.assertRaises(AuthorityError):
            recovered.finalize()
        self.assertTrue(recovered.attempt_cleanup(resource, OWNER, deadline_ns=200,
                                                 observe=world.observe, mutate=world.remove))
        self.assertEqual(world.calls, 1)
        self.assertTrue(recovered.finalize())

    def test_terminal_decision_has_one_pre_append_deadline_linearization(self):
        for crash in (False, True):
            store, clock, ledger, resource = setup_ledger()
            checkpoint = ledger.checkpoint
            world = World(store)
            sync = store.fsync_directory
            def late_terminal_sync():
                sync()
                if store.records()[-1]["event"] == "cleanup_decision":
                    clock[0] = 100
                    if crash:
                        raise OSError("crash after durable terminal decision")
            store.fsync_directory = late_terminal_sync
            with self.subTest(crash=crash):
                if crash:
                    with self.assertRaises(PersistenceError):
                        ledger.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                               observe=world.observe, mutate=world.remove)
                else:
                    self.assertTrue(ledger.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                                          observe=world.observe, mutate=world.remove))
                store.fsync_directory = sync
                store.crash()
                oracle = independent_chain_oracle(store.durable)
                self.assertEqual(oracle["remaining"], [])
                recovered = recover_ledger(store, lambda: clock[0], CLOCK_ID, checkpoint=checkpoint)
                self.assertEqual(recovered.remaining, ())
                self.assertTrue(recovered.finalize())

    def test_every_initialization_and_registration_publication_boundary(self):
        golden = FakeStore()
        ledger = CleanupLedger.create(golden, lambda: 1, CLOCK_ID, ledger_id="1" * 32)
        ledger.register(IDENTITY, OWNER)
        operations = list(golden.log)
        for index, operation in enumerate(operations, 1):
            for edge in ("before", "after"):
                with self.subTest(index=index, operation=operation, edge=edge):
                    store = FakeStore()
                    store.fault = (index, edge)
                    with self.assertRaises(PersistenceError):
                        ledger = CleanupLedger.create(store, lambda: 1, CLOCK_ID, ledger_id="1" * 32)
                        ledger.register(IDENTITY, OWNER)
                    store.crash()
                    try:
                        recovered = recover_ledger(store, lambda: 1, CLOCK_ID)
                    except CorruptLedger:
                        self.assertFalse(any(name.endswith(".json") for name in store.names()))
                    else:
                        self.assertFalse(recovered.successful or recovered.finalized)
                        self.assertIn(len(recovered.remaining), (0, 1))

    def test_every_create_write_fsync_close_rename_boundary_fails_closed_and_recovers(self):
        baseline, _, _, resource = setup_ledger()
        golden = baseline.clone()
        ledger = recover_ledger(golden, lambda: 1, CLOCK_ID)
        golden.log = []
        world = World(golden)
        ledger.attempt_cleanup(resource, OWNER, deadline_ns=100, observe=world.observe, mutate=world.remove)
        operations = list(golden.log)
        self.assertEqual(set(operations), {"create", "write", "fsync_file", "close", "rename", "fsync_directory"})
        self.assertGreater(operations.count("write"), 20)
        tested = 0
        for index, operation in enumerate(operations, 1):
            for edge in ("before", "after"):
                with self.subTest(index=index, operation=operation, edge=edge):
                    store = baseline.clone()
                    ledger = recover_ledger(store, lambda: 1, CLOCK_ID)
                    store.log = []
                    store.fault = (index, edge)
                    world = World(store)
                    with self.assertRaises(PersistenceError):
                        ledger.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                               observe=world.observe, mutate=world.remove)
                    calls = world.calls
                    with self.assertRaises(AuthorityError):
                        ledger.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                               observe=world.observe, mutate=world.remove)
                    self.assertEqual(world.calls, calls)
                    self.assertFalse(ledger.successful)
                    store.crash()
                    recovered = recover_ledger(store, lambda: 1, CLOCK_ID)
                    if recovered.remaining:
                        self.assertTrue(recovered.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                                                 observe=world.observe, mutate=world.remove))
                    self.assertEqual(world.calls, 1)
                    self.assertFalse(world.present)
                    self.assertTrue(recovered.finalize())
                    tested += 1
        print(f"cleanup publication fault edges verified: {tested}")

    def test_every_finalization_boundary_needs_durable_recovery_not_return_code(self):
        store, _, ledger, resource = setup_ledger()
        world = World(store)
        ledger.attempt_cleanup(resource, OWNER, deadline_ns=100, observe=world.observe, mutate=world.remove)
        baseline = store.clone()
        store.log = []
        ledger.finalize()
        operations = list(store.log)
        for index, operation in enumerate(operations, 1):
            for edge in ("before", "after"):
                with self.subTest(index=index, operation=operation, edge=edge):
                    candidate = baseline.clone()
                    recovered = recover_ledger(candidate, lambda: 1, CLOCK_ID)
                    candidate.log = []
                    candidate.fault = (index, edge)
                    with self.assertRaises(PersistenceError):
                        recovered.finalize()
                    self.assertFalse(recovered.finalized or recovered.successful)
                    candidate.crash()
                    final = recover_ledger(candidate, lambda: 1, CLOCK_ID)
                    if not final.finalized:
                        self.assertTrue(final.finalize())
                    self.assertTrue(final.successful)

    def test_visible_but_unsynced_intent_requires_recovery_sync_and_fresh_observation(self):
        store, _, ledger, resource = setup_ledger()
        store.chunk_size = 100000
        store.fault = (6, "before")  # create/write/fsync/close/rename/directory fsync
        world = World(store)
        with self.assertRaises(PersistenceError):
            ledger.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                   observe=world.observe, mutate=world.remove)
        self.assertEqual(world.calls, 0)
        self.assertEqual(store.records()[-1]["event"], "cleanup_intent")
        store.fault = None
        store.log = []
        store.fault = (1, "before")
        with self.assertRaises(OSError):
            recover_ledger(store, lambda: 1, CLOCK_ID)
        store.fault = None
        recovered = recover_ledger(store, lambda: 1, CLOCK_ID)
        self.assertFalse(recovered.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                                  observe=lambda target: Observation(target, None, "unknown", False, EVIDENCE),
                                                  mutate=world.remove))
        self.assertEqual(world.calls, 0)

    def test_process_crash_after_mutation_does_not_repeat_already_satisfied_cleanup(self):
        store, _, ledger, resource = setup_ledger()
        world = World(store)
        class Crash(BaseException):
            pass
        def mutation(authorization):
            world.remove(authorization)
            raise Crash()
        with self.assertRaises(Crash):
            ledger.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                   observe=world.observe, mutate=mutation)
        store.crash()
        recovered = recover_ledger(store, lambda: 1, CLOCK_ID)
        self.assertEqual(recovered.remaining, (resource,))
        self.assertTrue(recovered.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                                 observe=world.observe, mutate=world.remove))
        self.assertEqual(world.calls, 1)
        self.assertTrue(recovered.finalize())

    def test_zero_progress_write_and_rename_collision_never_mutate(self):
        for fault in ("zero-write", "rename-collision"):
            store, _, ledger, resource = setup_ledger()
            world = World(store)
            if fault == "zero-write":
                store.write = lambda handle, payload: 0
            else:
                def collision(source, destination):
                    raise FileExistsError(destination)
                store.rename_no_replace = collision
            with self.subTest(fault=fault), self.assertRaises(PersistenceError):
                ledger.attempt_cleanup(resource, OWNER, deadline_ns=100,
                                       observe=world.observe, mutate=world.remove)
            self.assertEqual(world.calls, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
