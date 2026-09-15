"""Deterministic fake-only host authority; no ADB/device/process/network work."""
from dataclasses import replace
import json
import socket
import subprocess
import unittest
from unittest.mock import patch

import native_page_host_authority as host

SESSION = "12345678-1234-4234-8234-123456789abc"
HOST = host.ProcessIdentity(900, 12345, 10123, host.HOST_PACKAGE)
STOCK = host.ProcessIdentity(700, 54321, 1000, host.FOREIGN_PACKAGE)
FOREIGN = host.ForeignIdentity(STOCK, 77, "foreign-token", "a" * 64)
HOST_ACTIVITY = host.ActivityRecord(HOST, 90, host.HOST_COMPONENT, "host-token", 0, True, True)
HOST_WINDOW = host.WindowRecord(HOST, 90, "host-token", 0, host.Rect(0, 0, 1404, 1872), True, True,
                                host.Rect(0, 0, 1404, 1872), (1404, 1872))
PHYSICAL = host.DisplayRecord(0, None, "physical", 1404, 1872, 300, frozenset())


class Retained:
    def __init__(self):
        self.process, self.bad = HOST, False
        self.on_verify = None
    def identity(self): return self.process
    def verify(self):
        if self.on_verify: self.on_verify()
        if self.bad: raise host.HostAuthorityError("retained APK/process image drift")


class PackageAuthorityTests(unittest.TestCase):
    def test_package_authority_is_the_reviewed_terminal_release_build(self):
        self.assertEqual(
            host.PINNED_PACKAGE,
            host.PackageRecord(
                "com.techrebbe.supernote.nativepagehost",
                "39abffb0c55ff0cacd5ab7b9917a529d2744684b43a96ade63c1f3374121617e",
                "670c755fabb00df87c6b6714c3dc8b878aa22e3190d95585b24adce295756178",
                "15d24cef8f4c70cf167ab6e93ac817fc2e85af4bfca6bb392e2535dc04863ab6",
                "a5a8551131de84d41660a3cf22d224f320f7a2f05a380282f76f6fe731807c67",
                2,
                "0.0.2-native-page-visual-only",
            ),
        )


class FakeProviders:
    def __init__(self):
        self.clock = 10_000_000_000
        self.snapshot = host.Snapshot(self.clock, host.PINNED_PACKAGE, (HOST, STOCK), (HOST_ACTIVITY,), (HOST_WINDOW,),
                                      (PHYSICAL,), "a" * 64, "b" * 64, "c" * 64, "d" * 64)
        self.events = []
        self.cursor, self.generation = 0, 0
        self.commands = []
        self.auth_bad = False
        self.on_send = self.on_capture = self.on_event = None
        self.release_failure = False
        self.released_once = False
        self.owner = None
        self.substitute_after_next_now = None

    def now_ns(self):
        value = self.clock
        if self.substitute_after_next_now is not None:
            replacement = self.substitute_after_next_now
            self.substitute_after_next_now = None
            assert self.owner is not None
            self.owner.providers = replacement
        return value
    def sleep_ns(self, duration_ns):
        if duration_ns <= 0: raise host.HostAuthorityError("host absolute deadline expired in fake wait")
        self.clock += duration_ns

    def capture(self, deadline_ns):
        if self.on_capture: self.on_capture(self)
        return replace(self.snapshot, captured_ns=self.clock)

    def emit(self, kind, body=None, *, advance=0, mutate=None, **changes):
        self.cursor += 1
        event = host.HostEvent(self.cursor, self.clock + sum(item[1] for item in self.events) + advance,
                               HOST, SESSION, self.generation, kind, body or {})
        self.events.append((replace(event, **changes), advance, mutate))

    def next_event(self, limit, deadline_ns):
        if self.on_event: self.on_event(self)
        if not self.events: return None
        event, advance, mutate = self.events.pop(0)
        self.clock += advance
        if mutate: mutate(self)
        return event

    def attest_event(self, event):
        if self.auth_bad: raise host.HostAuthorityError("unauthenticated log text is not a producer channel")

    def allocate(self, metrics=True):
        self.generation = 1
        virtual = host.DisplayRecord(5, HOST, f"NativePageVisualOnly-{SESSION}-1", 1404 if metrics else None,
                                     1872 if metrics else None, 300 if metrics else None, host.FLAGS)
        self.snapshot = replace(self.snapshot, displays=(self.snapshot.displays[0], virtual))

    def make_ready(self):
        self.generation = 1
        self.emit("DISPLAY_ALLOCATED", {"display": 5}, mutate=lambda runtime: runtime.allocate(False))
        self.emit("DISPLAY_READY", {"display": 5, "density": 300, "width": 1404, "height": 1872},
                  mutate=lambda runtime: runtime.allocate(True))

    def add_foreign(self, identity=FOREIGN):
        activity = host.ActivityRecord(identity.process, identity.task_id, identity.component, identity.activity_token, 5, True, True)
        window = host.WindowRecord(identity.process, identity.task_id, identity.activity_token, 5, host.Rect(0, 0, 1404, 1872), True, True)
        self.snapshot = replace(self.snapshot, activities=(HOST_ACTIVITY, activity), windows=(self.snapshot.windows[0], window))

    def remove_foreign(self):
        self.snapshot = replace(self.snapshot, activities=tuple(a for a in self.snapshot.activities if a.task_id != FOREIGN.task_id),
                                windows=tuple(w for w in self.snapshot.windows if w.task_id != FOREIGN.task_id))

    def landscape(self, placement=host.Placement.FULL):
        physical = replace(self.snapshot.displays[0], width=1872, height=1404)
        _, rect = host.placement_frame(placement, 1872, 1404)
        window = replace(self.snapshot.windows[0], frame=host.Rect(0, 0, 1872, 1404), surface_frame=rect)
        self.snapshot = replace(self.snapshot, displays=(physical,) + self.snapshot.displays[1:], windows=(window,) + self.snapshot.windows[1:])

    def release(self):
        self.snapshot = replace(self.snapshot, displays=(self.snapshot.displays[0],),
                                activities=tuple(a for a in self.snapshot.activities if a.task_id != 90),
                                windows=tuple(w for w in self.snapshot.windows if w.task_id != 90))

    def send(self, command, deadline_ns):
        if command.session != SESSION or command.display_id != 5 or command.generation != 1:
            raise host.HostAuthorityError("fake typed send identity mismatch")
        self.commands.append((command, deadline_ns))
        if self.on_send:
            self.on_send(self, command)
            return
        self.standard_reply(command)

    def standard_reply(self, command):
        body = json.loads(command.body_json)
        if command.action == "ACK_FOREIGN_ATTACHED": self.emit("READY", body)
        elif command.action.startswith("PLACE_"):
            placement = host.Placement(command.action[6:])
            physical = self.snapshot.displays[0]
            effective, rect = host.placement_frame(placement, physical.width, physical.height)
            self.emit("PLACEMENT_REQUESTED", {"sequence": command.sequence, "requested": placement.value})
            def apply(runtime):
                runtime.snapshot = replace(runtime.snapshot, windows=(replace(runtime.snapshot.windows[0], surface_frame=rect),) + runtime.snapshot.windows[1:])
            self.emit("PLACEMENT_READY", {"sequence": command.sequence, "requested": placement.value,
                                          "effective": effective.value, "rect": rect.wire()}, mutate=apply)
        elif command.action == "BEGIN_CLOSE": self.emit("WAIT_FOREIGN_DESTROY", {"foreign": FOREIGN.wire()})
        elif command.action in {"ACK_FOREIGN_DESTROYED", "ACK_NO_FOREIGN_AFTER_FAILURE", "ACK_NO_FOREIGN_PRE_ATTACH_ABORT"}:
            kinds = {"ACK_FOREIGN_DESTROYED": ("FOREIGN_DESTROYED", "DESTROY_REPLAY"),
                     "ACK_NO_FOREIGN_AFTER_FAILURE": ("EMPTY_ATTACH_ABORT", "EMPTY_ABORT_REPLAY"),
                     "ACK_NO_FOREIGN_PRE_ATTACH_ABORT": ("EMPTY_PRE_ATTACH_ABORT", "EMPTY_PRE_ATTACH_ABORT_REPLAY")}
            if self.released_once:
                self.emit(kinds[command.action][1], {"release_retry": True})
            else:
                self.emit(kinds[command.action][0], body)
                self.released_once = True
            if self.release_failure:
                self.emit("RELEASE_FAILED", {"display": 5, "retained": True, "retry_addressable": True})
            else: self.emit("DISPLAY_RELEASED", {"display": 5, "mode": "acknowledged_cleanup"}, mutate=lambda runtime: runtime.release())


class HostTests(unittest.TestCase):
    def setUp(self):
        for guard in (patch.object(socket, "socket", side_effect=AssertionError("no network")),
                      patch.object(subprocess, "Popen", side_effect=AssertionError("no process launch"))):
            guard.start()
            self.addCleanup(guard.stop)
        self.fresh()

    def fresh(self):
        self.retained, self.provider = Retained(), FakeProviders()
        self.authority = host.HostAuthority(self.retained, self.provider, SESSION, 90, "host-token")
        self.provider.owner = self.authority

    def deadline(self, span=5_000_000_000): return self.provider.clock + span
    def startable(self):
        self.provider.emit("SESSION")
        self.authority.admit_startable(self.deadline())

    def ready(self):
        self.startable()
        self.provider.make_ready()
        self.assertEqual(self.authority.await_display_ready(self.deadline()), 5)

    def active(self):
        self.ready()
        self.provider.add_foreign()
        self.authority.attach_ack(FOREIGN, self.deadline())

    def close_proof(self):
        self.authority.begin_close(self.deadline())
        self.provider.remove_foreign()
        return self.authority.prove_task_absent(self.deadline())

    def test_startable_admits_physical_frame_without_fictional_display_identity(self):
        self.startable()
        self.assertEqual(self.authority.state, "STARTABLE")
        self.assertIsNone(self.authority.display_id)
        self.assertEqual(self.authority.generation, 0)
        self.assertEqual(self.provider.commands, [])

    def test_preallocation_refuses_existing_owned_display_and_postallocation_requires_it(self):
        self.provider.allocate()
        with self.assertRaises(host.HostAuthorityError): self.startable()
        self.fresh()
        self.startable()
        self.provider.generation = 1
        self.provider.emit("DISPLAY_ALLOCATED", {"display": 5})
        with self.assertRaisesRegex(host.HostAuthorityError, "absent"): self.authority.await_display_ready(self.deadline())
        self.assertEqual((self.authority.display_id, self.authority.generation), (5, 1))
        self.assertTrue(self.authority.cleanup_obligations)

    def test_metrics_pending_retains_identity_but_does_not_publish_ready(self):
        self.startable()
        self.provider.generation = 1
        self.provider.emit("DISPLAY_ALLOCATED", {"display": 5}, mutate=lambda runtime: runtime.allocate(False))
        with self.assertRaisesRegex(host.HostAuthorityError, "deadline"): self.authority.await_display_ready(self.deadline(10_000_000))
        self.assertEqual(self.authority.state, "FAILED")
        self.assertEqual(self.authority.display_id, 5)

    def test_full_left_right_are_exact_measured_applied_placements(self):
        self.active()
        result = self.authority.place(host.Placement.LEFT, self.deadline())
        self.assertEqual(result.effective, host.Placement.FULL)
        self.provider.landscape(host.Placement.LEFT)
        for requested, rect in ((host.Placement.LEFT, host.Rect(0, 78, 936, 1248)),
                                (host.Placement.RIGHT, host.Rect(936, 78, 936, 1248)),
                                (host.Placement.FULL, host.Rect(409, 0, 1053, 1404))):
            result = self.authority.place(requested, self.deadline())
            self.assertEqual(result.rect, rect)
            self.assertEqual(result.requested, requested)

    def test_exact_destroyed_ack_releases_task_while_stock_process_stays_live(self):
        self.active()
        proof = self.close_proof()
        self.assertIn(STOCK, self.provider.snapshot.processes)
        self.authority.ack_destroyed(proof, self.deadline())
        self.authority.assert_quiescent(self.deadline())
        self.assertEqual(self.authority.state, "QUIESCENT")
        self.assertFalse(self.authority.cleanup_obligations)
        self.assertIn(STOCK, self.provider.snapshot.processes)

    def test_wrong_pinned_apk_dex_version_package_fail_before_command(self):
        for changes in ({"apk_sha256": "0" * 64},
                        {"reviewed_unsigned_apk_sha256": "0" * 64},
                        {"dex_sha256": "0" * 64},
                        {"signer_cert_sha256": "0" * 64},
                        {"version_code": 3},
                        {"version_name": "substitute"},
                        {"package": "substitute"}):
            self.fresh()
            self.provider.snapshot = replace(self.provider.snapshot, package=replace(host.PINNED_PACKAGE, **changes))
            with self.assertRaises(host.HostAuthorityError): self.startable()
            self.assertFalse(self.provider.commands)

    def test_retained_producer_pid_start_uid_image_drift_fail_before_send(self):
        for changes in ({"pid": 901}, {"start_ticks": 1}, {"uid": 0}, None):
            self.fresh()
            self.ready()
            self.provider.add_foreign()
            if changes: self.retained.process = replace(HOST, **changes)
            else: self.retained.bad = True
            with self.assertRaises(host.HostAuthorityError): self.authority.attach_ack(FOREIGN, self.deadline())
            self.assertFalse(self.provider.commands)

    def test_exact_dependency_substitution_before_or_during_callback_sends_nothing(self):
        for case in ("provider_before", "retained_before", "during_now",
                     "during_retained_verify_provider",
                     "during_retained_verify_retained"):
            self.fresh()
            self.active()
            self.provider.commands.clear()
            replacement_provider = FakeProviders()
            replacement_provider.clock = self.provider.clock
            replacement_provider.owner = self.authority
            replacement_retained = Retained()
            if case == "provider_before":
                self.authority.providers = replacement_provider
                expected = "provider object was substituted"
            elif case == "retained_before":
                self.authority.retained = replacement_retained
                expected = "process authority object was substituted"
            elif case == "during_now":
                self.provider.substitute_after_next_now = replacement_provider
                expected = "provider object was substituted"
            elif case == "during_retained_verify_provider":
                self.retained.on_verify = lambda: setattr(
                    self.authority, "providers", replacement_provider)
                expected = "provider object was substituted"
            else:
                self.retained.on_verify = lambda: setattr(
                    self.authority, "retained", replacement_retained)
                expected = "process authority object was substituted"
            with self.subTest(case=case):
                with self.assertRaisesRegex(host.HostAuthorityError, expected):
                    self.authority.place(host.Placement.LEFT,
                                         self.deadline())
                self.assertEqual(self.provider.commands, [])
                self.assertEqual(replacement_provider.commands, [])

    def test_uuid_log_text_is_not_producer_authentication(self):
        self.provider.auth_bad = True
        with self.assertRaises(host.HostAuthorityError): self.startable()

    def test_stale_duplicate_out_of_order_generation_session_and_producer_events_fail(self):
        mutations = ({"cursor": 0}, {"cursor": 2}, {"generation": 1}, {"session": "22345678-1234-4234-8234-123456789abc"},
                     {"producer": replace(HOST, start_ticks=2)}, {"body": {"flood": "x" * 5000}})
        for mutation in mutations:
            self.fresh()
            self.provider.emit("SESSION", **mutation)
            with self.assertRaises(host.HostAuthorityError): self.authority.admit_startable(self.deadline())
        self.fresh()
        self.startable()
        self.provider.emit("SESSION")
        with self.assertRaises(host.HostAuthorityError): self.authority.await_display_ready(self.deadline())

    def test_duplicate_or_out_of_order_ack_never_credits_next_operation(self):
        self.active()
        self.provider.emit("READY", {"foreign": FOREIGN.wire()})
        with self.assertRaises(host.HostAuthorityError): self.authority.place(host.Placement.FULL, self.deadline())
        self.assertEqual(self.authority.state, "FAILED")

    def test_foreign_pid_uid_token_task_display_and_frame_drift_are_independently_rejected(self):
        for mode in ("pid", "uid", "token", "task", "display0", "frame", "process_dead"):
            self.fresh()
            self.ready()
            self.provider.add_foreign()
            activity, window = self.provider.snapshot.activities[1], self.provider.snapshot.windows[1]
            if mode == "pid": activity = replace(activity, process=replace(STOCK, pid=701))
            elif mode == "uid": activity = replace(activity, process=replace(STOCK, uid=0))
            elif mode == "token": activity = replace(activity, token="other")
            elif mode == "task": activity = replace(activity, task_id=78)
            elif mode == "display0": activity, window = replace(activity, display_id=0), replace(window, display_id=0)
            elif mode == "frame": window = replace(window, frame=host.Rect(0, 0, 100, 100))
            else: self.provider.snapshot = replace(self.provider.snapshot, processes=(HOST,))
            self.provider.snapshot = replace(self.provider.snapshot, activities=(HOST_ACTIVITY, activity), windows=(HOST_WINDOW, window))
            with self.assertRaises(host.HostAuthorityError): self.authority.attach_ack(FOREIGN, self.deadline())
            self.assertFalse(self.provider.commands)

    def test_display_owner_name_flags_density_geometry_drift_rejects_readiness(self):
        for changes in ({"owner": replace(HOST, start_ticks=2)}, {"name": "different-session"}, {"flags": frozenset()},
                        {"density": 301}, {"width": 100}, {"display_id": 0}):
            self.fresh()
            self.startable()
            self.provider.make_ready()
            event, advance, _ = self.provider.events[-1]
            def mutate(runtime):
                runtime.allocate(True)
                runtime.snapshot = replace(runtime.snapshot, displays=(PHYSICAL, replace(runtime.snapshot.displays[1], **changes)))
            self.provider.events[-1] = event, advance, mutate
            with self.assertRaises(host.HostAuthorityError): self.authority.await_display_ready(self.deadline())
            self.assertEqual(self.authority.display_id, 5)

    def test_frame_mismatch_after_applied_ack_is_sticky_not_an_applied_placement(self):
        self.active()
        def wrong_frame(runtime, command):
            runtime.standard_reply(command)
            event, advance, _ = runtime.events[-1]
            runtime.events[-1] = event, advance, lambda r: setattr(r, "snapshot", replace(r.snapshot, windows=(replace(r.snapshot.windows[0], surface_frame=host.Rect(1, 0, 1404, 1872)),) + r.snapshot.windows[1:]))
        self.provider.on_send = wrong_frame
        with self.assertRaises(host.HostAuthorityError): self.authority.place(host.Placement.FULL, self.deadline())
        self.assertEqual(self.authority.state, "FAILED")

    def test_paused_command_requires_ready_and_keeps_original_absolute_deadline(self):
        self.active()
        def pause(runtime, command):
            runtime.emit("HOST_AUTHORITY_SUSPENDED", {"remaining_ms": 1500})
            runtime.emit("COMMAND_DEFERRED", {"sequence": command.sequence, "action": command.action})
            runtime.emit("HOST_AUTHORITY_REACQUIRED", advance=500_000_000)
            runtime.emit("HOST_AUTHORITY_READY")
            runtime.standard_reply(command)
        self.provider.on_send = pause
        self.authority.place(host.Placement.FULL, self.deadline())
        command, bound = self.provider.commands[-1]
        self.assertEqual(bound, command.issued_ns + host.COMMAND_NS)
        self.assertEqual(self.authority.state, "ACTIVE")

    def test_repeated_pause_and_reacquisition_do_not_extend_original_command_deadline(self):
        self.active()
        def churn(runtime, command):
            runtime.emit("HOST_AUTHORITY_SUSPENDED", {"remaining_ms": 1500})
            runtime.emit("HOST_AUTHORITY_READY", advance=1_000_000_000)
            runtime.emit("HOST_AUTHORITY_SUSPENDED", {"remaining_ms": 1500}, advance=600_000_000)
            runtime.standard_reply(command)
        self.provider.on_send = churn
        with self.assertRaisesRegex(host.HostAuthorityError, "deadline"): self.authority.place(host.Placement.FULL, self.deadline())
        self.assertEqual(self.authority.state, "FAILED")

    def test_clean_host_deferred_ack_precedes_final_frame_ready_without_early_publication(self):
        for final_ready in (True, False):
            self.fresh()
            self.active()
            def deferred(runtime, command):
                runtime.emit("HOST_AUTHORITY_SUSPENDED", {"remaining_ms": 1500})
                runtime.emit("COMMAND_DEFERRED", {"sequence": command.sequence, "action": command.action})
                runtime.emit("HOST_AUTHORITY_REACQUIRED", advance=500_000_000)
                runtime.emit("COMMAND_RESUMED", {"sequence": command.sequence, "action": command.action})
                runtime.standard_reply(command)
                if final_ready: runtime.emit("HOST_AUTHORITY_READY", advance=100_000_000)
            self.provider.on_send = deferred
            if final_ready:
                self.authority.place(host.Placement.FULL, self.deadline())
                self.assertEqual(self.provider.clock, 10_600_000_000)
            else:
                with self.assertRaisesRegex(host.HostAuthorityError, "deadline"):
                    self.authority.place(host.Placement.FULL, self.deadline())

    def test_clean_synchronous_layout_can_log_placement_ready_before_requested(self):
        self.active()
        def inverted(runtime, command):
            runtime.standard_reply(command)
            first, second = runtime.events[-2:]
            # Actual producer cursor still follows actual emitted order.
            runtime.events[-2:] = [(replace(second[0], cursor=first[0].cursor), second[1], second[2]),
                                   (replace(first[0], cursor=second[0].cursor), first[1], first[2])]
        self.provider.on_send = inverted
        self.authority.place(host.Placement.FULL, self.deadline())
        self.provider.on_send = None
        self.authority.begin_close(self.deadline())
        self.assertEqual(self.authority.phase, "WAIT_FOREIGN_DESTROY")

    def test_ack_while_paused_and_late_exact_ack_never_restore_ready(self):
        for mode in ("paused", "late"):
            self.fresh()
            self.ready()
            self.provider.add_foreign()
            def reply(runtime, command):
                if mode == "paused": runtime.emit("HOST_AUTHORITY_SUSPENDED", {"remaining_ms": 1500})
                runtime.emit("READY", {"foreign": FOREIGN.wire()}, advance=host.COMMAND_NS if mode == "late" else 0)
            self.provider.on_send = reply
            with self.assertRaises(host.HostAuthorityError): self.authority.attach_ack(FOREIGN, self.deadline())
            self.assertEqual(self.authority.state, "FAILED")
            self.assertTrue(any("foreign task 77" in value for value in self.authority.cleanup_obligations))

    def test_task_migration_to_display_zero_is_not_absence_even_if_old_display_empty(self):
        self.active()
        self.authority.begin_close(self.deadline())
        snap = self.provider.snapshot
        self.provider.snapshot = replace(snap, activities=(snap.activities[0], replace(snap.activities[1], display_id=0)),
                                         windows=(snap.windows[0], replace(snap.windows[1], display_id=0)))
        with self.assertRaisesRegex(host.HostAuthorityError, "migrated"): self.authority.prove_task_absent(self.deadline())
        self.assertEqual(len(self.provider.commands), 2)

    def test_late_exact_attach_ack_reconciles_cleanup_without_restoring_readiness(self):
        self.ready()
        self.provider.add_foreign()
        self.provider.on_send = lambda runtime, command: runtime.emit("READY", {"foreign": FOREIGN.wire()}, advance=host.COMMAND_NS)
        with self.assertRaises(host.HostAuthorityError): self.authority.attach_ack(FOREIGN, self.deadline())
        original = self.provider.commands[-1][0]
        self.authority.reconcile_late_ack(self.deadline())
        self.assertEqual(self.authority.state, "FAILED")
        self.assertEqual(len(self.provider.commands), 1)
        self.assertEqual(original.deadline_ns, original.issued_ns + host.COMMAND_NS)
        self.provider.on_send = None
        proof = self.close_proof()
        self.authority.ack_destroyed(proof, self.deadline())
        self.authority.assert_quiescent(self.deadline())
        self.assertFalse(self.authority.cleanup_obligations)

    def test_late_exact_destroy_ack_can_finish_cleanup_but_keeps_timeout_sticky(self):
        self.active()
        proof = self.close_proof()
        def late_destroy(runtime, command):
            runtime.emit("FOREIGN_DESTROYED", {"foreign": FOREIGN.wire()}, advance=host.COMMAND_NS)
            runtime.emit("DISPLAY_RELEASED", {"display": 5, "mode": "acknowledged_cleanup"}, mutate=lambda r: r.release())
        self.provider.on_send = late_destroy
        with self.assertRaises(host.HostAuthorityError): self.authority.ack_destroyed(proof, self.deadline())
        count = len(self.provider.commands)
        self.authority.reconcile_late_ack(self.deadline())
        self.authority.assert_quiescent(self.deadline())
        self.assertEqual(len(self.provider.commands), count)
        self.assertEqual(self.authority.state, "FAILED")

    def test_boolean_sequence_and_untyped_geometry_do_not_equal_integer_authority(self):
        self.active()
        def malformed(runtime, command):
            runtime.emit("PLACEMENT_READY", {"sequence": True, "requested": "FULL", "effective": "FULL", "rect": [0, 0, 1404, 1872]})
        self.provider.on_send = malformed
        with self.assertRaises(host.HostAuthorityError): self.authority.place(host.Placement.FULL, self.deadline())
        self.fresh()
        self.provider.snapshot = replace(self.provider.snapshot, windows=(replace(HOST_WINDOW, frame=host.Rect(False, 0, 1404, 1872)),))
        with self.assertRaises(host.HostAuthorityError): self.startable()

    def test_forged_stale_and_wrong_task_absence_proof_never_sends_ack(self):
        for mode in ("digest", "generation", "task", "stale"):
            self.fresh()
            self.active()
            proof = self.close_proof()
            if mode == "digest": proof = replace(proof, evidence_sha256="e" * 64)
            elif mode == "generation": proof = replace(proof, generation=2)
            elif mode == "task": proof = replace(proof, foreign=replace(FOREIGN, task_id=99))
            else: self.provider.clock += host.COMMAND_NS + 1
            before = len(self.provider.commands)
            with self.assertRaises(host.HostAuthorityError): self.authority.ack_destroyed(proof, self.deadline())
            self.assertEqual(len(self.provider.commands), before)

    def test_foreign_reappearing_after_absence_proof_blocks_destruction_ack(self):
        self.active()
        proof = self.close_proof()
        self.provider.add_foreign()
        with self.assertRaises(host.HostAuthorityError): self.authority.ack_destroyed(proof, self.deadline())
        self.assertEqual(len(self.provider.commands), 2)

    def test_destroyed_ack_is_ineligible_before_begin_close(self):
        self.active()
        self.provider.remove_foreign()
        proof = self.authority.prove_task_absent(self.deadline())
        with self.assertRaises(host.HostAuthorityError): self.authority.ack_destroyed(proof, self.deadline())
        self.assertEqual(len(self.provider.commands), 1)

    def test_release_exception_keeps_exact_object_route_and_retry_is_byte_identical(self):
        self.active()
        proof = self.close_proof()
        self.provider.release_failure = True
        with self.assertRaisesRegex(host.HostAuthorityError, "release exception"): self.authority.ack_destroyed(proof, self.deadline())
        original = self.provider.commands[-1][0]
        self.assertTrue(any("display 5" in value for value in self.authority.cleanup_obligations))
        with self.assertRaises(host.HostQuiescenceError): self.authority.assert_quiescent(self.deadline())
        self.provider.release_failure = False
        self.provider.clock += 2_000_000_000
        self.authority.retry_release(self.deadline())
        self.assertIs(self.provider.commands[-1][0], original)
        self.authority.assert_quiescent(self.deadline())
        self.assertEqual(self.authority.state, "FAILED")
        self.assertFalse(self.authority.cleanup_obligations)

    def test_empty_failure_ack_requires_no_foreign_and_releases(self):
        self.ready()
        self.provider.emit("TIMEOUT", {"phase": "foreign_attach"})
        self.authority.observe_failure(self.deadline())
        proof = self.authority.prove_empty(self.deadline())
        self.authority.ack_empty(proof, self.deadline())
        self.authority.assert_quiescent(self.deadline())
        self.assertFalse(self.authority.cleanup_obligations)
        self.assertEqual(self.authority.state, "FAILED")

    def test_healthy_pre_attach_abort_releases_allocated_and_waiting_displays(self):
        for phase in ("DISPLAY_ALLOCATED", "WAITING_FOR_FOREIGN_ACK"):
            with self.subTest(phase=phase):
                self.fresh()
                if phase == "WAITING_FOR_FOREIGN_ACK": self.ready()
                else:
                    self.startable()
                    self.provider.generation = 1
                    self.provider.emit("DISPLAY_ALLOCATED", {"display": 5},
                                       mutate=lambda runtime: runtime.allocate(False))
                    self.assertTrue(self.authority._progress(self.authority._event(self.deadline())))
                proof = self.authority.prove_pre_attach_empty(self.deadline())
                self.assertIsNone(proof.foreign)
                self.authority.abort_pre_attach_empty(proof, self.deadline())
                self.assertEqual(self.provider.commands[0][0].action, "ACK_NO_FOREIGN_PRE_ATTACH_ABORT")
                self.assertEqual(json.loads(self.provider.commands[0][0].body_json),
                                 {"absence_sha256": proof.evidence_sha256})
                self.authority.assert_quiescent(self.deadline())
                self.assertEqual(self.authority.state, "QUIESCENT")
                self.assertIsNone(self.authority.failure)
                self.assertIn(STOCK, self.provider.snapshot.processes)

    def test_healthy_pre_attach_abort_rejects_ineligible_phase_failure_foreign_and_pending(self):
        for mode in ("startable", "active", "failed", "foreign", "pending"):
            for operation in ("proof", "abort"):
                with self.subTest(mode=mode, operation=operation):
                    self.fresh()
                    self.ready()
                    proof = self.authority.prove_pre_attach_empty(self.deadline())
                    if mode == "startable": self.authority.phase = "STARTABLE"
                    elif mode == "active": self.authority.phase = "ACTIVE"
                    elif mode == "failed":
                        self.provider.emit("TIMEOUT", {"phase": "foreign_attach"})
                        self.authority.observe_failure(self.deadline())
                    elif mode == "foreign": self.authority._foreign = FOREIGN
                    else:
                        self.provider.on_send = lambda runtime, command: None
                        self.authority._command("ACK_FOREIGN_ATTACHED", {}, self.deadline())
                    before = len(self.provider.commands)
                    with self.assertRaisesRegex(host.HostAuthorityError, "healthy pre-attach abort"):
                        if operation == "proof": self.authority.prove_pre_attach_empty(self.deadline())
                        else: self.authority.abort_pre_attach_empty(proof, self.deadline())
                    self.assertEqual(len(self.provider.commands), before)

    def test_healthy_pre_attach_proofs_reject_unknown_content_and_display_identity_drift(self):
        for mode in ("activity", "window", "owner", "name", "flags", "display"):
            with self.subTest(mode=mode):
                self.fresh()
                self.ready()
                if mode in {"activity", "window"}:
                    self.provider.add_foreign()
                    if mode == "activity": self.provider.snapshot = replace(self.provider.snapshot, windows=(HOST_WINDOW,))
                    else: self.provider.snapshot = replace(self.provider.snapshot, activities=(HOST_ACTIVITY,))
                else:
                    changes = {"owner": {"owner": STOCK}, "name": {"name": "wrong"},
                               "flags": {"flags": frozenset()}, "display": {"display_id": 6}}[mode]
                    self.provider.snapshot = replace(self.provider.snapshot,
                        displays=(PHYSICAL, replace(self.provider.snapshot.displays[1], **changes)))
                with self.assertRaises(host.HostAuthorityError): self.authority.prove_pre_attach_empty(self.deadline())
                self.assertEqual(self.provider.commands, [])

    def test_healthy_pre_attach_abort_requires_fresh_bound_proof_and_independent_recapture(self):
        for mode in ("forged", "stale", "future", "session", "generation", "boolean_generation", "display", "foreign", "reappear", "owner", "slow_recapture"):
            with self.subTest(mode=mode):
                self.fresh()
                self.ready()
                proof = self.authority.prove_pre_attach_empty(self.deadline())
                if mode == "forged": proof = replace(proof, evidence_sha256="0" * 64)
                elif mode == "stale": self.provider.clock += host.COMMAND_NS + 1
                elif mode == "future": proof = replace(proof, captured_ns=self.provider.clock + 1)
                elif mode == "session": proof = replace(proof, session="87654321-1234-4234-8234-123456789abc")
                elif mode == "generation": proof = replace(proof, generation=2)
                elif mode == "boolean_generation": proof = replace(proof, generation=True)
                elif mode == "display": proof = replace(proof, display_id=6)
                elif mode == "foreign": proof = replace(proof, foreign=FOREIGN)
                elif mode == "reappear": self.provider.add_foreign()
                elif mode == "slow_recapture":
                    def slow_capture(runtime): runtime.clock += host.COMMAND_NS + 1
                    self.provider.on_capture = slow_capture
                else:
                    self.provider.snapshot = replace(self.provider.snapshot,
                        displays=(PHYSICAL, replace(self.provider.snapshot.displays[1], owner=STOCK)))
                with self.assertRaises(host.HostAuthorityError): self.authority.abort_pre_attach_empty(proof, self.deadline())
                self.assertEqual(self.provider.commands, [])

    def test_healthy_pre_attach_abort_late_exact_ack_reconciles_without_sending_or_clearing_failure(self):
        self.ready()
        proof = self.authority.prove_pre_attach_empty(self.deadline())
        def reply(runtime, command):
            runtime.emit("EMPTY_PRE_ATTACH_ABORT", json.loads(command.body_json), advance=host.COMMAND_NS)
            runtime.emit("DISPLAY_RELEASED", {"display": 5, "mode": "acknowledged_cleanup"},
                         mutate=lambda r: r.release())
        self.provider.on_send = reply
        with self.assertRaises(host.HostAuthorityError): self.authority.abort_pre_attach_empty(proof, self.deadline())
        original = self.provider.commands[0][0]
        self.authority.reconcile_late_ack(self.deadline())
        self.authority.assert_quiescent(self.deadline())
        self.assertEqual(self.authority.phase, "QUIESCENT")
        self.assertEqual(self.authority.state, "FAILED")
        self.assertEqual(len(self.provider.commands), 1)
        self.assertIs(self.authority._release_command, original)

    def test_healthy_pre_attach_release_failure_only_retries_identical_healthy_command(self):
        self.ready()
        proof = self.authority.prove_pre_attach_empty(self.deadline())
        self.provider.release_failure = True
        with self.assertRaises(host.HostAuthorityError): self.authority.abort_pre_attach_empty(proof, self.deadline())
        original = self.provider.commands[0][0]
        failed_proof = self.authority.prove_empty(self.deadline())
        with self.assertRaises(host.HostAuthorityError): self.authority.ack_empty(failed_proof, self.deadline())
        self.assertEqual(len(self.provider.commands), 1)
        self.provider.clock = original.deadline_ns + 1
        self.provider.release_failure = False
        self.authority.retry_release(self.deadline())
        replay, transport_deadline = self.provider.commands[1]
        self.assertIs(replay, original)
        self.assertEqual(replay.action, "ACK_NO_FOREIGN_PRE_ATTACH_ABORT")
        self.assertEqual(replay.body_json, original.body_json)
        self.assertGreater(transport_deadline, original.deadline_ns)
        self.authority.assert_quiescent(self.deadline())
        self.assertEqual(self.authority.state, "FAILED")

    def test_healthy_pre_attach_release_retry_rechecks_empty_display_identity(self):
        for mode in ("content", "owner"):
            with self.subTest(mode=mode):
                self.fresh()
                self.ready()
                proof = self.authority.prove_pre_attach_empty(self.deadline())
                self.provider.release_failure = True
                with self.assertRaises(host.HostAuthorityError): self.authority.abort_pre_attach_empty(proof, self.deadline())
                if mode == "content": self.provider.add_foreign()
                else:
                    self.provider.snapshot = replace(self.provider.snapshot,
                        displays=(PHYSICAL, replace(self.provider.snapshot.displays[1], owner=STOCK)))
                with self.assertRaises(host.HostAuthorityError): self.authority.retry_release(self.deadline())
                self.assertEqual(len(self.provider.commands), 1)

    def test_healthy_pre_attach_abort_rejects_failed_empty_ack_and_false_release_log(self):
        for mode in ("wrong_kind", "wrong_proof", "false_release"):
            with self.subTest(mode=mode):
                self.fresh()
                self.ready()
                proof = self.authority.prove_pre_attach_empty(self.deadline())
                def reply(runtime, command):
                    kind = "EMPTY_ATTACH_ABORT" if mode == "wrong_kind" else "EMPTY_PRE_ATTACH_ABORT"
                    body = {"absence_sha256": "0" * 64} if mode == "wrong_proof" else json.loads(command.body_json)
                    runtime.emit(kind, body)
                    runtime.emit("DISPLAY_RELEASED", {"display": 5, "mode": "acknowledged_cleanup"})
                self.provider.on_send = reply
                with self.assertRaises(host.HostAuthorityError): self.authority.abort_pre_attach_empty(proof, self.deadline())
                self.assertFalse(self.authority._released)
                self.assertTrue(self.authority.cleanup_obligations)

    def test_empty_failure_proof_rejects_unknown_task_on_owned_display(self):
        self.ready()
        self.provider.emit("TIMEOUT", {"phase": "foreign_attach"})
        self.authority.observe_failure(self.deadline())
        self.provider.add_foreign()
        with self.assertRaises(host.HostAuthorityError): self.authority.prove_empty(self.deadline())
        self.assertFalse(self.provider.commands)

    def test_emergency_cleanup_stays_failed_and_requires_independent_exact_absence(self):
        self.active()
        self.provider.emit("FAILED", {"display": 5, "emergency": True})
        self.authority.observe_failure(self.deadline())
        with self.assertRaises(host.HostQuiescenceError): self.authority.assert_quiescent(self.deadline())
        self.provider.remove_foreign()
        self.provider.release()
        self.authority.assert_quiescent(self.deadline())
        self.assertEqual(self.authority.state, "FAILED")
        self.assertFalse(self.authority.cleanup_obligations)
        self.assertIn(STOCK, self.provider.snapshot.processes)

    def test_release_log_alone_cannot_prove_actual_display_removal(self):
        self.active()
        proof = self.close_proof()
        def lying_release(runtime, command):
            runtime.emit("FOREIGN_DESTROYED", {"foreign": FOREIGN.wire()})
            runtime.emit("DISPLAY_RELEASED", {"display": 5, "mode": "acknowledged_cleanup"})
        self.provider.on_send = lying_release
        with self.assertRaises(host.HostQuiescenceError): self.authority.ack_destroyed(proof, self.deadline())

    def test_snapshot_incomplete_duplicate_or_flood_fails_closed(self):
        variants = ({"complete": False}, {"processes": (HOST, HOST)}, {"activities": (HOST_ACTIVITY,) * 257},
                    {"am_sha256": "missing"})
        for changes in variants:
            self.fresh()
            self.provider.snapshot = replace(self.provider.snapshot, **changes)
            with self.assertRaises(host.HostAuthorityError): self.startable()

    def test_no_input_document_launch_or_generic_process_cleanup_surface(self):
        for name in ("input", "tap", "launch_document", "launch", "kill", "kill_process", "force_stop"):
            self.assertFalse(hasattr(self.authority, name))
        with self.assertRaises(host.HostAuthorityError): host.HostAuthority(None, self.provider, SESSION, 90, "host-token")

    def test_terminal_recheck_rejects_display_or_foreign_task_reappearance(self):
        for mode in ("display", "foreign"):
            self.fresh()
            self.active()
            proof = self.close_proof()
            self.authority.ack_destroyed(proof, self.deadline())
            calls = []
            def reappear(runtime):
                calls.append(1)
                if len(calls) == 2:
                    if mode == "display": runtime.allocate()
                    else: runtime.add_foreign()
            self.provider.on_capture = reappear
            with self.assertRaises(host.HostQuiescenceError): self.authority.assert_quiescent(self.deadline())
            self.assertTrue(self.authority.cleanup_obligations)

    def test_unknown_pending_command_cannot_be_replaced_by_fresh_cleanup_sequence(self):
        self.active()
        self.provider.on_send = lambda runtime, command: None
        with self.assertRaises(host.HostAuthorityError): self.authority.place(host.Placement.FULL, self.deadline(10_000_000))
        before = len(self.provider.commands)
        with self.assertRaisesRegex(host.HostAuthorityError, "reconciliation"): self.authority.begin_close(self.deadline())
        self.assertEqual(len(self.provider.commands), before)

    def test_retained_identity_drift_blocks_cleanup_command_as_well_as_readiness(self):
        self.active()
        self.retained.process = replace(HOST, start_ticks=999)
        with self.assertRaises(host.HostAuthorityError): self.authority.begin_close(self.deadline())
        self.assertEqual(len(self.provider.commands), 1)

    def test_preissued_authenticated_ack_with_fresh_cursor_is_rejected_for_every_command_kind(self):
        cases = (
            ("ACK_FOREIGN_ATTACHED", "READY", {"foreign": FOREIGN.wire()}),
            ("PLACE_FULL", "PLACEMENT_READY", {"sequence": 1, "requested": "FULL", "effective": "FULL", "rect": [0, 0, 1404, 1872]}),
            ("BEGIN_CLOSE", "WAIT_FOREIGN_DESTROY", {"foreign": FOREIGN.wire()}),
            ("ACK_FOREIGN_DESTROYED", "FOREIGN_DESTROYED", {"foreign": FOREIGN.wire()}),
            ("ACK_NO_FOREIGN_AFTER_FAILURE", "EMPTY_ATTACH_ABORT", {"absence_sha256": "a" * 64}),
            ("ACK_FOREIGN_DESTROYED", "DISPLAY_RELEASED", {"display": 5, "mode": "acknowledged_cleanup"}),
            ("ACK_NO_FOREIGN_AFTER_FAILURE", "DISPLAY_RELEASED", {"display": 5, "mode": "acknowledged_cleanup"}),
            ("ACK_FOREIGN_DESTROYED", "DESTROY_REPLAY", {"release_retry": True}),
            ("ACK_NO_FOREIGN_AFTER_FAILURE", "EMPTY_ABORT_REPLAY", {"release_retry": True}),
            ("ACK_NO_FOREIGN_PRE_ATTACH_ABORT", "EMPTY_PRE_ATTACH_ABORT", {"absence_sha256": "a" * 64}),
            ("ACK_NO_FOREIGN_PRE_ATTACH_ABORT", "DISPLAY_RELEASED", {"display": 5, "mode": "acknowledged_cleanup"}),
            ("ACK_NO_FOREIGN_PRE_ATTACH_ABORT", "EMPTY_PRE_ATTACH_ABORT_REPLAY", {"release_retry": True}),
        )
        for action, kind, body in cases:
            with self.subTest(action=action, kind=kind):
                self.fresh()
                self.ready()
                self.provider.clock += 1000
                self.provider.on_send = lambda runtime, command: None
                command = self.authority._command(action, {}, self.deadline(), cleanup=True)
                self.provider.emit(kind, body, produced_ns=command.issued_ns - 1)
                event = self.provider.events[0][0]
                # This passes the preexisting cursor/session/global-time checks.
                self.assertEqual(event.cursor, self.authority._cursor + 1)
                self.assertGreaterEqual(event.produced_ns, self.authority._produced_ns)
                with self.assertRaisesRegex(host.HostAuthorityError, "predates exact pending"):
                    self.authority._wait(kind, command.deadline_ns, body, cleanup=True)
                self.assertIsNone(self.authority._observed_ack)
                self.assertFalse(self.authority._released or self.authority._destroyed_ack or self.authority._empty_ack)

    def test_preissued_command_progress_cannot_reacquire_or_advance_pending_command(self):
        cases = (
            ("COMMAND_DEFERRED", {"sequence": 1, "action": "PLACE_FULL"}),
            ("COMMAND_RESUMED", {"sequence": 1, "action": "PLACE_FULL"}),
            ("PLACEMENT_REQUESTED", {"sequence": 1, "requested": "FULL"}),
            ("HOST_AUTHORITY_SUSPENDED", {"remaining_ms": 1500}),
            ("HOST_AUTHORITY_REACQUIRED", {}),
            ("HOST_AUTHORITY_READY", {}),
            ("FRAME_READY", {}),
        )
        for kind, body in cases:
            with self.subTest(kind=kind):
                self.fresh()
                self.ready()
                self.provider.clock += 1000
                self.provider.on_send = lambda runtime, command: None
                command = self.authority._command("PLACE_FULL", {}, self.deadline())
                self.provider.emit(kind, body, produced_ns=command.issued_ns - 1)
                with self.assertRaisesRegex(host.HostAuthorityError, "predates exact pending"):
                    self.authority._wait("PLACEMENT_READY", command.deadline_ns, {})
                self.assertFalse(self.authority._runtime_reacquired)
                self.assertFalse(self.authority._placement_progress_seen)
                self.assertIsNone(self.authority._suspended_deadline)

    def test_public_attach_rejects_preissued_ready_without_retaining_it_for_late_reconciliation(self):
        self.ready()
        self.provider.add_foreign()
        self.provider.clock += 1000
        self.provider.on_send = lambda runtime, command: runtime.emit("READY", {"foreign": FOREIGN.wire()}, produced_ns=command.issued_ns - 1)
        with self.assertRaisesRegex(host.HostAuthorityError, "predates exact pending"):
            self.authority.attach_ack(FOREIGN, self.deadline())
        self.assertEqual(self.authority.state, "FAILED")
        self.assertIsNone(self.authority._observed_ack)
        self.assertTrue(any("foreign task 77" in item for item in self.authority.cleanup_obligations))

    def test_post_release_and_quiescent_mutating_calls_send_nothing_and_cannot_reopen(self):
        for route in ("foreign", "empty", "emergency", "healthy_empty"):
            for quiescent in (False, True):
                with self.subTest(route=route, quiescent=quiescent):
                    self.fresh()
                    if route == "healthy_empty":
                        self.ready()
                        proof = self.authority.prove_pre_attach_empty(self.deadline())
                        self.authority.abort_pre_attach_empty(proof, self.deadline())
                    elif route == "empty":
                        self.ready()
                        self.provider.emit("TIMEOUT", {"phase": "foreign_attach"})
                        self.authority.observe_failure(self.deadline())
                        proof = self.authority.prove_empty(self.deadline())
                        self.authority.ack_empty(proof, self.deadline())
                    else:
                        self.active()
                        if route == "emergency":
                            self.provider.emit("FAILED", {"display": 5, "emergency": True})
                            self.authority.observe_failure(self.deadline())
                        proof = self.close_proof()
                        self.authority.ack_destroyed(proof, self.deadline())
                    if quiescent: self.authority.assert_quiescent(self.deadline())
                    before = (len(self.provider.commands), self.authority.sequence, self.authority.phase, self.authority.failure)
                    calls = (
                        lambda: self.authority.begin_close(self.deadline()),
                        lambda: self.authority.ack_empty(proof, self.deadline()),
                        lambda: self.authority.ack_destroyed(proof, self.deadline()),
                        lambda: self.authority.abort_pre_attach_empty(proof, self.deadline()),
                        lambda: self.authority.retry_release(self.deadline()),
                        lambda: self.authority.attach_ack(FOREIGN, self.deadline()),
                        lambda: self.authority.place(host.Placement.FULL, self.deadline()),
                        lambda: self.authority.reconcile_late_ack(self.deadline()),
                        lambda: self.authority._command("BEGIN_CLOSE", {}, self.deadline(), cleanup=True),
                    )
                    for call in calls:
                        with self.assertRaisesRegex(host.HostAuthorityError, "permanently sealed"): call()
                        self.assertEqual((len(self.provider.commands), self.authority.sequence, self.authority.phase, self.authority.failure), before)
                    self.authority.assert_quiescent(self.deadline())
                    self.authority.assert_quiescent(self.deadline())
                    self.assertEqual(len(self.provider.commands), before[0])
                    self.assertFalse(self.authority.cleanup_obligations)

    def test_later_failed_absence_check_cannot_undo_terminal_command_seal(self):
        self.active()
        proof = self.close_proof()
        self.authority.ack_destroyed(proof, self.deadline())
        self.authority.assert_quiescent(self.deadline())
        self.provider.allocate()
        with self.assertRaises(host.HostQuiescenceError): self.authority.assert_quiescent(self.deadline())
        self.assertFalse(self.authority._released)
        before = len(self.provider.commands)
        with self.assertRaisesRegex(host.HostAuthorityError, "permanently sealed"): self.authority.begin_close(self.deadline())
        with self.assertRaisesRegex(host.HostAuthorityError, "permanently sealed"): self.authority.ack_destroyed(proof, self.deadline())
        self.assertEqual(len(self.provider.commands), before)


if __name__ == "__main__": unittest.main()
