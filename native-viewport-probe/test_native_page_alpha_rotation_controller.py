from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import native_page_alpha_rotation_controller as controller


CONTROLLER_ID = "0123456789abcdef0123456789abcdef"


def display_wire(rotation: int) -> bytes:
    width, height = ((1404, 1872) if rotation in (0, 2) else (1872, 1404))
    return f"""WINDOW MANAGER DISPLAY CONTENTS (dumpsys window displays)
  Display: mDisplayId=0 stacks=1
    init=1404x1872 300dpi cur={width}x{height} app={width}x{height}
    mDisplayInfo=DisplayInfo{{"Built-in Screen", displayId 0, rotation {rotation}, state ON, type INTERNAL}}
    DisplayFrames w={width} h={height} r={rotation}
    mRotation={rotation} mDeferredRotationPauseCount=0
""".encode("ascii")


class FakeDevice:
    def __init__(self, *, final_physical: int = 2) -> None:
        self.rotation = ("1", "2")
        self.physical = final_physical
        self.final_physical = final_physical
        self.commands: list[str] = []
        self.identity_value = dict(controller.EXPECTED_DEVICE_IDENTITY)
        self.transport: dict[str, str] = {}
        self.identity_reads = 0
        self.identity_drift_on_read: int | None = None
        self.settings_reads = 0
        self.drift_on_read: int | None = None

    def identity(self) -> dict[str, str]:
        self.identity_reads += 1
        if self.identity_drift_on_read == self.identity_reads:
            self.identity_value["currentUser"] = "10"
        return dict(self.identity_value)

    def settings(self) -> tuple[str, str]:
        self.settings_reads += 1
        if self.drift_on_read == self.settings_reads:
            self.rotation = ("1", "3")
        return self.rotation

    def window_displays(self) -> bytes:
        return display_wire(self.physical)

    def command(self, operation: str) -> None:
        self.commands.append(operation)
        mode = self.transport.get(operation, "ok")
        if mode != "unapplied":
            if operation in {"BOOTSTRAP_LOCK_ZERO", "PORTRAIT"}:
                self.rotation = ("0", "0")
                self.physical = 0
            elif operation in {"START_LANDSCAPE", "RETURN_LANDSCAPE"}:
                self.rotation = ("0", "1")
                self.physical = 1
            elif operation == "RESTORE_LOCK_TWO":
                self.rotation = ("0", "2")
                self.physical = 2
            elif operation == "RESTORE_FREE":
                self.rotation = ("1", "2")
                self.physical = self.final_physical
            else:
                raise AssertionError(operation)
        if mode in {"applied_uncertain", "unapplied"}:
            raise controller.ControllerError("simulated transport uncertainty")


class FakeChild:
    def __init__(self, lines: list[controller.ChildLine], *, returncode: int = 0,
                 pid: int = 1234) -> None:
        self.pid = pid
        self.argv = ("python", "runner")
        self._lines = lines
        self._returncode = returncode
        self._exited = False
        self._stdout = b"".join(item.raw for item in lines if item.stream == "stdout")
        self._stderr = b"".join(item.raw for item in lines if item.stream == "stderr")

    def lines(self, timeout: float):
        del timeout
        for item in self._lines:
            yield item
        self._exited = True

    def wait(self, timeout: float) -> int:
        del timeout
        self._exited = True
        return self._returncode

    def poll(self) -> int | None:
        return self._returncode if self._exited else None

    @property
    def stdout_bytes(self) -> bytes:
        return self._stdout

    @property
    def stderr_bytes(self) -> bytes:
        return self._stderr


class ToolFixture:
    def __init__(self, root: Path) -> None:
        self.paths: dict[str, Path] = {}
        for name in ("controller", "python", "runner", "adb"):
            path = root / (name + ".bin")
            path.write_bytes((name + "\n").encode("ascii"))
            self.paths[name] = path
        self.identities = {
            name: controller.read_regular_identity(path, 1024, name)
            for name, path in self.paths.items()
        }


def phase_lines(controller_id: str = CONTROLLER_ID) -> list[controller.ChildLine]:
    result = [controller.ChildLine("stdout", b"diagnostic line\n")]
    for sequence, phase in enumerate(controller.PHASES, 1):
        result.append(controller.ChildLine(
            "stdout", controller.encode_phase(controller_id, phase, sequence)))
    return result


def observation(accelerometer: str, user: str, physical: int,
                digest_character: str = "a") -> dict[str, object]:
    settings = {
        "accelerometerRotation": accelerometer,
        "userRotation": user,
    }
    return {
        "physicalRotation": physical,
        "settingsAfter": dict(settings),
        "settingsBefore": dict(settings),
        "windowDisplaysSha256": digest_character * 64,
    }


class RotationControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.tools = ToolFixture(self.root)
        self.journal_path = self.root / "rotation.jsonl"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_journal(self) -> controller.DurableJournal:
        return controller.DurableJournal(
            self.journal_path,
            controller._header(CONTROLLER_ID, self.tools.identities))

    def child_argv(self) -> list[str]:
        return [
            self.tools.identities["python"].path, "-u",
            self.tools.identities["runner"].path,
            "--adb", self.tools.identities["adb"].path,
            "--serial", controller.AUTHORIZED_SERIAL,
            "--output-root", str((self.root / "output").absolute()),
            "--host-metadata", str((self.root / "host.json").absolute()),
            "--rotation-authority", controller.alpha.ROTATION_ADB_SYSTEM_SETTINGS,
            "--rotation-controller-run-id", CONTROLLER_ID,
        ]

    def run_happy(self, *, final_physical: int = 2,
                  child: FakeChild | None = None,
                  device: FakeDevice | None = None):
        selected_device = device or FakeDevice(final_physical=final_physical)
        selected_child = child or FakeChild(phase_lines())
        journal = self.make_journal()
        try:
            value = controller.RotationController(
                selected_device, journal, CONTROLLER_ID,
                self.tools.identities, sleep=lambda _: None,
                child_factory=lambda _: selected_child).run(self.child_argv())
        finally:
            journal.close()
        return value, selected_device

    def test_happy_path_has_exact_mutation_order_and_restores_each_physical(self) -> None:
        for final_physical in range(4):
            with self.subTest(final_physical=final_physical):
                if self.journal_path.exists():
                    self.journal_path.unlink()
                value, device = self.run_happy(final_physical=final_physical)
                self.assertEqual(device.commands, [
                    "BOOTSTRAP_LOCK_ZERO", "START_LANDSCAPE", "PORTRAIT",
                    "RETURN_LANDSCAPE", "RESTORE_LOCK_TWO", "RESTORE_FREE"])
                self.assertEqual(device.rotation, ("1", "2"))
                self.assertEqual(device.physical, final_physical)
                self.assertEqual(value["phases"], list(controller.PHASES))
                self.assertEqual(value["result"], "ROTATION_CONTROLLER_CLEAN")
                parsed = controller.read_journal(self.journal_path, allow_torn=False)
                self.assertEqual(parsed.records[-1]["kind"], "complete")

    def test_phase_wire_is_exact_canonical_bound_and_ordered(self) -> None:
        line = controller.encode_phase(CONTROLLER_ID, "START_LANDSCAPE", 1)
        parsed = controller.parse_phase_line(line, CONTROLLER_ID, 1)
        self.assertEqual(parsed.phase, "START_LANDSCAPE")
        self.assertIsNone(controller.parse_phase_line(b"ordinary output\n", CONTROLLER_ID, 1))
        mutations = {
            "stale nonce": line.replace(CONTROLLER_ID.encode(), b"f" * 32),
            "wrong sequence": controller.encode_phase(CONTROLLER_ID, "PORTRAIT", 2),
            "duplicate key": (controller.PHASE_PREFIX +
                              b'{"authority":"native-page-alpha-rotation-phase-v1",'
                              b'"authority":"native-page-alpha-rotation-phase-v1",'
                              b'"controllerId":"' + CONTROLLER_ID.encode() +
                              b'","phase":"START_LANDSCAPE","sequence":1}\n'),
            "extra key": line[:-2] + b',"x":1}\n',
            "not canonical": line.replace(b'":', b'": ', 1),
            "partial": line[:-1],
        }
        for label, raw in mutations.items():
            with self.subTest(label=label), self.assertRaises(controller.ControllerError):
                controller.parse_phase_line(raw, CONTROLLER_ID, 1)

    def test_duplicate_reordered_missing_and_nonzero_child_restore(self) -> None:
        cases = {
            "duplicate": [
                controller.ChildLine("stdout", controller.encode_phase(
                    CONTROLLER_ID, "START_LANDSCAPE", 1)),
                controller.ChildLine("stdout", controller.encode_phase(
                    CONTROLLER_ID, "START_LANDSCAPE", 1)),
            ],
            "reordered": [controller.ChildLine(
                "stdout", controller.encode_phase(CONTROLLER_ID, "PORTRAIT", 2))],
            "missing": phase_lines()[:-1],
            "nonzero": phase_lines(),
        }
        for label, lines in cases.items():
            with self.subTest(label=label):
                if self.journal_path.exists():
                    self.journal_path.unlink()
                device = FakeDevice()
                child = FakeChild(lines, returncode=7 if label == "nonzero" else 0)
                with self.assertRaises(controller.ControllerError):
                    self.run_happy(child=child, device=device)
                self.assertEqual(device.rotation, ("1", "2"))
                self.assertEqual(device.commands[-2:], ["RESTORE_LOCK_TWO", "RESTORE_FREE"])

    def test_diagnostic_clean_child_may_exit_after_any_settled_phase_prefix(self) -> None:
        prefixes = ([], phase_lines()[1:2], phase_lines()[1:3], phase_lines()[1:])
        for index, lines in enumerate(prefixes):
            with self.subTest(prefix=index):
                if self.journal_path.exists():
                    self.journal_path.unlink()
                device = FakeDevice()
                value, device = self.run_happy(
                    child=FakeChild(lines, returncode=3), device=device)
                self.assertEqual(
                    value["result"],
                    "ROTATION_CONTROLLER_CHILD_DIAGNOSTIC_CLEAN")
                self.assertEqual(value["returncode"], 3)
                self.assertEqual(device.rotation, ("1", "2"))
                parsed = controller.read_journal(
                    self.journal_path, allow_torn=False)
                self.assertEqual(parsed.records[-1]["kind"], "complete")

    def test_applied_transport_uncertainty_is_observed_not_inferred(self) -> None:
        device = FakeDevice()
        device.transport["START_LANDSCAPE"] = "applied_uncertain"
        value, device = self.run_happy(device=device)
        self.assertEqual(value["result"], "ROTATION_CONTROLLER_CLEAN")
        records = controller.read_journal(self.journal_path, allow_torn=False).records
        settlement = next(record for record in records
                          if record["kind"] == "rotation_settlement" and
                          record["payload"]["operation"] == "START_LANDSCAPE")
        self.assertIn("simulated transport uncertainty",
                      settlement["payload"]["transportUncertain"])

    def test_unapplied_transport_uncertainty_fails_and_restores(self) -> None:
        device = FakeDevice()
        device.transport["START_LANDSCAPE"] = "unapplied"
        with self.assertRaises(controller.ControllerError):
            self.run_happy(device=device)
        self.assertEqual(device.rotation, ("1", "2"))
        self.assertEqual(device.commands[-2:], ["RESTORE_LOCK_TWO", "RESTORE_FREE"])

    def test_external_drift_between_observations_fails_closed(self) -> None:
        device = FakeDevice()
        # Admission consumes four setting reads. Bootstrap guard consumes four;
        # then drift during bootstrap proof prevents two agreeing observations.
        device.drift_on_read = 10
        with self.assertRaises(controller.ControllerError):
            self.run_happy(device=device)
        self.assertEqual(device.rotation, ("1", "2"))

    def test_tool_path_replacement_before_first_mutation_causes_zero_commands(self) -> None:
        journal = self.make_journal()
        device = FakeDevice()
        self.tools.paths["runner"].write_bytes(b"replacement\n")
        try:
            with self.assertRaises(controller.ControllerError):
                controller.RotationController(
                    device, journal, CONTROLLER_ID, self.tools.identities,
                    sleep=lambda _: None,
                    child_factory=lambda _: FakeChild(phase_lines())).run(
                        ("python", "runner"))
        finally:
            journal.close()
        self.assertEqual(device.commands, [])

    def test_journal_rejects_reuse_tamper_and_arbitrary_torn_suffix(self) -> None:
        journal = self.make_journal()
        journal.close()
        with self.assertRaises(controller.ControllerError):
            self.make_journal()
        with self.journal_path.open("ab") as stream:
            stream.write(b"binary\x00tail")
        with self.assertRaises(controller.ControllerError):
            controller.read_journal(self.journal_path, allow_torn=True)

    def test_plausible_torn_record_is_classified_but_not_authority(self) -> None:
        journal = self.make_journal()
        journal.record("rotation_intent", {
            "command": controller._command_wire("BOOTSTRAP_LOCK_ZERO"),
            "operation": "BOOTSTRAP_LOCK_ZERO",
            "target": {"accelerometerRotation": "0", "userRotation": "0",
                       "physicalRotation": 0},
        })
        journal.close()
        with self.journal_path.open("ab") as stream:
            stream.write(b'{"kind":"restore_intent","payload":{')
        parsed = controller.read_journal(self.journal_path, allow_torn=True)
        self.assertTrue(parsed.torn)
        self.assertEqual(parsed.records[-1]["kind"], "rotation_intent")

    def test_journal_exact_write_loop_and_zero_progress_poisoning(self) -> None:
        journal = self.make_journal()
        original = journal._stream

        class Partial:
            closed = False
            def __init__(self, target, zero: bool = False):
                self.target = target
                self.zero = zero
            def write(self, raw):
                if self.zero:
                    return 0
                return self.target.write(raw[:1])
            def flush(self):
                self.target.flush()
            def fileno(self):
                return self.target.fileno()

        journal._stream = Partial(original)
        journal.record("rotation_intent", {
            "command": controller._command_wire("BOOTSTRAP_LOCK_ZERO"),
            "operation": "BOOTSTRAP_LOCK_ZERO",
            "target": {"accelerometerRotation": "0", "userRotation": "0",
                       "physicalRotation": 0},
        })
        journal._stream = Partial(original, zero=True)
        with self.assertRaises(controller.ControllerError):
            journal.record("restore_intent", {})
        with self.assertRaises(controller.ControllerError):
            journal.record("restore_intent", {})
        journal._stream = original
        journal.close()

    def test_grammar_rejects_phase_without_receipt_and_records_after_terminal(self) -> None:
        journal = self.make_journal()
        journal.record("rotation_intent", {
            "command": controller._command_wire("BOOTSTRAP_LOCK_ZERO"),
            "operation": "BOOTSTRAP_LOCK_ZERO",
            "target": {"accelerometerRotation": "0", "userRotation": "0",
                       "physicalRotation": 0},
        })
        journal.record("rotation_settlement", {
            "observations": [observation("0", "0", 0),
                             observation("0", "0", 0, "b")],
            "operation": "BOOTSTRAP_LOCK_ZERO",
            "transportUncertain": None})
        journal.record("child_start_intent", {
            "argv": self.child_argv(), "controllerId": CONTROLLER_ID})
        journal.record("child_started", {"controllerId": CONTROLLER_ID, "pid": 10})
        journal.record("rotation_intent", {
            "command": controller._command_wire("START_LANDSCAPE"),
            "operation": "START_LANDSCAPE",
            "target": {"accelerometerRotation": "0", "userRotation": "1",
                       "physicalRotation": 1},
        })
        journal.close()
        with self.assertRaises(controller.ControllerError):
            controller.read_journal(self.journal_path, allow_torn=False)

    def test_grammar_rejects_mutated_target_and_empty_observations(self) -> None:
        for case in ("target", "observations"):
            with self.subTest(case=case):
                if self.journal_path.exists():
                    self.journal_path.unlink()
                journal = self.make_journal()
                target = {
                    "accelerometerRotation": "0", "userRotation": "0",
                    "physicalRotation": 0,
                }
                if case == "target":
                    target["physicalRotation"] = 1
                journal.record("rotation_intent", {
                    "command": controller._command_wire("BOOTSTRAP_LOCK_ZERO"),
                    "operation": "BOOTSTRAP_LOCK_ZERO", "target": target,
                })
                if case == "observations":
                    journal.record("rotation_settlement", {
                        "observations": [{}, {}],
                        "operation": "BOOTSTRAP_LOCK_ZERO",
                        "transportUncertain": None,
                    })
                journal.close()
                with self.assertRaises(controller.ControllerError):
                    controller.read_journal(self.journal_path, allow_torn=False)

    def test_grammar_rejects_each_mutated_observation_authority(self) -> None:
        for case in ("accelerometer", "user", "physical", "digest", "extra"):
            with self.subTest(case=case):
                if self.journal_path.exists():
                    self.journal_path.unlink()
                journal = self.make_journal()
                journal.record("rotation_intent", {
                    "command": controller._command_wire("BOOTSTRAP_LOCK_ZERO"),
                    "operation": "BOOTSTRAP_LOCK_ZERO",
                    "target": controller._target_wire(("0", "0", 0)),
                })
                mutated = observation("0", "0", 0)
                if case == "accelerometer":
                    mutated["settingsBefore"]["accelerometerRotation"] = "1"
                elif case == "user":
                    mutated["settingsAfter"]["userRotation"] = "2"
                elif case == "physical":
                    mutated["physicalRotation"] = 1
                elif case == "digest":
                    mutated["windowDisplaysSha256"] = "not-a-digest"
                else:
                    mutated["unexpected"] = True
                journal.record("rotation_settlement", {
                    "observations": [mutated, observation("0", "0", 0, "b")],
                    "operation": "BOOTSTRAP_LOCK_ZERO",
                    "transportUncertain": None,
                })
                journal.close()
                with self.assertRaises(controller.ControllerError):
                    controller.read_journal(self.journal_path, allow_torn=False)

    def test_grammar_rejects_mutated_or_open_child_argv(self) -> None:
        mutations = {
            "buffered_python": (1, "runner.py"),
            "wrong_serial": (6, "boox"),
            "relative_output": (8, "relative-output"),
            "wrong_controller": (14, "f" * 32),
        }
        for case, (index, replacement) in mutations.items():
            with self.subTest(case=case):
                if self.journal_path.exists():
                    self.journal_path.unlink()
                journal = self.make_journal()
                journal.record("rotation_intent", {
                    "command": controller._command_wire("BOOTSTRAP_LOCK_ZERO"),
                    "operation": "BOOTSTRAP_LOCK_ZERO",
                    "target": controller._target_wire(("0", "0", 0)),
                })
                journal.record("rotation_settlement", {
                    "observations": [observation("0", "0", 0),
                                     observation("0", "0", 0, "b")],
                    "operation": "BOOTSTRAP_LOCK_ZERO",
                    "transportUncertain": None,
                })
                argv = self.child_argv()
                argv[index] = replacement
                journal.record("child_start_intent", {
                    "argv": argv, "controllerId": CONTROLLER_ID,
                })
                journal.close()
                with self.assertRaises(controller.ControllerError):
                    controller.read_journal(self.journal_path, allow_torn=False)

    def test_adb_adapter_always_addresses_only_exact_nomad(self) -> None:
        calls: list[tuple[str, ...]] = []
        replies = iter((
            b"device\n",
            (controller.AUTHORIZED_SERIAL + "\n").encode(),
            (controller.AUTHORIZED_SERIAL + "\n").encode(),
            (controller.alpha.MODEL + "\n").encode(),
            (controller.alpha.SDK + "\n").encode(),
            (controller.alpha.FINGERPRINT + "\n").encode(),
            b"0\n",
            b"",
        ))
        def execute(argv, **kwargs):
            del kwargs
            calls.append(tuple(argv))
            return SimpleNamespace(returncode=0, stdout=next(replies), stderr=b"")
        device = controller.AdbRotationDevice(
            controller.PINNED_ADB_PATH, controller.AUTHORIZED_SERIAL,
            executor=execute)
        self.assertEqual(device.identity()["serial"], controller.AUTHORIZED_SERIAL)
        device.command("PORTRAIT")
        self.assertTrue(calls)
        self.assertTrue(all(call[1:3] == ("-s", controller.AUTHORIZED_SERIAL)
                            for call in calls))
        self.assertFalse(any("boox" in token.lower() for call in calls for token in call))

    def test_adb_adapter_rejects_same_serial_with_wrong_firmware(self) -> None:
        replies = iter((
            b"device\n",
            (controller.AUTHORIZED_SERIAL + "\n").encode(),
            (controller.AUTHORIZED_SERIAL + "\n").encode(),
            (controller.alpha.MODEL + "\n").encode(),
            (controller.alpha.SDK + "\n").encode(),
            b"wrong-fingerprint\n",
            b"0\n",
        ))
        def execute(argv, **kwargs):
            del argv, kwargs
            return SimpleNamespace(returncode=0, stdout=next(replies), stderr=b"")
        device = controller.AdbRotationDevice(
            controller.PINNED_ADB_PATH, controller.AUTHORIZED_SERIAL,
            executor=execute)
        with self.assertRaisesRegex(controller.ControllerError, "exact Nomad"):
            device.identity()

    def test_guard_rejects_device_identity_drift(self) -> None:
        device = FakeDevice()
        journal = self.make_journal()
        try:
            value = controller.RotationController(
                device, journal, CONTROLLER_ID, self.tools.identities,
                sleep=lambda _: None, child_factory=lambda _: FakeChild(phase_lines()))
            device.identity_value["currentUser"] = "10"
            with self.assertRaisesRegex(controller.ControllerError, "identity changed"):
                value._guard(controller.ORIGINAL_SETTINGS, None)
            self.assertEqual(device.commands, [])
        finally:
            journal.close()

    def test_guard_rejects_journal_path_drift_before_device_mutation(self) -> None:
        device = FakeDevice()
        journal = self.make_journal()
        try:
            value = controller.RotationController(
                device, journal, CONTROLLER_ID, self.tools.identities,
                sleep=lambda _: None, child_factory=lambda _: FakeChild(phase_lines()))
            with patch.object(
                    journal, "assert_current_path",
                    side_effect=controller.ControllerError("journal drift")):
                with self.assertRaisesRegex(controller.ControllerError,
                                            "journal drift"):
                    value._guard(controller.ORIGINAL_SETTINGS, None)
            self.assertEqual(device.identity_reads, 0)
            self.assertEqual(device.commands, [])
        finally:
            journal.close()

    def test_restore_only_rechecks_identity_before_each_mutation(self) -> None:
        journal = self.make_journal()
        journal.record("rotation_intent", {
            "command": controller._command_wire("BOOTSTRAP_LOCK_ZERO"),
            "operation": "BOOTSTRAP_LOCK_ZERO",
            "target": {"accelerometerRotation": "0", "userRotation": "0",
                       "physicalRotation": 0},
        })
        journal.close()
        device = FakeDevice()
        device.rotation = ("0", "0")
        device.physical = 0
        # Initial restore-only admission, lock guard, then drift before free.
        device.identity_drift_on_read = 3
        arguments = SimpleNamespace(journal=self.journal_path)
        with patch.object(controller, "AdbRotationDevice", return_value=device), \
                patch.object(controller, "_tool_identities",
                             return_value=self.tools.identities), \
                patch.object(controller, "prove_twice",
                             side_effect=controller.ControllerError(
                                 "rotation target was not proved twice")):
            with self.assertRaises(controller.ControllerError):
                controller._restore_only(arguments)
        self.assertEqual(device.commands, ["RESTORE_LOCK_TWO"])


if __name__ == "__main__":
    unittest.main()
