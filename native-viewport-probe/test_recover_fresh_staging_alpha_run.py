from __future__ import annotations

from dataclasses import replace
import shutil
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import native_page_alpha_runner as alpha
import native_page_host_authority as host
import recover_fresh_staging_alpha_run as recovery


class FakeDevice:
    HOST_APK = "/data/app/~~fixed/com.techrebbe.supernote.nativepagehost/base.apk"

    def __init__(self) -> None:
        self.history: list[dict[str, object]] = []
        self.files = {
            alpha.SOURCE_PDF: recovery.PINNED_SOURCE_PDF,
            alpha.SOURCE_MARK: recovery.PINNED_SOURCE_MARK,
            alpha.PARKING_PDF: recovery.PINNED_PARKING,
            recovery.STAGING_PDF: recovery.PINNED_STAGING,
        }
        self.host_live = False
        self.document_live = True
        self.activities_raw = b"no activity tasks\n"
        self.windows_raw = b"no windows\n"
        self.displays_raw = b"no virtual displays\n"
        self.fd_targets = (alpha.PARKING_PDF,)
        self.remove_raises_after_unlink = False

    def adb_authority(self):
        return {"sha256": recovery.shared.PINNED_ADB_SHA256}

    def get_state(self): return "device"
    def get_serial(self): return alpha.AUTHORIZED_SERIAL
    def getprop(self, name):
        return {
            "ro.product.model": alpha.MODEL,
            "ro.build.version.sdk": alpha.SDK,
            "ro.build.fingerprint": alpha.FINGERPRINT,
        }[name]
    def current_user(self): return "0"
    def package_dump(self, package):
        if package == alpha.DOCUMENT_PACKAGE:
            return (f"Package [{package}]\n versionCode={alpha.DOCUMENT_VERSION_CODE} "
                    f"targetSdk=30\n versionName={alpha.DOCUMENT_VERSION_NAME}\n")
        return (f"Package [{package}]\n versionCode={alpha.HOST_VERSION_CODE} "
                f"targetSdk=30\n versionName={alpha.HOST_VERSION_NAME}\n")
    def package_path(self, package):
        return alpha.DOCUMENT_APK if package == alpha.DOCUMENT_PACKAGE else self.HOST_APK
    def sha256_file(self, path):
        if path == alpha.DOCUMENT_APK: return alpha.DOCUMENT_APK_SHA256
        if path == self.HOST_APK: return alpha.ALPHA_SIGNED_APK_SHA256
        return self.files[path].sha256
    def stat_file(self, path, *, absent_ok=False):
        value = self.files.get(path)
        if value is None and not absent_ok:
            raise recovery.RecoveryError("missing fake path " + path)
        return value
    def activities(self): return self.activities_raw
    def windows(self): return self.windows_raw
    def displays(self): return self.displays_raw
    def pidof(self, package):
        if package == alpha.HOST_PACKAGE:
            return (4444,) if self.host_live else ()
        return (2053,) if self.document_live else ()
    def process_identity(self, pid, package):
        return host.ProcessIdentity(pid, 3382, 1000, package)
    def process_fd_links(self, pid):
        return "".join(
            f"lr-x------ 1 root root 64 2026-09-16 17:00 {index} -> {path}\n"
            for index, path in enumerate(self.fd_targets, 10)
        )
    def rotation_settings(self): return ("1", "2")
    def remove_staging_member(self, staging):
        if staging != recovery.STAGING_PDF:
            raise AssertionError("escaped staging path")
        self.history.append({"operation": "remove_staging", "path": staging})
        self.files.pop(staging)
        if self.remove_raises_after_unlink:
            self.remove_raises_after_unlink = False
            raise recovery.RecoveryError("simulated transport loss after unlink")
        return alpha.CommandResult("remove_staging", (), 0, b"", b"")


class RecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.run_dir = self.root / recovery.RUN_ID
        self.run_dir.mkdir()
        self.report_path = self.run_dir / "report.json"
        self.report_path.write_bytes(b"pinned-report-placeholder\n")
        fixture_active = (
            Path(__file__).parent / "build/native-page-alpha-runs" /
            alpha.ACTIVE_MUTATION_JOURNAL_FILENAME
        )
        if not fixture_active.exists():
            fixture_active = (
                Path(__file__).parent / recovery.REPORT_RELATIVE.parent /
                recovery.RETIRED_BASENAME
            )
        self.active_path = self.root / alpha.ACTIVE_MUTATION_JOURNAL_FILENAME
        shutil.copyfile(fixture_active, self.active_path)
        _, report_wire = recovery._read_local(
            self.report_path, 1024, "test report")
        _, active_wire = recovery._read_local(
            self.active_path, alpha.MUTATION_JOURNAL_MAX_BYTES,
            "test active journal")
        self.authority = recovery.RunAuthority(
            self.root, self.run_dir, report_wire, active_wire,
            self.run_dir / recovery.RECOVERY_BASENAME,
            self.run_dir / recovery.RETIRED_BASENAME,
            self.run_dir / recovery.EVIDENCE_BASENAME,
        )
        self.device = FakeDevice()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def session(self):
        return recovery.Recovery(self.device, self.authority, sleep=lambda _: None)

    def test_default_plan_is_read_only(self):
        evidence = self.session().plan()
        self.assertEqual("PLAN_READY", evidence["result"])
        self.assertFalse(evidence["deviceMutationAttempted"])
        self.assertIn(recovery.STAGING_PDF, self.device.files)
        self.assertEqual([], self.device.history)
        self.assertTrue(self.active_path.exists())
        self.assertFalse(self.authority.recovery_path.exists())

    def test_execute_unlinks_only_staging_then_retires(self):
        evidence = self.session().execute()
        self.assertEqual("RECOVERED_CLEANLY", evidence["result"])
        self.assertEqual(
            [{"operation": "remove_staging", "path": recovery.STAGING_PDF}],
            self.device.history)
        self.assertNotIn(recovery.STAGING_PDF, self.device.files)
        self.assertEqual(recovery.PINNED_SOURCE_PDF,
                         self.device.files[alpha.SOURCE_PDF])
        self.assertEqual(recovery.PINNED_SOURCE_MARK,
                         self.device.files[alpha.SOURCE_MARK])
        self.assertFalse(self.active_path.exists())
        self.assertTrue(self.authority.retired_path.exists())
        self.assertEqual(
            recovery.ACTIVE_JOURNAL_SHA256,
            recovery._read_local(
                self.authority.retired_path,
                recovery.ACTIVE_JOURNAL_BYTES, "retired")[1].sha256)
        self.assertEqual(
            recovery.RecoveryJournal.EVENTS,
            tuple(evidence["recoveryEvents"]))
        self.assertTrue(self.authority.evidence_path.exists())

    def test_completed_rerun_is_idempotent_and_repairs_partial_evidence(self):
        first = self.session().execute()
        complete = self.authority.evidence_path.read_bytes()
        second = self.session().execute()
        self.assertEqual(first, second)
        self.assertEqual(complete, self.authority.evidence_path.read_bytes())
        self.authority.evidence_path.write_bytes(complete[:len(complete) // 2])
        third = self.session().execute()
        self.assertEqual(first, third)
        self.assertEqual(complete, self.authority.evidence_path.read_bytes())

    def test_resume_after_uncertain_unlink(self):
        self.device.remove_raises_after_unlink = True
        with self.assertRaisesRegex(recovery.RecoveryError, "transport loss"):
            self.session().execute()
        self.assertFalse(self.active_path.exists() is False)
        self.assertNotIn(recovery.STAGING_PDF, self.device.files)
        evidence = self.session().execute()
        self.assertEqual("RECOVERED_CLEANLY", evidence["result"])
        self.assertEqual(1, len(self.device.history))

    def test_torn_next_record_is_truncated_then_recovered(self):
        self.device.remove_raises_after_unlink = True
        with self.assertRaises(recovery.RecoveryError):
            self.session().execute()
        with self.authority.recovery_path.open("ab") as stream:
            stream.write(b'{"kind":"delete_settled","payload":')
        evidence = self.session().execute()
        self.assertEqual("RECOVERED_CLEANLY", evidence["result"])
        self.assertEqual(1, len(self.device.history))

    def test_partial_first_header_is_recovered_before_any_device_mutation(self):
        probe = recovery.RecoveryJournal.__new__(recovery.RecoveryJournal)
        probe.authority = self.authority
        partial = probe._header_record_bytes()[:41]
        self.authority.recovery_path.write_bytes(partial)
        evidence = self.session().execute()
        self.assertEqual("RECOVERED_CLEANLY", evidence["result"])
        self.assertEqual(1, len(self.device.history))

    def test_reappeared_staging_after_retire_intent_blocks_retirement(self):
        with mock.patch.object(
                recovery, "_retire_active",
                side_effect=recovery.RecoveryError("crash before retirement")):
            with self.assertRaisesRegex(recovery.RecoveryError,
                                        "crash before retirement"):
                self.session().execute()
        self.device.files[recovery.STAGING_PDF] = recovery.PINNED_STAGING
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "still exists after cleanup"):
            self.session().execute()
        self.assertTrue(self.active_path.exists())
        self.assertFalse(self.authority.retired_path.exists())

    def test_source_replacement_fails_closed_without_mutation(self):
        self.device.files[alpha.SOURCE_PDF] = replace(
            recovery.PINNED_SOURCE_PDF, inode=999999)
        with self.assertRaisesRegex(recovery.RecoveryError, "source PDF"):
            self.session().execute()
        self.assertEqual([], self.device.history)
        self.assertTrue(self.active_path.exists())

    def test_neighbor_target_fails_closed_without_mutation(self):
        self.device.files[alpha.TARGET_PDF] = replace(
            recovery.PINNED_STAGING, path=alpha.TARGET_PDF)
        with self.assertRaisesRegex(recovery.RecoveryError, "neighbor path"):
            self.session().execute()
        self.assertEqual([], self.device.history)

    def test_host_process_fails_closed(self):
        self.device.host_live = True
        with self.assertRaisesRegex(recovery.RecoveryError, "host process"):
            self.session().plan()

    def test_descriptor_reference_fails_closed(self):
        self.device.fd_targets = (alpha.PARKING_PDF, recovery.STAGING_PDF)
        with self.assertRaisesRegex(recovery.RecoveryError, "cleanup scope"):
            self.session().plan()

    def test_document_task_fails_closed(self):
        self.device.activities_raw = (
            b"task com.supernote.document/.DocumentActivity\n")
        with self.assertRaisesRegex(recovery.RecoveryError, "task or window"):
            self.session().plan()

    def test_irrelevant_dumpsys_volatility_does_not_defeat_stable_proof(self):
        counter = {"value": 0}
        def changing_activities():
            counter["value"] += 1
            return f"unrelated volatile counter={counter['value']}\n".encode()
        self.device.activities = changing_activities
        evidence = self.session().plan()
        self.assertEqual("PLAN_READY", evidence["result"])
        self.assertEqual(2, counter["value"])

    def test_relevant_second_observation_task_mutation_fails_closed(self):
        counter = {"value": 0}
        def changing_activities():
            counter["value"] += 1
            if counter["value"] == 1:
                return b"unrelated first observation\n"
            return b"task com.supernote.document/.DocumentActivity\n"
        self.device.activities = changing_activities
        with self.assertRaisesRegex(recovery.RecoveryError, "task or window"):
            self.session().plan()
        self.assertEqual([], self.device.history)

    def test_relevant_second_observation_window_or_display_fails_closed(self):
        for channel, injected, expected in (
                ("windows", b"com.supernote.document/.DocumentActivity\n",
                 "task or window"),
                ("displays", alpha.HOST_PACKAGE.encode() + b"\n",
                 "retains failed alpha scope")):
            with self.subTest(channel=channel):
                device = FakeDevice()
                counter = {"value": 0}
                def changing():
                    counter["value"] += 1
                    return b"unrelated first observation\n" if counter["value"] == 1 else injected
                setattr(device, channel, changing)
                with self.assertRaisesRegex(recovery.RecoveryError, expected):
                    recovery.Recovery(
                        device, self.authority, sleep=lambda _: None).plan()
                self.assertEqual([], device.history)

    def test_local_active_replacement_fails_before_delete(self):
        self.active_path.write_bytes(b"replacement\n")
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "active mutation journal"):
            self.session().execute()
        self.assertEqual([], self.device.history)

    def test_fixed_nomad_rejects_every_other_staging_path_before_transport(self):
        instance = recovery.FixedNomad.__new__(recovery.FixedNomad)
        with self.assertRaisesRegex(recovery.RecoveryError, "sole staging"):
            instance.remove_staging_member(recovery.STAGING_MARK)

    def test_crash_after_retire_rename_is_admitted_and_resumed(self):
        device = FakeDevice()
        original_retire = recovery._retire_active
        def retire_then_crash(value):
            original_retire(value)
            raise recovery.RecoveryError("simulated crash after retirement")
        with mock.patch.object(recovery, "_retire_active", retire_then_crash):
            with self.assertRaisesRegex(recovery.RecoveryError,
                                        "crash after retirement"):
                recovery.Recovery(
                    device, self.authority, sleep=lambda _: None).execute()
        self.assertFalse(self.active_path.exists())
        self.assertTrue(self.authority.retired_path.exists())
        raw, journal_file, active = recovery._read_bound_journal(
            self.active_path, self.authority.retired_path,
            self.authority.recovery_path)
        self.assertFalse(active)
        self.assertEqual(recovery.ACTIVE_JOURNAL_SHA256,
                         recovery._sha(raw))
        resumed = replace(self.authority, active_journal=journal_file)
        evidence = recovery.Recovery(
            device, resumed, sleep=lambda _: None).execute()
        self.assertEqual("RECOVERED_CLEANLY", evidence["result"])

    def test_retirement_never_overwrites_preexisting_destination(self):
        self.authority.retired_path.write_bytes(b"foreign\n")
        with self.assertRaisesRegex(recovery.RecoveryError,
                                    "retirement state is ambiguous"):
            self.session().execute()
        self.assertEqual(b"foreign\n", self.authority.retired_path.read_bytes())
        self.assertTrue(self.active_path.exists())

    def test_loads_exact_real_failed_authorities_read_only(self):
        root = Path(__file__).resolve().parent
        authority = recovery.load_authority(
            root, root / recovery.REPORT_RELATIVE,
            root / recovery.ACTIVE_RELATIVE)
        self.assertEqual(recovery.REPORT_SHA256, authority.report.sha256)
        self.assertEqual(recovery.ACTIVE_JOURNAL_SHA256,
                         authority.active_journal.sha256)


if __name__ == "__main__":
    unittest.main()
