"""Synthetic-only tests: consistency is never hardware or Frida admission."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import unittest

import native_page_display0_observation as observation
import native_page_graph_v2_runner as graph
from test_native_page_display0_admission import (
    BOOT, MARK, PATH, PDF, PID, URI, capture as admission_capture,
    file_read, proc, selection,
)
from test_native_page_display0_stock_dialect import activities, windows, TASK_ID


def evidence(*, mark: bool = False, graph_raw: bytes | None = None):
    source = admission_capture(mark=mark)
    return observation.ObservationCapture(
        activities(), windows(), activities(), windows(),
        source.process, source.process,
        source.pdf, source.pdf,
        source.mark, source.mark,
        source.uri_resolution_raw, source.uri_resolution_raw,
        graph_raw,
    )


def candidate(*, mark: bool = False) -> dict:
    return {
        "event": "native_page_graph_snapshot",
        "schemaVersion": 2,
        "authority": graph.SNAPSHOT_AUTHORITY,
        "manifestSha256": "0" * 64,
        "observationOnly": True,
        "atomic": False,
        "attachment": {
            "packageName": "com.supernote.document",
            "processName": "com.supernote.document",
            "pid": PID,
            "processStartTimeTicks": "54321",
        },
        "externalSession": {"displayId": 0, "taskId": TASK_ID,
                            "authorizedSerial": graph.AUTHORIZED_SERIAL},
        "fileAuthority": {}, "coordinator": {}, "calibrationProfile": {},
        "lifecycle": {"resumed": True, "finished": False,
                      "destroyed": False, "graphStable": True},
        "document": {"uri": URI},
        "pageInfo": {},
        "presenter": {"uri": URI,
                      "markPath": PATH + ".mark" if mark else None},
        "views": {}, "layers": {},
    }


class DisplayZeroObservationTests(unittest.TestCase):
    def reject(self, *, selected=None, observed=None):
        with self.assertRaises(observation.ObservationError):
            observation.validate_observation(selected or selection(),
                                             observed or evidence())

    def test_consistent_supplied_capture_is_explicitly_non_admitting(self):
        result = observation.validate_observation(selection(), evidence())
        value = result.value()
        self.assertEqual(result.sha256, hashlib.sha256(result.raw).hexdigest())
        self.assertEqual(value["authority"], observation.AUTHORITY)
        self.assertEqual((value["bootId"], value["pid"],
                          value["processStartTimeTicks"]), (BOOT, PID, "54321"))
        self.assertEqual(value["documentUri"], URI)
        self.assertEqual(value["originalPdf"]["sha256"], hashlib.sha256(PDF).hexdigest())
        self.assertEqual(value["candidateGraph"]["status"], "absent")
        self.assertTrue(value["prePostSuppliedEvidenceConsistent"])
        for name in ("rawCaptureProvenanceVerified", "processStartTimeIndependentlyVerified",
                     "fileReadProvenanceVerified", "uriResolutionIndependentlyVerified",
                     "markAbsenceIndependentlyVerified", "stockGraphContractVerified",
                     "graphSnapshotVerified",
                     "documentIdentityVerified", "hardwareAdmission",
                     "mutationCommandsAuthorized"):
            self.assertFalse(value[name], name)

    def test_present_mark_is_stable_but_still_not_an_authority(self):
        result = observation.validate_observation(selection(mark=True), evidence(mark=True))
        value = result.value()
        self.assertTrue(value["mark"]["present"])
        self.assertEqual(value["mark"]["sha256"], hashlib.sha256(MARK).hexdigest())
        self.assertFalse(value["documentIdentityVerified"])

    def test_matching_graph_identity_is_shape_only(self):
        raw = graph.canonical_bytes(candidate())
        value = observation.validate_observation(
            selection(), evidence(graph_raw=raw)).value()
        self.assertEqual(value["candidateGraph"],
                         {"status": "identity-shape-only-untrusted",
                          "sha256": hashlib.sha256(raw).hexdigest()})
        self.assertFalse(value["graphSnapshotVerified"])
        self.assertFalse(value["hardwareAdmission"])

    def test_absent_mark_may_still_have_a_presenter_save_path(self):
        possible = candidate()
        possible["presenter"]["markPath"] = PATH + ".mark"
        value = observation.validate_observation(
            selection(), evidence(graph_raw=graph.canonical_bytes(possible))).value()
        self.assertFalse(value["mark"]["present"])
        self.assertFalse(value["markAbsenceIndependentlyVerified"])
        self.assertFalse(value["hardwareAdmission"])

    def test_present_mark_requires_its_exact_presenter_path(self):
        graph_value = candidate(mark=True)
        value = observation.validate_observation(
            selection(mark=True), evidence(mark=True,
                graph_raw=graph.canonical_bytes(graph_value))).value()
        self.assertTrue(value["mark"]["present"])
        graph_value["presenter"]["markPath"] = None
        self.reject(selected=selection(mark=True), observed=evidence(
            mark=True, graph_raw=graph.canonical_bytes(graph_value)))

    def test_process_replacement_and_boot_change_rejected(self):
        base = evidence()
        for changed in (proc(pid=PID + 1), proc(start="54322"),
                        replace(proc(), boot_id="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
                        replace(proc(), cmdline_bytes=b"other\x00")):
            with self.subTest(changed=changed):
                self.reject(observed=replace(base, after_process=changed))

    def test_task_window_focus_change_rejected(self):
        base = evidence()
        self.reject(observed=replace(base, after_activity_raw=activities().replace(
            b"66d8263", b"deadbeef")))
        self.reject(observed=replace(base, after_window_raw=windows().replace(
            b"39e379f", b"deadbeef")))

    def test_file_replacement_or_wrong_document_rejected(self):
        base = evidence()
        self.reject(observed=replace(base, after_pdf=file_read("pdf", PDF + b"x")))
        self.reject(observed=replace(base, after_pdf=file_read("pdf", PDF,
                                                               path=PATH + ".other")))
        replaced_inode = dict(graph.load_canonical(base.before_pdf.stat_before, 2048).value,
                              inode="another-inode")
        self.reject(observed=replace(base, after_pdf=file_read(
            "pdf", PDF, stat_before=graph.canonical_bytes(replaced_inode),
            stat_after=graph.canonical_bytes(replaced_inode))))

    def test_mark_presence_or_absence_switch_rejected(self):
        base = evidence()
        self.reject(observed=replace(base, after_mark=file_read("mark", MARK)))
        self.reject(observed=replace(base, after_mark=file_read(
            "mark", None, absence_proof=b"")))

    def test_resolution_and_descriptor_alias_rejected(self):
        base = evidence()
        wrong_uri = graph.canonical_bytes({
            "authority": "rtl-reader-file-uri-resolution-v1",
            "documentUri": URI, "resolvedPath": PATH + ".other",
            "evidenceSha256": "1" * 64})
        self.reject(observed=replace(base, after_uri_resolution_raw=wrong_uri))
        self.reject(observed=replace(base, after_mark=replace(
            base.after_mark, identity=base.after_pdf.identity)))

    def test_candidate_cross_document_and_stale_process_rejected(self):
        base = candidate()
        for mutate in (
            lambda value: value["document"].update(uri=URI + ".other"),
            lambda value: value["presenter"].update(uri=URI + ".other"),
            lambda value: value["attachment"].update(pid=PID + 1),
            lambda value: value["attachment"].update(processStartTimeTicks="54322"),
            lambda value: value["externalSession"].update(displayId=7),
            lambda value: value["externalSession"].update(taskId=TASK_ID + 1),
            lambda value: value["presenter"].update(markPath=PATH + ".other.mark"),
            lambda value: value["attachment"].update(processName="Document"),
            lambda value: value["lifecycle"].update(resumed=False),
        ):
            value = candidate()
            mutate(value)
            with self.subTest(value=value):
                self.reject(observed=evidence(graph_raw=graph.canonical_bytes(value)))

    def test_candidate_malformed_canonical_and_unknown_top_level_rejected(self):
        self.reject(observed=evidence(graph_raw=b'{"event":"x","event":"x"}'))
        changed = candidate()
        changed["unknown"] = "x"
        self.reject(observed=evidence(graph_raw=graph.canonical_bytes(changed)))
        for malformed in ([], {}):
            with self.subTest(mark_path=malformed):
                changed = candidate()
                changed["presenter"]["markPath"] = malformed
                self.reject(observed=evidence(
                    graph_raw=graph.canonical_bytes(changed)))
        self.reject(observed=evidence(graph_raw="not bytes"))

    def test_foreign_input_types_rejected(self):
        self.reject(observed={"raw": b"x"})
        self.reject(observed=replace(evidence(), before_process={"pid": PID}))
        self.reject(selected=replace(selection(), document_uri=URI + ".other"))


if __name__ == "__main__":
    unittest.main()
