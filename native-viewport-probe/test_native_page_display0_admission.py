"""Offline adversarial checks for display-0 phase-0 admission only."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import unittest

import native_page_display0_admission as d0
from native_page_authority_provider import FileRead, ProcessRead
from native_page_cleanup_ledger import ResourceIdentity
import native_page_graph_v2_runner as graph
from test_native_page_android_authority import wire as activity_wire


PID = 10104
BOOT = "12345678-1234-1234-1234-123456789abc"
PDF = b"%PDF-1.4\nphase-zero-disposable\n"
MARK = b"separate-test-mark"
URI = "file:///storage/emulated/0/Document/display0_disposable.pdf"
PATH = URI[7:]
REGULAR_STAT = {
    "device": "1", "inode": "101", "mode": str(0o100644),
    "uid": 1000, "gid": 1000, "mtimeNs": "123", "ctimeNs": "456",
}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def selection(*, mark: bool = False) -> d0.DisposableSelection:
    return d0.DisposableSelection(
        d0.SELECTION_AUTHORITY, 1, "display0-session-0001", d0.AUTHORIZED_SERIAL,
        URI, PATH, len(PDF), sha(PDF), len(MARK) if mark else None,
        sha(MARK) if mark else None, True,
    )


def proc(*, pid: int = PID, start: str = "54321") -> ProcessRead:
    fields = ["1"] * 19
    fields[18] = start
    return ProcessRead(
        (str(pid) + " (document) R " + " ".join(fields) + "\n").encode("ascii"),
        b"com.supernote.document\x00", BOOT,
    )


def file_read(role: str, contents: bytes | None, *, path: str | None = None,
              identity: ResourceIdentity | None = None,
              stat_before: bytes | None = None,
              stat_after: bytes | None = None,
              absence_proof: bytes | None = None) -> FileRead:
    selected_path = path if path is not None else PATH + (".mark" if role == "mark" else "")
    selected_identity = identity or ResourceIdentity(
        "file", d0.AUTHORIZED_SERIAL, "file:" + role, "inode-" + role)
    if contents is None:
        return FileRead(selected_path, selected_identity, False, None, None, None,
                        absence_proof if absence_proof is not None else b"retained-absence")
    stat_raw = graph.canonical_bytes(REGULAR_STAT)
    return FileRead(selected_path, selected_identity, True, contents,
                    stat_raw if stat_before is None else stat_before,
                    stat_raw if stat_after is None else stat_after,
                    absence_proof)


def capture(*, mark: bool = False) -> d0.PreAttachCapture:
    resolution = graph.canonical_bytes({
        "authority": "rtl-reader-file-uri-resolution-v1",
        "documentUri": URI, "resolvedPath": PATH,
        "evidenceSha256": sha(b"independent-file-uri-resolution"),
    })
    return d0.PreAttachCapture(activity_wire(), proc(), file_read("pdf", PDF),
                               file_read("mark", MARK if mark else None), resolution)


class DisplayZeroAdmissionTests(unittest.TestCase):
    def reject(self, selected=None, evidence=None):
        with self.assertRaises(d0.AdmissionError):
            d0.validate_pre_attach(selected or selection(), evidence or capture())

    def test_one_existing_visible_display_zero_activity_yields_preparatory_record(self):
        result = d0.validate_pre_attach(selection(), capture())
        value = result.value()
        self.assertEqual(result.sha256, sha(result.raw))
        self.assertEqual(value["authority"], d0.ADMISSION_AUTHORITY)
        self.assertEqual((value["task"]["display_id"], value["task"]["pid"]), (0, PID))
        self.assertEqual(value["target"]["startTimeTicks"], "54321")
        self.assertEqual(value["task"]["task_token"], "66d8263")
        self.assertEqual(value["task"]["activity_token"], "11846f4")
        self.assertEqual(value["files"]["originalPdf"]["sha256"], sha(PDF))
        self.assertFalse(value["files"]["mark"]["present"])
        self.assertTrue(value["preAttachOnly"])
        for name in ("hardwareAdmission", "focusVerified",
                     "documentIdentityConfirmedByObserver",
                     "uriResolutionIndependentlyVerified", "filePathIdentityVerified",
                     "markAbsenceIndependentlyVerified", "mutationCommandsAuthorized"):
            self.assertFalse(value[name])
        self.assertEqual(value["disposableStatus"], "caller-attested-only")

    def test_present_mark_is_exactly_selected_and_captured(self):
        value = d0.validate_pre_attach(selection(mark=True), capture(mark=True)).value()
        self.assertEqual(value["files"]["mark"]["sha256"], sha(MARK))
        self.assertEqual(value["files"]["mark"]["path"], PATH + ".mark")

    def test_selection_requires_exact_version_serial_session_and_disposable_attestation(self):
        base = selection()
        for changed in (
            replace(base, authority="other"), replace(base, schema_version=True),
            replace(base, authorized_serial="another-device"),
            replace(base, observation_session_id="short"),
            replace(base, disposable_attested=False),
        ):
            with self.subTest(changed=changed):
                self.reject(selected=changed)

    def test_selection_rejects_broad_or_mismatched_uri_and_path(self):
        base = selection()
        for changed in (
            replace(base, document_uri="file:///storage/emulated/0/Document/../secret.pdf"),
            replace(base, document_uri="content://provider/document"),
            replace(base, document_uri="file:///storage/emulated/0/Document/a.pdf?x=1"),
            replace(base, pdf_path="/storage/emulated/0/Document/another.pdf"),
            replace(base, pdf_size=True), replace(base, pdf_sha256="A" * 64),
            replace(base, mark_size=1),
        ):
            with self.subTest(changed=changed):
                self.reject(selected=changed)

    def test_activity_must_be_one_live_visible_stock_task_on_display_zero(self):
        base = capture()
        for raw in (
            activity_wire(resumed=False, state="PAUSED"),
            activity_wire(visible="false"),
            activity_wire(finishing="true"),
            activity_wire(duplicate=True),
            activity_wire(display_id=7),
            activity_wire(pid=PID + 1),
        ):
            with self.subTest(raw=raw[:90]):
                self.reject(evidence=replace(base, activity_raw=raw))

    def test_process_raw_pid_starttime_cmdline_and_boot_are_validated(self):
        base = capture()
        for changed in (
            replace(proc(), stat_bytes=proc(pid=PID + 1).stat_bytes),
            replace(proc(), stat_bytes=proc(start="0").stat_bytes),
            replace(proc(), stat_bytes=proc().stat_bytes[:-1]),
            replace(proc(), stat_bytes=proc().stat_bytes.replace(b"(document)", b"(doc\x00ument)")),
            replace(proc(), cmdline_bytes=b"com.supernote.document.extra\x00"),
            replace(proc(), boot_id="not-a-boot-id"),
        ):
            with self.subTest(changed=changed):
                self.reject(evidence=replace(base, process=changed))

    def test_pdf_bytes_path_and_descriptor_namespace_must_match_selection(self):
        base = capture()
        foreign_identity = ResourceIdentity("file", "other-serial", "file:pdf", "inode-pdf")
        for changed in (
            file_read("pdf", PDF + b"changed"),
            file_read("pdf", PDF, path=PATH + ".other"),
            file_read("pdf", PDF, identity=foreign_identity),
            file_read("pdf", None),
        ):
            with self.subTest(changed=changed.path):
                self.reject(evidence=replace(base, pdf=changed))

    def test_pdf_fstat_must_be_canonical_regular_and_stable(self):
        base = capture()
        changed_stat = dict(REGULAR_STAT, inode="102")
        directory_stat = dict(REGULAR_STAT, mode=str(0o40755))
        for changed in (
            file_read("pdf", PDF, stat_after=graph.canonical_bytes(changed_stat)),
            file_read("pdf", PDF, stat_before=graph.canonical_bytes(directory_stat)),
            file_read("pdf", PDF, stat_before=b'{"uid":1000,"uid":1000}'),
        ):
            with self.subTest(changed=changed.stat_before):
                self.reject(evidence=replace(base, pdf=changed))

    def test_mark_absence_requires_proof_and_present_mark_requires_exact_selection(self):
        base = capture()
        self.reject(evidence=replace(base, mark=file_read("mark", None, absence_proof=b"")))
        self.reject(evidence=replace(base, mark=file_read("mark", MARK)))
        self.reject(selected=selection(mark=True), evidence=base)
        self.reject(selected=replace(selection(mark=True), mark_sha256=sha(b"wrong")),
                    evidence=capture(mark=True))

    def test_pdf_and_mark_descriptor_slots_cannot_alias(self):
        base = capture()
        alias = file_read("mark", None, identity=base.pdf.identity)
        self.reject(evidence=replace(base, mark=alias))

    def test_uri_resolution_must_be_canonical_and_match_exact_selected_file(self):
        base = capture()
        wrong = graph.canonical_bytes({"authority": "rtl-reader-file-uri-resolution-v1",
                                       "documentUri": URI, "resolvedPath": PATH + ".other",
                                       "evidenceSha256": sha(b"independent-file-uri-resolution")})
        for raw in (wrong, b'{"authority":"x","authority":"x"}', b"", b"{}"):
            with self.subTest(raw=raw):
                self.reject(evidence=replace(base, uri_resolution_raw=raw))

    def test_formally_valid_but_unverified_claims_never_grant_hardware_admission(self):
        base = capture()
        fabricated_resolution = graph.canonical_bytes({
            "authority": "rtl-reader-file-uri-resolution-v1",
            "documentUri": URI, "resolvedPath": PATH,
            "evidenceSha256": sha(b"fabricated-claim"),
        })
        fabricated_absence = file_read("mark", None, absence_proof=b"fabricated-absence")
        value = d0.validate_pre_attach(selection(), replace(
            base, uri_resolution_raw=fabricated_resolution,
            mark=fabricated_absence,
        )).value()
        for name in ("hardwareAdmission", "uriResolutionIndependentlyVerified",
                     "filePathIdentityVerified", "markAbsenceIndependentlyVerified"):
            self.assertFalse(value[name])

    def test_exact_capture_types_fail_closed(self):
        base = capture()
        self.reject(evidence=replace(base, activity_raw="not bytes"))
        self.reject(evidence=replace(base, process={"pid": PID}))
        self.reject(evidence=replace(base, pdf={"path": PATH}))
        self.reject(evidence=replace(base, mark={"present": False}))


if __name__ == "__main__":
    unittest.main()
