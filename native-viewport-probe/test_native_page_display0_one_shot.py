"""Synthetic-only tests of the separately versioned stock one-shot host seam."""
from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import unittest

import native_page_display0_one_shot as one
import native_page_graph_v2_runner as graph
from test_native_page_display0_admission import (
    MARK, PDF, file_read, proc, selection as old_selection,
)
from test_native_page_display0_stock_dialect import activities, windows


SOURCE = Path(__file__).with_name("native_page_display0_identity_observer.js").read_bytes()
PATH = one.DISPOSABLE_URI[7:]


def selection(*, mark: bool = False):
    return replace(old_selection(mark=mark), document_uri=one.DISPOSABLE_URI,
                   pdf_path=PATH)


def half(*, mark: bool = False, process=None, activity=None, window=None,
         pdf=None, mark_file=None, resolution=None):
    selected = selection(mark=mark)
    return one.CaptureHalf(
        activities() if activity is None else activity,
        windows() if window is None else window,
        proc() if process is None else process,
        file_read("pdf", PDF, path=PATH) if pdf is None else pdf,
        file_read("mark", MARK if mark else None, path=PATH + ".mark")
        if mark_file is None else mark_file,
        graph.canonical_bytes({
            "authority": "rtl-reader-file-uri-resolution-v1",
            "documentUri": selected.document_uri,
            "resolvedPath": selected.pdf_path,
            "evidenceSha256": hashlib.sha256(b"synthetic-uri-claim").hexdigest(),
        }) if resolution is None else resolution,
    )


def identity(manifest_sha: str, *, mark: bool = False) -> bytes:
    return graph.canonical_bytes({
        "event": "native_page_display0_identity", "schemaVersion": 1,
        "authority": one.RECORD_AUTHORITY,
        "manifestSha256": manifest_sha,
        "observationOnly": True, "hardwareAdmission": False,
        "hostAssertionsOnly": True, "runtimePidMatched": True,
        "heapWalks": 1, "retainedRootSamples": 2,
        "lifecycle": {"resumed": True, "finished": False, "destroyed": False},
        "uriAgreementAndExpectedMatch": True,
        "markPathPresent": mark,
        "markPathMatchedExpected": True if mark else None,
    })


COMPLETE = graph.canonical_bytes({
    "event": "native_page_display0_identity_complete", "success": True,
})


class FakeClock:
    def __init__(self):
        self.now = 1_000_000_000

    def clock(self):
        return self.now

    def pause(self, seconds):
        self.now += max(1, round(seconds * 1_000_000_000))


class FakeWorker:
    """A claim source, never a live ADB/Frida authority."""
    def __init__(self, *, before=None, after=None, mark=False, pre_wait=0,
                 final_wait=0, frames=None, trace=one.TRACE, joined=True,
                 throw=None):
        self.before = half(mark=mark) if before is None else before
        self.after = half(mark=mark) if after is None else after
        self.pre_wait = pre_wait
        self.final_wait = final_wait
        self.frames = frames
        self.trace = trace
        self.joined = joined
        self.throw = throw
        self.calls = []
        self.manifest = None
        self._pre_count = 0
        self._final_count = 0

    def launch(self, selected):
        self.calls.append("launch")
        if self.throw == "launch":
            raise RuntimeError("private path: " + PATH)

    def poll_before(self):
        self.calls.append("poll_before")
        self._pre_count += 1
        return self.before if self._pre_count > self.pre_wait else None

    def submit(self, manifest_raw, observer_source):
        self.calls.append("submit")
        self.manifest = graph.load_canonical(manifest_raw, 4096).value
        assert hashlib.sha256(observer_source).hexdigest() == one.OBSERVER_SHA256
        if self.throw == "submit":
            raise RuntimeError("private path: " + PATH)

    def poll_final(self):
        self.calls.append("poll_final")
        self._final_count += 1
        if self._final_count <= self.final_wait:
            return None
        frames = self.frames
        if frames is None:
            frames = (identity(hashlib.sha256(graph.canonical_bytes(
                self.manifest)).hexdigest(),
                mark=self.manifest["expected"]["markPath"] is not None), COMPLETE)
        return one.FinalEvidence(self.after, frames, self.trace)

    def terminate(self):
        self.calls.append("terminate")
        if self.throw == "terminate":
            raise RuntimeError("private path: " + PATH)

    def join(self, timeout_ns):
        self.calls.append("join")
        assert type(timeout_ns) is int and timeout_ns >= 0
        return self.joined


class OneShotTests(unittest.TestCase):
    def run_fake(self, worker=None, *, mark=False, source=SOURCE, clock=None):
        clock = clock or FakeClock()
        worker = worker or FakeWorker(mark=mark)
        return one.run_one_shot(selection(mark=mark), source, worker,
                                clock_ns=clock.clock, pause=clock.pause)

    def rejected(self, worker, *, mark=False, clock=None):
        with self.assertRaises(one.OneShotError) as caught:
            self.run_fake(worker, mark=mark, clock=clock)
        self.assertEqual(str(caught.exception), "stock observation rejected")
        self.assertNotIn(PATH, str(caught.exception))
        self.assertIn("terminate", worker.calls)
        self.assertIn("join", worker.calls)

    def test_success_is_one_shot_and_never_hardware_admission(self):
        worker = FakeWorker(pre_wait=2, final_wait=3)
        result = self.run_fake(worker)
        self.assertEqual(result.sha256, hashlib.sha256(result.raw).hexdigest())
        value = result.value()
        self.assertEqual(value["authority"], one.RUNNER_AUTHORITY)
        self.assertTrue(value["identityObserverReportedUriAgreement"])
        self.assertEqual(worker.calls.count("launch"), 1)
        self.assertEqual(worker.calls.count("submit"), 1)
        self.assertEqual(worker.calls.count("terminate"), 1)
        self.assertEqual(worker.calls.count("join"), 1)
        self.assertEqual(worker.manifest["coordinator"], {
            "abortOnAnyError": True, "detachOnDeadline": True,
            "hardDeadlineMs": 1000, "maxJavaChooseWalks": 1, "noRetry": True,
            "retainedRootSamples": 2,
        })
        self.assertEqual(worker.manifest["expected"], {
            "documentUri": one.DISPOSABLE_URI, "markPath": None})
        self.assertEqual(value["transportTraceClaimed"], list(one.TRACE))
        for key in ("rawCaptureProvenanceVerified", "workerIsolationVerified",
                    "documentIdentityVerified", "hardwareAdmission",
                    "mutationCommandsAuthorized"):
            self.assertFalse(value[key], key)
        self.assertNotIn(PATH.encode(), result.raw)
        self.assertNotIn(one.DISPOSABLE_URI.encode(), result.raw)

    def test_present_mark_is_consistent_but_not_a_save_authority(self):
        worker = FakeWorker(mark=True)
        value = self.run_fake(worker, mark=True).value()
        self.assertEqual(worker.manifest["expected"]["markPath"], PATH + ".mark")
        self.assertFalse(value["documentIdentityVerified"])
        self.assertFalse(value["hardwareAdmission"])

    def test_missing_mark_can_still_have_presenter_future_save_path(self):
        worker = FakeWorker(frames=(graph.canonical_bytes({
            **graph.load_canonical(identity("0" * 64), 4096).value,
            "manifestSha256": "placeholder", "markPathPresent": True,
        }), COMPLETE))
        # Replace the placeholder only after submit, since the digest is
        # determined by the pre-capture.  A caller may not assert exact mark
        # absence from the Java presenter path alone.
        original = worker.poll_final
        def patched():
            if worker.manifest is not None:
                digest = hashlib.sha256(graph.canonical_bytes(worker.manifest)).hexdigest()
                item = graph.load_canonical(worker.frames[0], 4096).value
                worker.frames = (graph.canonical_bytes({**item, "manifestSha256": digest}),
                                 COMPLETE)
            return original()
        worker.poll_final = patched
        value = self.run_fake(worker).value()
        self.assertFalse(value["documentIdentityVerified"])

    def test_stale_process_file_or_focus_is_rejected(self):
        self.rejected(FakeWorker(after=half(process=proc(start="54322"))))
        self.rejected(FakeWorker(after=half(pdf=file_read("pdf", PDF + b"x", path=PATH))))
        self.rejected(FakeWorker(after=half(window=windows(window_token="deadbeef"))))
        self.rejected(FakeWorker(after=half(mark_file=file_read(
            "mark", MARK, path=PATH + ".mark"))))

    def test_manifest_or_frame_mismatch_is_rejected(self):
        self.rejected(FakeWorker(frames=(identity("0" * 64), COMPLETE)))
        self.rejected(FakeWorker(frames=(identity("0" * 64),)))
        self.rejected(FakeWorker(frames=(identity("0" * 64), COMPLETE, COMPLETE)))
        self.rejected(FakeWorker(frames=(b'{"event":"x","event":"x"}', COMPLETE)))
        self.rejected(FakeWorker(frames=(graph.canonical_bytes({
            "event": "native_page_display0_identity_error", "schemaVersion": 1,
            "code": "DISPLAY0_IDENTITY_REJECTED"}),
            graph.canonical_bytes({"event": "native_page_display0_identity_complete",
                                   "success": False}))))
        self.rejected(FakeWorker(trace=("attach", "load", "detach")))
        self.rejected(FakeWorker(trace=("attach", "load", "unload", "detach", "attach")))

    def test_json_integer_cannot_impersonate_true_in_nested_frames(self):
        digest = "0" * 64
        original = graph.load_canonical(identity(digest), 4096).value
        for field in ("resumed", "finished", "destroyed"):
            changed = {**original, "lifecycle": {
                **original["lifecycle"], field: 1 if field == "resumed" else 0}}
            with self.subTest(field=field), self.assertRaises(one.OneShotError):
                one.parse_identity_frames((graph.canonical_bytes(changed), COMPLETE),
                                          digest, mark_required=False)
        false_complete = graph.canonical_bytes({
            "event": "native_page_display0_identity_complete", "success": 1})
        with self.assertRaises(one.OneShotError):
            one.parse_identity_frames((identity(digest), false_complete), digest,
                                      mark_required=False)

    def test_deadline_or_uncertain_cleanup_fails_closed(self):
        self.rejected(FakeWorker(pre_wait=1000))
        self.rejected(FakeWorker(final_wait=1000))
        self.rejected(FakeWorker(joined=False))
        self.rejected(FakeWorker(throw="launch"))
        self.rejected(FakeWorker(throw="submit"))
        self.rejected(FakeWorker(throw="terminate"))

    def test_source_is_exact_and_live_path_remains_blocked(self):
        self.assertEqual(hashlib.sha256(SOURCE).hexdigest(), one.OBSERVER_SHA256)
        with self.assertRaises(one.OneShotError):
            self.run_fake(FakeWorker(), source=SOURCE + b" ")
        with self.assertRaises(one.LiveBackendUnavailable):
            one.run_live()


if __name__ == "__main__":
    unittest.main()
