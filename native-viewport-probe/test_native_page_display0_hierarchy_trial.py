"""Host-only parser, source-pinning and offline-build checks."""
from __future__ import annotations

import copy
import hashlib
import unittest

import native_page_display0_hierarchy_trial as subject
import native_page_graph_v2_runner as canonical


MANIFEST_SHA = "a" * 64
CLASSES = [
    "com.supernote.document.utils.view.DocumentImageView",
    "com.supernote.document.utils.view.DigestImageView",
    "com.supernote.document.handwrite.HandWriteView",
    "android.widget.RelativeLayout",
    "android.widget.RelativeLayout",
    "android.widget.FrameLayout",
]


def record() -> dict:
    return {
        "event": "native_page_hierarchy", "schemaVersion": 1,
        "authority": subject.RECORD_AUTHORITY, "manifestSha256": MANIFEST_SHA,
        "observationOnly": True, "hardwareAdmission": False,
        "uiThreadSamples": True, "heapWalks": 1,
        "retainedRootSamples": 2, "hierarchyStable": True,
        "rootClass": "android.widget.FrameLayout", "rootId": 10,
        "rootBounds": [0, 0, 1872, 1404], "childCount": len(CLASSES),
        "children": [
            {"index": i, "id": 1000 + i, "className": name,
             "bounds": [0, 0, 1872, 1404], "visibility": 0,
             "z": "0x0000000000000000", "parentIsRoot": True}
            for i, name in enumerate(CLASSES)
        ],
        "fieldIndex": {"pdf": 0, "digest": 1, "pen": 2},
        "customDrawingOrder": False, "effectiveCompositingAdmitted": False,
        "uriMatchedExpected": True, "lifecycleStable": True,
    }


def frames(value: dict) -> tuple[bytes, bytes]:
    return (canonical.canonical_bytes(value, subject.MAX_FRAME),
            canonical.canonical_bytes(
                {"event": "native_page_hierarchy_complete", "success": True},
                subject.MAX_FRAME))


class HierarchyTrialTests(unittest.TestCase):
    def test_source_pin_and_offline_bundle(self) -> None:
        self.assertEqual(hashlib.sha256(subject._source()).hexdigest(),
                         subject.SOURCE_SHA256)
        self.assertEqual(hashlib.sha256(subject.build_bundle()).hexdigest(),
                         subject.BUNDLE_SHA256)

    def test_accepts_diagnostic_only(self) -> None:
        value = record()
        self.assertEqual(subject.parse_frames(frames(value), MANIFEST_SHA), value)

    def test_accepts_zero_size_nonvisible_child_only(self) -> None:
        for visibility in (4, 8):
            with self.subTest(visibility=visibility):
                value = record()
                value["children"][5]["visibility"] = visibility
                value["children"][5]["bounds"] = [0, 0, 0, 0]
                self.assertEqual(subject.parse_frames(frames(value), MANIFEST_SHA),
                                 value)
                value["children"][5]["bounds"] = [0, 0, -1, 0]
                with self.assertRaises(subject.HierarchyError):
                    subject.parse_frames(frames(value), MANIFEST_SHA)

    def test_rejects_mutated_authority(self) -> None:
        for mutate in (
            lambda v: v.update(authority="untrusted"),
            lambda v: v.update(manifestSha256="b" * 64),
            lambda v: v.update(hardwareAdmission=True),
            lambda v: v.update(effectiveCompositingAdmitted=True),
            lambda v: v.update(uiThreadSamples=False),
            lambda v: v.update(childCount=32),
            lambda v: v.update(retainedRootSamples=True),
            lambda v: v["children"][0].update(index=True),
            lambda v: v["children"][1].update(parentIsRoot=False),
            lambda v: v["children"][2].update(z="0x7ff0000000000000"),
            lambda v: v["children"][2].update(bounds=[0, 0, 0, 0]),
            lambda v: v["fieldIndex"].update(pen=1),
            lambda v: v["children"][1].update(className="android.view.View"),
            lambda v: v.update(unknown="extra"),
        ):
            with self.subTest(mutate=mutate):
                value = copy.deepcopy(record())
                mutate(value)
                with self.assertRaises(subject.HierarchyError):
                    subject.parse_frames(frames(value), MANIFEST_SHA)

    def test_error_record_is_not_success(self) -> None:
        error = {"event": "native_page_hierarchy_error", "schemaVersion": 1,
                 "code": "HIERARCHY_REJECTED", "phase": "HIERARCHY",
                 "reason": "MISMATCH"}
        raw = (canonical.canonical_bytes(error, subject.MAX_FRAME),
               canonical.canonical_bytes(
                   {"event": "native_page_hierarchy_complete", "success": False},
                   subject.MAX_FRAME))
        self.assertEqual(subject.parse_error_frames(raw),
                         ("HIERARCHY", "MISMATCH"))
        with self.assertRaises(subject.HierarchyError):
            subject.parse_frames(raw, MANIFEST_SHA)


if __name__ == "__main__":
    unittest.main()
