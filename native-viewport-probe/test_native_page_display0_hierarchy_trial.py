"""Host-only parser, source-pinning and offline-build checks."""
from __future__ import annotations

import copy
from contextlib import redirect_stderr
import hashlib
from io import StringIO
import base64
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

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


def child_wire() -> bytes:
    return canonical.canonical_bytes({
        "authority": subject.MANIFEST_AUTHORITY,
        "attachment": {
            "pid": 1234,
            "observerSha256": subject.SOURCE_SHA256,
            "firmwareFingerprint": subject.identity.FINGERPRINT,
        },
        "expected": {"documentUri": subject.identity.URI, "markPath": None},
    }, 4096)


def pinned_frida():
    sys.path.insert(0, str(subject.identity.FRIDA_SITE))
    import frida  # type: ignore[import-not-found]
    return frida


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

    def test_exact_pinned_attach_errors_are_fixed_codes(self) -> None:
        frida = pinned_frida()
        self.assertEqual(len(subject.ATTACH_ERROR_TYPES),
                         len({name for name, _ in subject.ATTACH_ERROR_TYPES}))
        for class_name, reason in subject.ATTACH_ERROR_TYPES:
            with self.subTest(class_name=class_name):
                exception_type = getattr(frida, class_name)
                error = exception_type("pid=1234 C:\\private\\file.pdf secret")
                code = "HIERARCHY_CHILD_ATTACH_" + reason
                self.assertEqual(subject._attach_error_code(error, frida), code)
                self.assertIn(code, subject.CHILD_CODES)
                self.assertNotIn("private", code)

    def test_attach_unknown_and_subclass_are_generic(self) -> None:
        frida = pinned_frida()
        self.assertEqual(subject._attach_error_code(
            RuntimeError("pid=1234 C:\\private\\file.pdf"), frida),
            "HIERARCHY_CHILD_ATTACH_FAILED")
        subclass = type("Subclass", (frida.ProcessNotFoundError,), {})
        self.assertEqual(subject._attach_error_code(
            subclass("pid=1234 C:\\private\\file.pdf"), frida),
            "HIERARCHY_CHILD_ATTACH_FAILED")

    def test_child_attach_failure_has_one_attempt_and_redacted_stderr(self) -> None:
        frida = pinned_frida()
        wire = child_wire()
        device = Mock()
        device.attach.side_effect = frida.ProcessNotFoundError(
            "pid=1234 C:\\private\\file.pdf secret")
        manager = SimpleNamespace(add_remote_device=lambda _: device)
        stderr = StringIO()
        with (patch.object(subject, "load_bundle", return_value=b"unused"),
              patch.object(frida, "get_device_manager", return_value=manager),
              redirect_stderr(stderr)):
            result = subject.main([
                "__child", "1234", base64.urlsafe_b64encode(wire).decode("ascii")])
        self.assertEqual(result, 2)
        self.assertEqual(stderr.getvalue(),
                         "HIERARCHY_CHILD_ATTACH_PROCESS_NOT_FOUND\n")
        device.attach.assert_called_once_with(1234)
        device.create_script.assert_not_called()

    def test_parent_accepts_only_allowlisted_child_diagnostic(self) -> None:
        backend = subject.Backend()
        wire = child_wire()
        with patch.object(subject.subprocess, "run", return_value=
                          subprocess.CompletedProcess([], 2, b"",
                              b"HIERARCHY_CHILD_ATTACH_PERMISSION_DENIED\n")):
            with self.assertRaisesRegex(subject.HierarchyError,
                                        "^HIERARCHY_CHILD_ATTACH_PERMISSION_DENIED$"):
                backend.child_hierarchy(1234, wire)
        with patch.object(subject.subprocess, "run", return_value=
                          subprocess.CompletedProcess([], 2, b"",
                              b"Permission denied: C:\\private\\file.pdf\n")):
            with self.assertRaisesRegex(subject.HierarchyError,
                                        "^HIERARCHY_CHILD_FAILED$"):
                backend.child_hierarchy(1234, wire)

    def test_detach_uncertainty_still_dominates_body_failure(self) -> None:
        frida = pinned_frida()
        script = Mock()
        script.load.side_effect = RuntimeError("secret load failure")
        session = Mock()
        session.create_script.return_value = script
        session.detach.side_effect = RuntimeError("secret detach failure")
        device = Mock()
        device.attach.return_value = session
        manager = SimpleNamespace(add_remote_device=lambda _: device)
        with (patch.object(subject, "load_bundle", return_value=b"unused"),
              patch.object(frida, "get_device_manager", return_value=manager)):
            with self.assertRaisesRegex(subject.HierarchyError,
                                        "^HIERARCHY_CHILD_DETACH_FAILED$"):
                subject.child(1234, child_wire())
        device.attach.assert_called_once_with(1234)
        script.unload.assert_called_once_with()
        session.detach.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
