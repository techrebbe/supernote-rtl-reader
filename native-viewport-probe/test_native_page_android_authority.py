from __future__ import annotations

from dataclasses import replace
import unittest

import native_page_android_authority as authority


PID = 10104


def wire(*, state: str = "RESUMED", stopped: str = "false",
         finishing: str = "false", visible: str = "true",
         task_visible: str = "true", now_visible: str = "true",
         delayed_resume: str = "false", reported_visible: str = "true",
         resumed: bool = True, pid: int = PID, task_id: int = 4538,
         display_id: int = 0, uid: int = authority.SYSTEM_UID,
         duplicate: bool = False) -> bytes:
    marker = ("    mResumedActivity: ActivityRecord{11846f4 u0 "
              "com.supernote.document/.document.DocumentActivity t4538}\n"
              if resumed else
              "    mLastPausedActivity: ActivityRecord{11846f4 u0 "
              "com.supernote.document/.document.DocumentActivity t4538}\n")
    block = f"""  Stack #4538: type=standard mode=fullscreen
{marker}    * Task{{66d8263 #{task_id} visible={task_visible} type=standard mode=fullscreen translucent=true A=1000:com.supernote.document U=0 StackId=4538 sz=1}}
      taskId={task_id} stackId=4538
      * Hist #0: ActivityRecord{{11846f4 u0 com.supernote.document/.document.DocumentActivity t{task_id}}}
          packageName=com.supernote.document processName=com.supernote.document
          app=ProcessRecord{{2083011 {pid}:com.supernote.document/{uid}}}
          mActivityComponent=com.supernote.document/.document.DocumentActivity
          baseDir=/system_ext/app/SupernoteDocument/SupernoteDocument.apk
          CurrentConfiguration={{1.0 en_US 300dpi port winConfig={{ mBounds=Rect(0, 0 - 1404, 1872) mAppBounds=Rect(0, 0 - 1404, 1872) mRotation=ROTATION_0}} s.186}}
          state={state} stopped={stopped} delayedResume={delayed_resume} finishing={finishing}
          mVisibleRequested={visible} mVisible={visible} mClientVisible={visible} reportedDrawn={visible} reportedVisible={reported_visible}
          nowVisible={now_visible} lastVisibleTime=-1s
"""
    if duplicate:
        block += block
    return ("ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n"
            f"Display #{display_id} (activities from top to bottom):\n" +
            block).encode("utf-8")


def multi_display_wire(
        *, foreign_resumed: bytes = b"    mResumedActivity: null\n") -> bytes:
    """Add one synthetic, non-target display before the live document display."""
    target_header = b"Display #3 (activities from top to bottom):\n"
    foreign_display = (
        b"Display #0 (activities from top to bottom):\n"
        b"  Stack #7: type=home mode=fullscreen\n" +
        foreign_resumed +
        b"    * Task{7654321 #7 visible=true type=home mode=fullscreen "
        b"A=1000:com.example.home U=0 StackId=7 sz=1}\n"
        b"      taskId=7 stackId=7\n"
        b"      * Hist #0: ActivityRecord{abcdef0 u0 "
        b"com.example.home/.HomeActivity t7}\n")
    return wire(display_id=3).replace(
        target_header,
        b"Display areas in focus order:\n" + foreign_display + target_header)


class ActivityAuthorityTests(unittest.TestCase):
    def test_live_document_is_admitted(self) -> None:
        value = authority.parse_document_task_authority(wire(), expected_pid=PID)
        self.assertEqual(value.authority, authority.AUTHORITY)
        self.assertEqual((value.task_id, value.display_id, value.pid), (4538, 0, PID))
        self.assertEqual((value.width, value.height, value.density_dpi, value.rotation),
                         (1404, 1872, 300, 0))
        self.assertTrue(value.resumed)
        self.assertEqual(value.canonical_bytes(), value.canonical_bytes())

    def test_background_document_is_evidence_but_not_live(self) -> None:
        raw = wire(state="STOPPED", stopped="true", visible="false",
                   task_visible="false", now_visible="false", resumed=False)
        with self.assertRaises(authority.AndroidAuthorityError):
            authority.parse_document_task_authority(raw, expected_pid=PID)
        value = authority.parse_document_task_authority(
            raw, expected_pid=PID, require_live=False)
        self.assertFalse(value.resumed)
        self.assertEqual(value.state, "STOPPED")

    def test_every_live_witness_is_required(self) -> None:
        cases = [
            {"state": "PAUSED"}, {"stopped": "true"},
            {"delayed_resume": "true"},
            {"finishing": "true"}, {"visible": "false"},
            {"reported_visible": "false"},
            {"task_visible": "false"}, {"now_visible": "false"},
            {"resumed": False},
        ]
        for values in cases:
            with self.subTest(values=values), self.assertRaises(
                    authority.AndroidAuthorityError):
                authority.parse_document_task_authority(
                    wire(**values), expected_pid=PID)

    def test_pid_task_stack_and_component_disagreement_fail(self) -> None:
        bad = [
            (wire(pid=PID + 1), PID),
            (wire(uid=authority.SYSTEM_UID + 1), PID),
            (wire().replace(b"A=1000:com.supernote.document",
                            b"A=2000:com.supernote.document"), PID),
            (wire().replace(b" U=0 ", b" U=10 "), PID),
            (wire(task_id=4539), PID),
            (wire().replace(b"StackId=4538", b"StackId=4539"), PID),
            (wire().replace(b"taskId=4538 stackId=4538",
                            b"taskId=9999 stackId=9999"), PID),
            (wire().replace(b"taskId=4538 stackId=4538",
                            b"taskId=4538 stackId=9999"), PID),
            (wire().replace(b"300dpi", b"-300dpi"), PID),
            (wire().replace(b"300dpi", b"0300dpi"), PID),
            (wire().replace(b" A=1000:com.supernote.document ",
                            b" A=2000:com.example.other A=1000:com.supernote.document "), PID),
            (wire().replace(b" U=0 ", b" U=10 U=0 "), PID),
            (wire().replace(b" StackId=4538 ",
                            b" StackId=9999 StackId=4538 "), PID),
            (wire().replace(b" visible=true type=", b" visible=false visible=true type="), PID),
            (wire().replace(b" U=0 ", b" U= U=0 "), PID),
            (wire().replace(b" visible=true type=", b" visible= visible=true type="), PID),
            (wire().replace(b" StackId=4538 ", b" StackId= StackId=4538 "), PID),
            (wire().replace(b" A=1000:com.supernote.document ",
                            b" A=bogus A=1000:com.supernote.document "), PID),
            (wire().replace(b"/.document.DocumentActivity", b"/.document.OtherActivity"), PID),
        ]
        for raw, expected in bad:
            with self.subTest(raw=raw[:80]), self.assertRaises(
                    authority.AndroidAuthorityError):
                authority.parse_document_task_authority(raw, expected_pid=expected,
                                                         require_live=False)

    def test_duplicate_target_fails(self) -> None:
        with self.assertRaises(authority.AndroidAuthorityError):
            authority.parse_document_task_authority(
                wire(duplicate=True), expected_pid=PID, require_live=False)

        second_history = wire().replace(
            b"      * Hist #0: ActivityRecord{11846f4 u0 "
            b"com.supernote.document/.document.DocumentActivity t4538}\n",
            b"      * Hist #0: ActivityRecord{11846f4 u0 "
            b"com.supernote.document/.document.DocumentActivity t4538}\n"
            b"      * Hist #1: ActivityRecord{22846f4 u0 "
            b"com.supernote.document/.document.DocumentActivity t4538}\n")
        with self.assertRaises(authority.AndroidAuthorityError):
            authority.parse_document_task_authority(
                second_history, expected_pid=PID, require_live=False)
        for malformed in (
                b"      * Hist #1: ActivityRecord{ABCDEF u0 "
                b"com.supernote.document/.document.DocumentActivity t4538}\n",
                b"      * Hist #1: ActivityRecord{abcdef u0 "
                b"com.supernote.document/.document.DocumentActivity tgarbage}\n",
        ):
            with self.subTest(malformed=malformed), self.assertRaises(
                    authority.AndroidAuthorityError):
                authority.parse_document_task_authority(
                    wire() + malformed, expected_pid=PID, require_live=False)

    def test_foreign_or_duplicate_resumed_marker_fails(self) -> None:
        target = (b"    mResumedActivity: ActivityRecord{11846f4 u0 "
                  b"com.supernote.document/.document.DocumentActivity t4538}\n")
        foreign = (b"    mResumedActivity: ActivityRecord{deadbee u0 "
                   b"com.example.other/.OtherActivity t9999}\n")
        for raw in (
                wire().replace(target, target + foreign),
                wire().replace(target, foreign + target),
                wire().replace(target, target + target),
                wire().replace(target,
                               b"    mResumedActivity: ActivityRecord{}\n" + target),
                wire().replace(
                    target,
                    b"    mResumedActivity: ActivityRecord{ABCDEF u0 "
                    b"com.supernote.document/.document.DocumentActivity t4538}\n"),
        ):
            with self.subTest(raw=raw[:120]), self.assertRaises(
                    authority.AndroidAuthorityError):
                authority.parse_document_task_authority(
                    raw, expected_pid=PID, require_live=False)

    def test_activity_fields_cannot_be_borrowed_from_foreign_history(self) -> None:
        target = (b"      * Hist #0: ActivityRecord{11846f4 u0 "
                  b"com.supernote.document/.document.DocumentActivity t4538}\n")
        foreign = (b"      * Hist #1: ActivityRecord{ffff u0 "
                   b"com.example.other/.OtherActivity t4538}\n")
        with self.assertRaises(authority.AndroidAuthorityError):
            authority.parse_document_task_authority(
                wire().replace(target, target + foreign),
                expected_pid=PID, require_live=False)

        task_detail = b"      taskId=4538 stackId=4538\n"
        with self.assertRaises(authority.AndroidAuthorityError):
            authority.parse_document_task_authority(
                wire().replace(task_detail, b"").replace(
                    target, target + task_detail),
                expected_pid=PID, require_live=False)

        resumed = (b"    mResumedActivity: ActivityRecord{11846f4 u0 "
                   b"com.supernote.document/.document.DocumentActivity t4538}\n")
        task_header = next(
            line + b"\n" for line in wire().splitlines()
            if line.startswith(b"    * Task{66d8263 #4538"))
        with self.assertRaises(authority.AndroidAuthorityError):
            authority.parse_document_task_authority(
                wire().replace(resumed, b"").replace(
                    task_header, task_header + resumed),
                expected_pid=PID, require_live=False)

    def test_duplicate_activity_or_configuration_authority_fails(self) -> None:
        process = (b"          app=ProcessRecord{2083011 "
                   b"10104:com.supernote.document/1000}\n")
        configuration = next(
            line + b"\n" for line in wire().splitlines()
            if line.startswith(b"          CurrentConfiguration="))
        cases = (
            wire().replace(process, process + process),
            wire().replace(configuration, configuration + configuration),
            wire().replace(b"      taskId=4538 stackId=4538\n",
                           b"      taskId=4538 stackId=4538\n"
                           b"      taskId=9999 stackId=9999 malformed\n"),
            wire().replace(b"300dpi port", b"300dpi 400dpi port"),
            wire().replace(b"mRotation=ROTATION_0",
                           b"mRotation=ROTATION_1 mRotation=ROTATION_0"),
            wire().replace(b" mBounds=Rect(", b" bogus_mBounds=Rect("),
            wire().replace(b" mBounds=Rect(",
                           b" mBounds=garbage mBounds=Rect("),
            wire().replace(b" mRotation=ROTATION_0",
                           b" bogus_mRotation=ROTATION_0"),
            wire().replace(b"nowVisible=true lastVisibleTime=-1s",
                           b"nowVisible=true lastVisibleTime=-1s nowVisible=false"),
        )
        for raw in cases:
            with self.subTest(raw=raw[:160]), self.assertRaises(
                    authority.AndroidAuthorityError):
                authority.parse_document_task_authority(
                    raw, expected_pid=PID, require_live=False)

        repeated = b" ".join(
            b"300dpi x mBounds=Rect(0, 0 - 1404, 1872)"
            for _ in range(500))
        with self.assertRaises(authority.AndroidAuthorityError):
            authority.parse_document_task_authority(
                wire().replace(b"300dpi", repeated),
                expected_pid=PID, require_live=False)

    def test_duplicate_display_stack_and_bad_header_fail(self) -> None:
        duplicate_display = wire() + wire().split(b"\n", 1)[1]
        duplicate_stack = wire() + wire().split(
            b"Display #0 (activities from top to bottom):\n", 1)[1]
        bad_header = wire().replace(b"ACTIVITY MANAGER ACTIVITIES", b"OTHER", 1)
        for raw in (duplicate_display, duplicate_stack, bad_header):
            with self.subTest(raw=raw[-80:]), self.assertRaises(
                    authority.AndroidAuthorityError):
                authority.parse_document_task_authority(
                    raw, expected_pid=PID, require_live=False)

    def test_synthetic_multi_display_headers_and_foreign_null_resume_are_admitted(
            self) -> None:
        value = authority.parse_document_task_authority(
            multi_display_wire(), expected_pid=PID)
        self.assertEqual((value.display_id, value.stack_id, value.task_id),
                         (3, 4538, 4538))
        self.assertTrue(value.resumed)

    def test_multi_display_structural_lookalikes_still_fail_closed(self) -> None:
        wire_header = (
            b"ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n")
        display_preamble = b"Display areas in focus order:\n"
        display_header = b"Display #3 (activities from top to bottom):\n"
        for malformed_header in (
                b"Display #3 (activities from top to bottom): extra\n",
                b" Display #3 (activities from top to bottom):\n",
                b"Display #x (activities from top to bottom):\n",
                b"Display#3 (activities from top to bottom):\n"):
            with self.subTest(malformed_header=malformed_header), self.assertRaises(
                    authority.AndroidAuthorityError):
                authority.parse_document_task_authority(
                    multi_display_wire().replace(display_header, malformed_header),
                    expected_pid=PID, require_live=False)

        for malformed_resumed in (
                b"    mResumedActivity: NULL\n",
                b"    mResumedActivity:null\n",
                b"    mResumedActivity: null extra\n"):
            with self.subTest(malformed_resumed=malformed_resumed), self.assertRaises(
                    authority.AndroidAuthorityError):
                authority.parse_document_task_authority(
                    multi_display_wire(foreign_resumed=malformed_resumed),
                    expected_pid=PID, require_live=False)

        without_preamble = multi_display_wire().replace(display_preamble, b"", 1)
        foreign_header = b"Display #0 (activities from top to bottom):\n"
        misplaced_preambles = (
            multi_display_wire().replace(
                display_preamble, display_preamble + display_preamble, 1),
            without_preamble.replace(
                foreign_header, foreign_header + display_preamble, 1),
            without_preamble + display_preamble,
            multi_display_wire().replace(
                display_preamble, b"Display summary:\n", 1),
            multi_display_wire().replace(
                wire_header + display_preamble,
                wire_header + b"\n" + display_preamble, 1),
            multi_display_wire().replace(
                wire_header + display_preamble,
                wire_header + b"Recent tasks:\n" + display_preamble, 1),
            multi_display_wire().replace(
                display_preamble, display_preamble + b"\n", 1),
            without_preamble.replace(
                wire_header, wire_header + b"\n", 1),
        )
        for raw in misplaced_preambles:
            with self.subTest(raw=raw[:160]), self.assertRaises(
                    authority.AndroidAuthorityError):
                authority.parse_document_task_authority(
                    raw, expected_pid=PID, require_live=False)

        target_resumed = (b"    mResumedActivity: ActivityRecord{11846f4 u0 "
                          b"com.supernote.document/.document.DocumentActivity "
                          b"t4538}\n")
        with self.assertRaises(authority.AndroidAuthorityError):
            authority.parse_document_task_authority(
                multi_display_wire().replace(
                    target_resumed, b"    mResumedActivity: null\n"),
                expected_pid=PID, require_live=False)

    def test_top_level_boundary_cannot_extend_last_display_scope(self) -> None:
        target_header = b"Display #3 (activities from top to bottom):\n"
        swallowed_target = multi_display_wire().replace(
            target_header, b"Recent tasks:\n", 1)
        later_display = multi_display_wire().replace(
            target_header, b"Recent tasks:\n" + target_header, 1)
        for raw in (swallowed_target, later_display):
            with self.subTest(raw=raw[-200:]), self.assertRaises(
                    authority.AndroidAuthorityError):
                authority.parse_document_task_authority(
                    raw, expected_pid=PID, require_live=False)

        harmless_footer = multi_display_wire() + (
            b"Recent tasks:\n"
            b"  no activity structures retained\n")
        value = authority.parse_document_task_authority(
            harmless_footer, expected_pid=PID)
        self.assertEqual(value.display_id, 3)

    def test_target_resumed_marker_is_owned_by_selected_stack_globally(
            self) -> None:
        foreign_target_resumed = (
            b"    mResumedActivity: ActivityRecord{deadbee u0 "
            b"com.supernote.document/.document.DocumentActivity t9999}\n")
        selected_target_resumed = (
            b"    mResumedActivity: ActivityRecord{11846f4 u0 "
            b"com.supernote.document/.document.DocumentActivity t4538}\n")
        selected_target_paused = selected_target_resumed.replace(
            b"mResumedActivity", b"mLastPausedActivity")
        duplicate_across_displays = multi_display_wire(
            foreign_resumed=selected_target_resumed)
        outside_selected_stack = multi_display_wire(
            foreign_resumed=foreign_target_resumed).replace(
                selected_target_resumed, selected_target_paused, 1)
        for raw in (duplicate_across_displays, outside_selected_stack):
            with self.subTest(raw=raw[:240]), self.assertRaises(
                    authority.AndroidAuthorityError):
                authority.parse_document_task_authority(
                    raw, expected_pid=PID, require_live=False)

    def test_malformed_structural_boundary_cannot_inherit_prior_scope(self) -> None:
        display = b"Display #0 (activities from top to bottom):\n"
        reviewer_counterexample = wire().replace(
            display,
            b"Display #7 (activities from top to bottom):\n"
            b"Display #0 (activities from top to bottom): extra\n")
        malformed_stack = wire().replace(
            b"  Stack #4538: type=standard mode=fullscreen\n",
            b"  Stack #7: type=standard mode=fullscreen\n"
            b"  Stack #4538 extra: type=standard mode=fullscreen\n")
        malformed_task = wire().replace(
            b"    * Task{66d8263 #4538",
            b"    * Task{aaaaaaa #7 visible=false}\n"
            b"     * Task{66d8263 #4538")
        malformed_history = wire().replace(
            b"      * Hist #0: ActivityRecord{",
            b"      * Hist #9: ActivityRecord{ffff u0 com.example/.Other t7}\n"
            b"       * Hist #0: ActivityRecord{")
        for raw in (reviewer_counterexample, malformed_stack,
                    malformed_task, malformed_history):
            with self.subTest(raw=raw[:160]), self.assertRaises(
                    authority.AndroidAuthorityError):
                authority.parse_document_task_authority(
                    raw, expected_pid=PID, require_live=False)

    def test_crlf_is_accepted_but_mixed_and_unterminated_fail(self) -> None:
        crlf = wire().replace(b"\n", b"\r\n")
        self.assertEqual(authority.parse_document_task_authority(
            crlf, expected_pid=PID).task_id, 4538)
        for raw in (wire().replace(b"\n", b"\r\n", 1), wire()[:-1]):
            with self.subTest(raw=raw[:40]), self.assertRaises(
                    authority.AndroidAuthorityError):
                authority.parse_document_task_authority(raw, expected_pid=PID)

    def test_noncanonical_line_separators_cannot_hide_structure(self) -> None:
        header = "Display #0 (activities from top to bottom):\n"
        decoded = wire().decode("utf-8")
        for separator in ("\v", "\f", "\x1c", "\x1d", "\x1e", "\x85",
                          "\u2028", "\u2029"):
            hostile = decoded.replace(
                header,
                "Display #7 (activities from top to bottom):\n" +
                separator + header).encode("utf-8")
            with self.subTest(separator=repr(separator)), self.assertRaises(
                    authority.AndroidAuthorityError):
                authority.parse_document_task_authority(
                    hostile, expected_pid=PID, require_live=False)

    def test_malformed_bounds_density_rotation_and_wire_fail(self) -> None:
        mutations = [
            wire().replace(b"300dpi", b"0dpi"),
            wire().replace(b"1404, 1872", b"0, 1872"),
            wire().replace(b"ROTATION_0", b"ROTATION_4"),
            wire() + b"\x00",
            (b"ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n" +
             b"x" * (authority.MAX_LINE_CHARS + 1) + b"\n"),
            b"\xff\n",
            b"x" * (authority.MAX_DUMPSYS_BYTES + 1),
        ]
        for raw in mutations:
            with self.subTest(raw=raw[:60]), self.assertRaises(
                    authority.AndroidAuthorityError):
                authority.parse_document_task_authority(raw, expected_pid=PID)

    def test_semantic_stability_ignores_only_raw_digest(self) -> None:
        first = authority.parse_document_task_authority(wire(), expected_pid=PID)
        second = replace(first, raw_sha256="f" * 64)
        self.assertTrue(authority.stable_authority(first, second))
        self.assertEqual(authority.stable_authority_bytes(first),
                         authority.stable_authority_bytes(second))
        self.assertEqual(authority.stable_authority_sha256(first),
                         authority.stable_authority_sha256(second))
        self.assertFalse(authority.stable_authority(first, replace(second, task_id=9)))
        self.assertNotEqual(authority.stable_authority_sha256(first),
                            authority.stable_authority_sha256(
                                replace(second, task_id=9)))
        with self.assertRaises(authority.AndroidAuthorityError):
            authority.stable_authority(first, replace(second, resumed=1))
        with self.assertRaises(authority.AndroidAuthorityError):
            authority.stable_authority(first, replace(second, task_id=True))
        with self.assertRaises(authority.AndroidAuthorityError):
            authority.stable_authority(first, object())  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
