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


def real_display_summary_wire() -> bytes:
    """Mirror the Nomad's redundant supervisor hierarchy and display summaries."""
    extra_stacks = b"".join(
        f"  Stack #{stack_id}: type=standard mode=fullscreen\n".encode("ascii")
        for stack_id in range(6000, 6004)
    )
    return (wire() + extra_stacks +
            b"Display #4 (activities from top to bottom):\n"
            b"\n"
            b"ActivityStackSupervisor state:\n"
            b"  topDisplayFocusedStack=Task{66d8263 #4538 visible=true "
            b"type=standard mode=fullscreen translucent=true "
            b"A=1000:com.supernote.document U=0 StackId=4538 sz=1}\n"
            b"  mLastOrientationSource=ActivityRecord{11846f4 u0 "
            b"com.supernote.document/.document.DocumentActivity t4538}\n"
            b"  deepestLastOrientationSource=ActivityRecord{11846f4 u0 "
            b"com.supernote.document/.document.DocumentActivity t4538}\n"
            b"  Display: mDisplayId=0 stacks=5\n"
            b"    Task display areas in top down Z order:\n"
            b"      TaskDisplayArea DefaultTaskDisplayArea\n"
            b"      Application tokens in top down Z order:\n"
            b"      * Task{66d8263 #4538 visible=true type=standard "
            b"mode=fullscreen translucent=true A=1000:com.supernote.document "
            b"U=0 StackId=4538 sz=1}\n"
            b"        bounds=[0,0][1404,1872]\n"
            b"        * ActivityRecord{11846f4 u0 "
            b"com.supernote.document/.document.DocumentActivity t4538}\n"
            b"  Display: mDisplayId=4 stacks=0\n")


def real_idle_display_area_wire() -> bytes:
    """Mirror the Nomad's idle supervisor orientation-source dialect."""
    return (
        b"ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n"
        b"Display areas in focus order:\n"
        b"Display #0 (activities from top to bottom):\n"
        b"  Stack #7: type=home mode=fullscreen\n"
        b"    mResumedActivity: ActivityRecord{abcdef0 u0 "
        b"com.example.home/.HomeActivity t7}\n"
        b"    * Task{7654321 #7 visible=true type=home mode=fullscreen "
        b"A=1000:com.example.home U=0 StackId=7 sz=1}\n"
        b"      taskId=7 stackId=7\n"
        b"      * Hist #0: ActivityRecord{abcdef0 u0 "
        b"com.example.home/.HomeActivity t7}\n"
        b"Display #3 (activities from top to bottom):\n"
        b"ActivityStackSupervisor state:\n"
        b"  topDisplayFocusedStack=Task{7654321 #7 visible=true "
        b"type=home mode=fullscreen A=1000:com.example.home "
        b"U=0 StackId=7 sz=1}\n"
        b"  mLastOrientationSource=DefaultTaskDisplayArea@159915765\n"
        b"  deepestLastOrientationSource=DefaultTaskDisplayArea@159915765\n"
        b"  Display: mDisplayId=0 stacks=1\n"
        b"  Display: mDisplayId=3 stacks=0\n")


def real_multi_display_orientation_pair_wire() -> bytes:
    """Mirror the second pinned two-display supervisor dialect."""
    display_four = b"  Display: mDisplayId=4 stacks=0\n"
    orientation_pair = (
        b"  mLastOrientationSource=DefaultTaskDisplayArea@140913322\n"
        b"  deepestLastOrientationSource="
        b"DefaultTaskDisplayArea@140913322\n")
    return real_display_summary_wire().replace(
        display_four, orientation_pair + display_four, 1)


def real_two_nonprimary_orientation_pairs_wire() -> bytes:
    """Bind distinct display-area identities to two nonprimary displays."""
    return real_multi_display_orientation_pair_wire().replace(
        b"\nActivityStackSupervisor state:\n",
        b"Display #5 (activities from top to bottom):\n"
        b"\nActivityStackSupervisor state:\n",
        1).replace(
            b"  Display: mDisplayId=4 stacks=0\n",
            b"  Display: mDisplayId=4 stacks=0\n"
            b"  mLastOrientationSource="
            b"DefaultTaskDisplayArea@140913323\n"
            b"  deepestLastOrientationSource="
            b"DefaultTaskDisplayArea@140913323\n"
            b"  Display: mDisplayId=5 stacks=0\n",
            1)


def live_host_document_activity_orientation_wire() -> bytes:
    """Mirror the observed host-on-display-0 / Document-on-display-1 wire."""
    target_header = b"Display #1 (activities from top to bottom):\n"
    host_identity = (
        b"ActivityRecord{0a1b2c3 u0 com.techrebbe.supernote.nativepagehost/"
        b".NativePageHostActivity t4646}")
    host_display = (
        b"Display #0 (activities from top to bottom):\n"
        b"  Stack #4646: type=standard mode=fullscreen\n"
        b"    mResumedActivity: " + host_identity + b"\n"
        b"    * Task{7654321 #4646 visible=true type=standard "
        b"mode=fullscreen A=1000:com.techrebbe.supernote.nativepagehost "
        b"U=0 StackId=4646 sz=1}\n"
        b"      taskId=4646 stackId=4646\n"
        b"      * Hist #0: " + host_identity + b"\n"
        b"  Stack #9: type=home mode=fullscreen\n"
        b"  Stack #8: type=standard mode=fullscreen\n"
        b"  Stack #7: type=standard mode=fullscreen\n")
    document_identity = (
        b"ActivityRecord{11846f4 u0 "
        b"com.supernote.document/.document.DocumentActivity t4538}")
    supervisor = (
        b"ActivityStackSupervisor state:\n"
        b"  topDisplayFocusedStack=Task{7654321 #4646 visible=true "
        b"type=standard mode=fullscreen "
        b"A=1000:com.techrebbe.supernote.nativepagehost U=0 "
        b"StackId=4646 sz=1}\n"
        b"  mLastOrientationSource=" + host_identity + b"\n"
        b"  deepestLastOrientationSource=" + host_identity + b"\n"
        b"  Display: mDisplayId=0 stacks=4\n"
        b"  mLastOrientationSource=" + document_identity + b"\n"
        b"  deepestLastOrientationSource=" + document_identity + b"\n"
        b"  Display: mDisplayId=1 stacks=1\n")
    return wire(display_id=1).replace(
        target_header,
        b"Display areas in focus order:\n" + host_display + target_header,
        1) + supervisor


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

    def test_real_nomad_display_supervisor_summaries_are_cross_checked(self) -> None:
        value = authority.parse_document_task_authority(
            real_display_summary_wire(), expected_pid=PID)
        self.assertEqual((value.display_id, value.stack_id, value.task_id),
                         (0, 4538, 4538))
        self.assertTrue(value.resumed)

    def test_real_idle_default_task_display_area_prologue_is_admitted(self) -> None:
        raw = real_idle_display_area_wire()
        text, _ = authority._wire(raw)
        canonical = authority._reject_malformed_structural_headers(text)
        self.assertNotIn("ActivityStackSupervisor state:", canonical)
        self.assertIn("Display #0 (activities from top to bottom):", canonical)
        self.assertIn("Display #3 (activities from top to bottom):", canonical)

    def test_real_multi_display_orientation_pair_is_admitted_as_metadata(
            self) -> None:
        raw = real_multi_display_orientation_pair_wire()
        value = authority.parse_document_task_authority(raw, expected_pid=PID)
        self.assertEqual((value.display_id, value.stack_id, value.task_id),
                         (0, 4538, 4538))
        self.assertTrue(value.resumed)

        text, _ = authority._wire(raw)
        canonical = authority._reject_malformed_structural_headers(text)
        self.assertNotIn("DefaultTaskDisplayArea@140913322", canonical)
        self.assertNotIn("ActivityStackSupervisor state:", canonical)

    def test_each_nonprimary_display_can_own_one_bound_orientation_pair(
            self) -> None:
        raw = real_two_nonprimary_orientation_pairs_wire()
        value = authority.parse_document_task_authority(raw, expected_pid=PID)
        self.assertEqual((value.display_id, value.stack_id, value.task_id),
                         (0, 4538, 4538))

    def test_live_nonprimary_document_activity_orientation_pair_is_bound(
            self) -> None:
        raw = live_host_document_activity_orientation_wire()
        value = authority.parse_document_task_authority(raw, expected_pid=PID)
        self.assertEqual((value.display_id, value.stack_id, value.task_id),
                         (1, 4538, 4538))
        self.assertTrue(value.resumed)

        text, _ = authority._wire(raw)
        canonical = authority._reject_malformed_structural_headers(text)
        self.assertNotIn("mLastOrientationSource", canonical)
        self.assertNotIn("ActivityStackSupervisor state:", canonical)

    def test_activity_orientation_pair_mutations_fail_closed(self) -> None:
        raw = live_host_document_activity_orientation_wire()
        host = (
            b"ActivityRecord{0a1b2c3 u0 "
            b"com.techrebbe.supernote.nativepagehost/"
            b".NativePageHostActivity t4646}")
        document = (
            b"ActivityRecord{11846f4 u0 "
            b"com.supernote.document/.document.DocumentActivity t4538}")
        last = b"  mLastOrientationSource=" + document + b"\n"
        deepest = b"  deepestLastOrientationSource=" + document + b"\n"
        summary = b"  Display: mDisplayId=1 stacks=1\n"
        malformed = (
            # Mismatched exact identities.
            raw.replace(deepest, b"  deepestLastOrientationSource=" +
                        document.replace(b"11846f4", b"21846f4") + b"\n", 1),
            raw.replace(deepest, b"  deepestLastOrientationSource=" +
                        document.replace(b"t4538", b"t4539") + b"\n", 1),
            # Cross-display reuse of the host's otherwise canonical identity.
            raw.replace(last, b"  mLastOrientationSource=" + host + b"\n", 1)
               .replace(deepest,
                        b"  deepestLastOrientationSource=" + host + b"\n", 1),
            # Supervisor-only identity, absent from every canonical Hist block.
            raw.replace(document, document.replace(b"11846f4", b"31846f4"), 2),
            # Mixed ActivityRecord/display-area and null dialects.
            raw.replace(deepest,
                        b"  deepestLastOrientationSource="
                        b"DefaultTaskDisplayArea@140913322\n", 1),
            raw.replace(last, b"  mLastOrientationSource=null\n", 1),
            # Malformed/noncanonical ActivityRecord identities.
            raw.replace(last, last.replace(b"11846f4", b"ABCDEF0"), 1),
            raw.replace(last, last.replace(b"u0", b"u00"), 1),
            raw.replace(last, last.replace(b"t4538", b"t04538"), 1),
            # Pair placement and duplicate canonical-identity ambiguity.
            raw.replace(last + deepest + summary,
                        last + summary + deepest, 1),
            raw.replace(
                b"      * Hist #0: " + document + b"\n",
                b"      * Hist #0: " + document + b"\n"
                b"      * Hist #1: " + document + b"\n", 1),
            # The same pair cannot be borrowed by another nonprimary display.
            raw.replace(
                b"\nActivityStackSupervisor state:\n",
                b"\nDisplay #2 (activities from top to bottom):\n"
                b"\nActivityStackSupervisor state:\n", 1).replace(
                    summary,
                    summary + last + deepest +
                    b"  Display: mDisplayId=2 stacks=0\n", 1),
        )
        for candidate in malformed:
            with self.subTest(candidate=candidate[-500:]), self.assertRaises(
                    authority.AndroidAuthorityError):
                authority.parse_document_task_authority(
                    candidate, expected_pid=PID, require_live=False)

    def test_activity_orientation_binding_requires_canonical_task_nesting(
            self) -> None:
        raw = live_host_document_activity_orientation_wire()
        document = (
            b"ActivityRecord{11846f4 u0 "
            b"com.supernote.document/.document.DocumentActivity t4538}")
        history = b"      * Hist #0: " + document + b"\n"
        display_one = b"Display #1 (activities from top to bottom):\n"
        task_header = b"    * Task{66d8263 #4538 "
        task_detail = b"      taskId=4538 stackId=4538\n"
        summary = b"  Display: mDisplayId=1 stacks=1\n"
        reused_token_identity = (
            b"ActivityRecord{11846f4 u0 com.example.other/.OtherActivity "
            b"t5000}")
        reused_token_stack = (
            b"  Stack #5000: type=standard mode=fullscreen\n"
            b"    * Task{5000000 #5000 visible=false type=standard "
            b"mode=fullscreen A=1000:com.example.other U=0 "
            b"StackId=5000 sz=1}\n"
            b"      taskId=5000 stackId=5000\n"
            b"      * Hist #0: " + reused_token_identity + b"\n")
        malformed = (
            # The Hist has canonical indentation but is outside any Task.
            raw.replace(history, b"", 1).replace(
                display_one, display_one + history, 1),
            # Every enclosing identity must agree with ActivityRecord t4538.
            raw.replace(task_header, b"    * Task{66d8263 #4539 ", 1),
            raw.replace(task_detail,
                        b"      taskId=4539 stackId=4538\n", 1),
            raw.replace(b"StackId=4538", b"StackId=4539", 1),
            raw.replace(b"  Stack #4538:", b"  Stack #4539:", 1),
            # Reusing one ActivityRecord token in a second canonical task is
            # ambiguous even when the full identities differ.
            raw.replace(
                b"\nActivityStackSupervisor state:\n",
                b"\n" + reused_token_stack +
                b"ActivityStackSupervisor state:\n",
                1).replace(summary,
                           b"  Display: mDisplayId=1 stacks=2\n", 1),
        )
        for candidate in malformed:
            with self.subTest(candidate=candidate[-600:]), self.assertRaises(
                    authority.AndroidAuthorityError):
                text, _ = authority._wire(candidate)
                authority._reject_malformed_structural_headers(text)

    def test_activity_orientation_identity_is_exact_observed_dialect(
            self) -> None:
        raw = live_host_document_activity_orientation_wire()
        document = (
            b"ActivityRecord{11846f4 u0 "
            b"com.supernote.document/.document.DocumentActivity t4538}")
        malformed = (
            raw.replace(document, document.replace(b" u0 ", b" u1 ")),
            raw.replace(document, document.replace(b" u0 ", b" u00 ")),
            raw.replace(document, document.replace(b"t4538", b"t0")),
            raw.replace(document, document.replace(b"t4538", b"t01")),
        )
        for candidate in malformed:
            with self.subTest(candidate=candidate[-500:]), self.assertRaises(
                    authority.AndroidAuthorityError):
                text, _ = authority._wire(candidate)
                authority._reject_malformed_structural_headers(text)

    def test_nonprimary_displays_cannot_reuse_one_orientation_identity(
            self) -> None:
        raw = real_two_nonprimary_orientation_pairs_wire().replace(
            b"DefaultTaskDisplayArea@140913323",
            b"DefaultTaskDisplayArea@140913322")
        with self.assertRaises(authority.AndroidAuthorityError):
            authority.parse_document_task_authority(
                raw, expected_pid=PID, require_live=False)

    def test_multi_display_orientation_pair_mutations_fail_closed(self) -> None:
        raw = real_multi_display_orientation_pair_wire()
        pair = (
            b"  mLastOrientationSource=DefaultTaskDisplayArea@140913322\n"
            b"  deepestLastOrientationSource="
            b"DefaultTaskDisplayArea@140913322\n")
        last = b"  mLastOrientationSource=DefaultTaskDisplayArea@140913322\n"
        deepest = (
            b"  deepestLastOrientationSource="
            b"DefaultTaskDisplayArea@140913322\n")
        display_zero = b"  Display: mDisplayId=0 stacks=5\n"
        display_four = b"  Display: mDisplayId=4 stacks=0\n"
        target_last = (
            b"  mLastOrientationSource=ActivityRecord{11846f4 u0 "
            b"com.supernote.document/.document.DocumentActivity t4538}\n")
        target_deepest = (
            b"  deepestLastOrientationSource=ActivityRecord{11846f4 u0 "
            b"com.supernote.document/.document.DocumentActivity t4538}\n")
        malformed = (
            raw.replace(pair, last + display_four + deepest, 1),
            raw.replace(pair, deepest + last, 1),
            raw.replace(pair, pair + pair, 1),
            raw.replace(pair, pair + b"  arbitrary=1\n", 1),
            raw.replace(pair, b"", 1).replace(
                display_zero, pair + display_zero, 1),
            raw.replace(deepest, b"", 1),
            raw.replace(last, b"", 1),
            raw.replace(deepest, deepest.replace(b"140913322", b"140913323"), 1),
            raw.replace(last, last.replace(b"140913322", b"0140913322"), 1),
            raw.replace(last, last.replace(b"140913322", b"-140913322"), 1),
            raw.replace(last, last.replace(b"140913322", b"2147483648"), 1),
            raw.replace(last, target_last, 1),
            raw.replace(deepest, target_deepest, 1),
            raw.replace(last, target_last, 1).replace(
                deepest, target_deepest, 1),
            raw.replace(last, b" mLastOrientationSource=" +
                        last.split(b"=", 1)[1], 1),
            raw.replace(display_four, b"  Display: mDisplayId=0 stacks=0\n", 1),
        )
        for candidate in malformed:
            with self.subTest(candidate=candidate[-360:]), self.assertRaises(
                    authority.AndroidAuthorityError):
                authority.parse_document_task_authority(
                    candidate, expected_pid=PID, require_live=False)

    def test_idle_orientation_source_mutations_fail_closed(self) -> None:
        raw = real_idle_display_area_wire()
        last = (
            b"  mLastOrientationSource=DefaultTaskDisplayArea@159915765\n")
        deepest = (
            b"  deepestLastOrientationSource="
            b"DefaultTaskDisplayArea@159915765\n")
        malformed = (
            raw.replace(
                deepest,
                b"  deepestLastOrientationSource="
                b"DefaultTaskDisplayArea@159915766\n", 1),
            raw.replace(last, b"  mLastOrientationSource=null\n", 1),
            raw.replace(
                deepest,
                b"  deepestLastOrientationSource=ActivityRecord{abcdef0 u0 "
                b"com.example.home/.HomeActivity t7}\n", 1),
            raw.replace(b"@159915765", b"@0159915765", 1),
            raw.replace(b"@159915765", b"@-159915765", 1),
            raw.replace(b"@159915765", b"@2147483648", 1),
            raw.replace(b"DefaultTaskDisplayArea", b"TaskDisplayArea", 1),
            raw.replace(deepest, deepest + last, 1),
            raw.replace(
                b"  topDisplayFocusedStack=Task{7654321 #7 visible=true "
                b"type=home mode=fullscreen A=1000:com.example.home "
                b"U=0 StackId=7 sz=1}\n",
                b"  topDisplayFocusedStack=Task{7654321 #7 visible=true "
                b"type=home mode=fullscreen A=1000:com.example.home "
                b"U=0 StackId=7 sz=1}\n"
                b"  topDisplayFocusedStack=null\n", 1),
        )
        for candidate in malformed:
            with self.subTest(candidate=candidate[-240:]), self.assertRaises(
                    authority.AndroidAuthorityError):
                text, _ = authority._wire(candidate)
                authority._reject_malformed_structural_headers(text)

    def test_target_looking_supervisor_hierarchy_is_not_target_authority(self) -> None:
        raw = real_display_summary_wire()
        value = authority.parse_document_task_authority(raw, expected_pid=PID)
        self.assertEqual(value.task_id, 4538)

        canonical_history = (
            b"      * Hist #0: ActivityRecord{11846f4 u0 "
            b"com.supernote.document/.document.DocumentActivity t4538}\n")
        with self.assertRaises(authority.AndroidAuthorityError):
            authority.parse_document_task_authority(
                raw.replace(
                    canonical_history,
                    canonical_history.replace(
                        b"com.supernote.document/.document.DocumentActivity",
                        b"com.example.other/.OtherActivity"),
                    1),
                expected_pid=PID, require_live=False)

    def test_display_supervisor_summary_mutations_fail_closed(self) -> None:
        raw = real_display_summary_wire()
        display_zero = b"  Display: mDisplayId=0 stacks=5\n"
        display_four = b"  Display: mDisplayId=4 stacks=0\n"
        malformed = (
            raw.replace(display_zero, b"  Display: mDisplayId=0\n", 1),
            raw.replace(display_zero,
                        b"  Display: mDisplayId=0 stacks=5 extra=1\n", 1),
            raw.replace(display_zero, b" Display: mDisplayId=0 stacks=5\n", 1),
            raw.replace(display_zero, b"  Display: mDisplayId=00 stacks=5\n", 1),
            raw.replace(display_zero, b"  Display: mDisplayId=0 stacks=05\n", 1),
            raw.replace(display_zero, b"  Display: mDisplayId=0 stacks=-1\n", 1),
            raw.replace(display_four, b"  Display: mDisplayId=7 stacks=0\n", 1),
            raw.replace(display_zero, b"  Display: mDisplayId=0 stacks=4\n", 1),
            raw.replace(display_four, b"  Display: mDisplayId=4 stacks=1\n", 1),
            raw.replace(display_four, display_zero, 1),
            raw.replace(display_four, b"", 1),
            raw.replace(display_zero, b"", 1).replace(
                b"  Stack #6000: type=standard mode=fullscreen\n",
                display_zero +
                b"  Stack #6000: type=standard mode=fullscreen\n",
                1),
            raw.replace(display_zero, b"", 1).replace(
                b"Display #4 (activities from top to bottom):\n",
                display_zero +
                b"Display #4 (activities from top to bottom):\n",
                1),
            raw.replace(display_zero, b"", 1).replace(
                display_four, display_four + display_zero, 1),
        )
        for candidate in malformed:
            with self.subTest(candidate=candidate[-180:]), self.assertRaises(
                    authority.AndroidAuthorityError):
                authority.parse_document_task_authority(
                    candidate, expected_pid=PID, require_live=False)

    def test_supervisor_boundary_and_hierarchy_mutations_fail_closed(self) -> None:
        raw = real_display_summary_wire()
        boundary = b"ActivityStackSupervisor state:\n"
        canonical_stack = b"  Stack #9999: type=standard mode=fullscreen\n"
        canonical_task = b"    * Task{abcdef0 #9999 visible=false}\n"
        canonical_history = (
            b"      * Hist #0: ActivityRecord{abcdef0 u0 "
            b"com.example.other/.OtherActivity t9999}\n")
        canonical_resumed = b"    mResumedActivity: null\n"
        supervisor_task = (
            b"      * Task{66d8263 #4538 visible=true type=standard "
            b"mode=fullscreen translucent=true A=1000:com.supernote.document "
            b"U=0 StackId=4538 sz=1}\n")
        supervisor_activity = (
            b"        * ActivityRecord{11846f4 u0 "
            b"com.supernote.document/.document.DocumentActivity t4538}\n")
        malformed = (
            raw.replace(boundary, b" ActivityStackSupervisor state:\n", 1),
            raw.replace(boundary, boundary + boundary, 1),
            raw.replace(boundary, boundary + canonical_stack, 1),
            raw.replace(boundary, boundary + canonical_task, 1),
            raw.replace(boundary, boundary + canonical_history, 1),
            raw.replace(boundary, boundary + canonical_resumed, 1),
            raw.replace(supervisor_task, b"     " + supervisor_task[6:], 1),
            raw.replace(supervisor_task, b"       " + supervisor_task[6:], 1),
            raw.replace(
                supervisor_activity, b"       " + supervisor_activity[8:], 1),
            raw.replace(
                supervisor_activity, b"         " + supervisor_activity[8:], 1),
        )
        for candidate in malformed:
            with self.subTest(candidate=candidate[-240:]), self.assertRaises(
                    authority.AndroidAuthorityError):
                authority.parse_document_task_authority(
                    candidate, expected_pid=PID, require_live=False)

    def test_supervisor_content_before_boundary_fails_closed(self) -> None:
        raw = real_display_summary_wire()
        boundary = b"ActivityStackSupervisor state:\n"
        display_summary = b"  Display: mDisplayId=0 stacks=5\n"
        supervisor_task = next(
            line + b"\n" for line in raw.splitlines()
            if line.startswith(b"      * Task{66d8263 #4538"))
        for supervisor_record in (display_summary, supervisor_task):
            moved = raw.replace(supervisor_record, b"", 1).replace(
                boundary, supervisor_record + boundary, 1)
            with self.subTest(record=supervisor_record), self.assertRaises(
                    authority.AndroidAuthorityError):
                authority.parse_document_task_authority(
                    moved, expected_pid=PID, require_live=False)

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
