"""Independent proof-cut derivation tests; no provider or device calls."""
from __future__ import annotations

import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import app_evidence as subject
import host_protocol as host


ADMISSION = host.Admission(host.SERIAL, "1", 30, host.PACKAGE,
                           "a" * 64, "b" * 64, 2468, "incarnation-1", 1,
                           "activity-1", "root-1", True)
B = (0, 0, 100, 200)
W = (0, 0, 101, 200)
M = (0, 0, 99, 200)
O = (1, 0, 101, 200)
RESTORING = ("parent-plus-one", "parent-minus-one",
             "direct-root-layout", "direct-root-offset")
NON_RESTORING = ("unchanged-bounds", "away-back-aba")


def box(rect):
    return dict(zip(("left", "top", "right", "bottom"), rect))


def cut(rect, revision, write, calls, paint, *, exact=True):
    return {"rootToken": "root-1", "rootIdentityHash": -142,
            "scene": "probe://disposable/layout-fence/nine:orientation=1",
            "bounds": box(rect), "childCount": 9,
            "parentPreCallRevision": revision,
            "observedWriteOrdinal": write, "rootLayoutCallCount": calls,
            "startedPaintRevision": paint,
            "paintStartedElapsedMs": 900 + paint,
            "paintStartParentRevision": revision,
            "paintStartWriteOrdinal": write,
            "completedPaintRevision": paint,
            "completedPaintElapsedMs": 1000 + paint,
            "exactNinePainted": exact,
            "children": [{"index": i, "identityHash": i + 1,
                          "parentIsRoot": True,
                          "evidence": f"TextView:{100+i}:visible:stable"}
                         for i in range(9)],
            "effectivePaintOrder": list(range(1, 10))}


def state_for(variant):
    base = cut(B, 4, 4, 3, 8)
    first_rect = {"parent-plus-one": W, "parent-minus-one": M,
                  "unchanged-bounds": B, "direct-root-layout": W,
                  "direct-root-offset": O, "away-back-aba": B}[variant]
    direct = variant.startswith("direct-")
    if variant == "away-back-aba":
        first = cut(B, 6, 6, 5, 8, exact=False)
        aba = cut(W, 5, 5, 4, 8, exact=False)
    elif variant == "unchanged-bounds":
        first = cut(B, 5, 5, 3, 8, exact=False)
        aba = None
    elif direct:
        first = cut(first_rect, 4, 5, 4 if variant == "direct-root-layout"
                    else 3, 8, exact=False)
        aba = None
    else:
        first = cut(first_rect, 5, 5, 4, 8, exact=False)
        aba = None
    first_frame = cut(first_rect, first["parentPreCallRevision"],
                      first["observedWriteOrdinal"],
                      first["rootLayoutCallCount"], 9)
    if variant in ("unchanged-bounds", "away-back-aba"):
        restore = None
        restored_frame = first_frame
    else:
        restore = cut(B, first["parentPreCallRevision"] + 1,
                      first["observedWriteOrdinal"] + 1,
                      first["rootLayoutCallCount"] + 1, 9, exact=False)
        # The restore layout has not painted yet; it still carries the first
        # changed frame's paint-start and completion provenance.
        for key in ("startedPaintRevision", "paintStartedElapsedMs",
                    "paintStartParentRevision", "paintStartWriteOrdinal",
                    "completedPaintRevision", "completedPaintElapsedMs"):
            restore[key] = first_frame[key]
        restored_frame = cut(B, restore["parentPreCallRevision"],
                             restore["observedWriteOrdinal"],
                             restore["rootLayoutCallCount"], 10)
    second = cut(B, restored_frame["parentPreCallRevision"],
                 restored_frame["observedWriteOrdinal"],
                 restored_frame["rootLayoutCallCount"],
                 restored_frame["completedPaintRevision"] + 1)
    second["paintStartedElapsedMs"] = (
        restored_frame["completedPaintElapsedMs"] + 30)
    second["completedPaintElapsedMs"] = second["paintStartedElapsedMs"] + 1
    return {"schema": subject.SCHEMA,
            "process": {"pid": 2468, "incarnation": "incarnation-1",
                        "activitySerial": 1, "activityPresent": True,
                        "armState": "TRIAL_WATCHDOG_ACTIVE"},
            "activityPresent": True, "activitySerial": 1,
            "activityToken": "activity-1", "rootToken": "root-1",
            "rootAttached": True, "rootHasFocus": True,
            "parentSoleChild": True, "rootLost": False,
            "originalsExact": True, "sessionTainted": False,
            "cleanupVerified": True, "commandClaimed": True,
            "revisionScope": "PARENT_LAYOUT_CALL_ONLY",
            "rootBounds": box(B),
            "current": copy.deepcopy(second),
            "lastCompletedPaint": copy.deepcopy(second),
            "trial": {"command": variant, "state": "PASS",
                      "paintOrderProofVersion": 2,
                      "currentlyValid": True, "rollbackVerified": True,
                      "completeMutationCoverage": False,
                      "bypassObserved": direct,
                      "baseline": base, "firstAfter": first,
                      "firstFrame": first_frame, "restoreAfter": restore,
                      "restoredFrame": restored_frame,
                      "interveningRestoredFrame": None,
                      "secondPaintRequestElapsedMs":
                          restored_frame["completedPaintElapsedMs"] + 25,
                      "secondPaintStartRevisionFloor":
                          restored_frame["startedPaintRevision"],
                      "secondFrame": copy.deepcopy(second),
                      "secondSample": second, "abaAway": aba}}


def with_intervening_restored_paint(state):
    restored = state["trial"]["restoredFrame"]
    intervening = cut(B, restored["parentPreCallRevision"],
                      restored["observedWriteOrdinal"],
                      restored["rootLayoutCallCount"],
                      restored["startedPaintRevision"] + 1)
    intervening["paintStartedElapsedMs"] = (
        restored["completedPaintElapsedMs"] + 1)
    intervening["completedPaintElapsedMs"] = (
        intervening["paintStartedElapsedMs"] + 1)
    second = cut(B, restored["parentPreCallRevision"],
                 restored["observedWriteOrdinal"],
                 restored["rootLayoutCallCount"],
                 intervening["startedPaintRevision"] + 1)
    second["paintStartedElapsedMs"] = (
        intervening["completedPaintElapsedMs"] + 30)
    second["completedPaintElapsedMs"] = second["paintStartedElapsedMs"] + 1
    state["trial"]["interveningRestoredFrame"] = intervening
    state["trial"]["secondPaintRequestElapsedMs"] = (
        intervening["completedPaintElapsedMs"] + 25)
    state["trial"]["secondPaintStartRevisionFloor"] = (
        intervening["startedPaintRevision"])
    state["trial"]["secondFrame"] = copy.deepcopy(second)
    state["trial"]["secondSample"] = copy.deepcopy(second)
    state["current"] = copy.deepcopy(second)
    state["lastCompletedPaint"] = copy.deepcopy(second)
    return state


class EvidenceTests(unittest.TestCase):
    def test_all_six_variant_orders(self) -> None:
        expected_rects = {
            "parent-plus-one": [(B, W), (W, B)],
            "parent-minus-one": [(B, M), (M, B)],
            "unchanged-bounds": [(B, B)],
            "direct-root-layout": [(B, W), (W, B)],
            "direct-root-offset": [(O, B)],
            "away-back-aba": [(B, W), (W, B)]}
        for variant, pairs in expected_rects.items():
            with self.subTest(variant=variant):
                events = subject.derive_entries(state_for(variant),
                                                ADMISSION, variant)
                self.assertEqual([(item.old_bounds, item.proposed_bounds)
                                  for item in events], pairs)
                self.assertEqual(len(events), len(pairs))

    def test_duplicate_or_missing_proof_cut_rejected(self) -> None:
        state = state_for("parent-plus-one")
        state["trial"]["restoreAfter"] = None
        with self.assertRaisesRegex(host.TrialError, "APP_PROOF_INVALID"):
            subject.derive_entries(state, ADMISSION, "parent-plus-one")

    def test_wrong_activity_token_rejected(self) -> None:
        state = state_for("parent-plus-one")
        state["activityToken"] = "other-activity"
        with self.assertRaisesRegex(host.TrialError, "APP_PROOF_INVALID"):
            subject.derive_entries(state, ADMISSION, "parent-plus-one")

    def test_aba_revision_cannot_reuse_final_bounds(self) -> None:
        state = state_for("away-back-aba")
        state["trial"]["abaAway"]["parentPreCallRevision"] = 4
        with self.assertRaisesRegex(host.TrialError, "APP_PROOF_DRIFT"):
            subject.derive_entries(state, ADMISSION, "away-back-aba")

    def test_false_coverage_is_mandatory(self) -> None:
        state = state_for("direct-root-offset")
        state["trial"]["completeMutationCoverage"] = True
        with self.assertRaisesRegex(host.TrialError, "APP_TRIAL_NOT_VALID"):
            subject.derive_entries(state, ADMISSION, "direct-root-offset")

    def test_reused_restored_frame_cannot_impersonate_second_paint(self) -> None:
        state = state_for("parent-plus-one")
        stale = copy.deepcopy(state["trial"]["restoredFrame"])
        state["trial"]["secondFrame"] = copy.deepcopy(stale)
        state["trial"]["secondSample"] = copy.deepcopy(stale)
        state["current"] = copy.deepcopy(stale)
        state["lastCompletedPaint"] = copy.deepcopy(stale)
        with self.assertRaisesRegex(host.TrialError, "APP_PROOF_DRIFT"):
            subject.derive_entries(state, ADMISSION, "parent-plus-one")

    def test_paint_order_must_match_child_indices(self) -> None:
        state = state_for("parent-plus-one")
        state["trial"]["firstFrame"]["effectivePaintOrder"][0:2] = [2, 1]
        with self.assertRaisesRegex(host.TrialError, "APP_PROOF_INVALID"):
            subject.derive_entries(state, ADMISSION, "parent-plus-one")

    def test_one_intervening_paint_is_non_voting(self) -> None:
        for variant in RESTORING:
            with self.subTest(variant=variant):
                state = with_intervening_restored_paint(state_for(variant))
                restored = copy.deepcopy(state["trial"]["restoredFrame"])
                events = subject.derive_entries(state, ADMISSION, variant)
                self.assertEqual(len(events), 1 if variant == "direct-root-offset" else 2)
                self.assertEqual(state["trial"]["restoredFrame"], restored)
                self.assertEqual(restored["startedPaintRevision"], 10)
                self.assertEqual(state["trial"]["interveningRestoredFrame"]
                                 ["startedPaintRevision"], 11)
                self.assertEqual(state["trial"]["secondFrame"]
                                 ["startedPaintRevision"], 12)
                self.assertEqual(state["trial"]["secondPaintStartRevisionFloor"], 11)

    def test_intervening_paint_cannot_replace_requested_second(self) -> None:
        for variant in RESTORING:
            with self.subTest(variant=variant):
                state = with_intervening_restored_paint(state_for(variant))
                stale = copy.deepcopy(state["trial"]["interveningRestoredFrame"])
                for name in ("secondFrame", "secondSample"):
                    state["trial"][name] = copy.deepcopy(stale)
                state["current"] = copy.deepcopy(stale)
                state["lastCompletedPaint"] = copy.deepcopy(stale)
                with self.assertRaisesRegex(host.TrialError, "APP_PROOF_DRIFT"):
                    subject.derive_entries(state, ADMISSION, variant)

    def test_intervening_paint_or_request_drift_rejected(self) -> None:
        mutations = (("rootLayoutCallCount", 99),
                     ("observedWriteOrdinal", 99),
                     ("parentPreCallRevision", 99),
                     ("startedPaintRevision", 13),
                     ("paintStartedElapsedMs", 1),
                     ("paintStartParentRevision", 99),
                     ("paintStartWriteOrdinal", 99),
                     ("completedPaintRevision", 99),
                     ("bounds", box(W)),
                     ("rootToken", "other-root"),
                     ("completedPaintElapsedMs", 4000))
        for variant in RESTORING:
            for field, value in mutations:
                with self.subTest(variant=variant, field=field):
                    state = with_intervening_restored_paint(state_for(variant))
                    state["trial"]["interveningRestoredFrame"][field] = value
                    with self.assertRaises(host.TrialError):
                        subject.derive_entries(state, ADMISSION, variant)
            state = with_intervening_restored_paint(state_for(variant))
            state["trial"]["secondPaintRequestElapsedMs"] = (
                state["trial"]["interveningRestoredFrame"]
                     ["completedPaintElapsedMs"])
            with self.subTest(variant=variant, field="secondPaintRequestElapsedMs"):
                with self.assertRaisesRegex(host.TrialError, "APP_PROOF_DRIFT"):
                    subject.derive_entries(state, ADMISSION, variant)

    def test_extra_request_floor_and_requested_start_are_distinct(self) -> None:
        for variant in RESTORING:
            with self.subTest(variant=variant, field="requestFloor"):
                state = with_intervening_restored_paint(state_for(variant))
                state["trial"]["secondPaintStartRevisionFloor"] = (
                    state["trial"]["restoredFrame"]["startedPaintRevision"])
                with self.assertRaisesRegex(host.TrialError, "APP_PROOF_DRIFT"):
                    subject.derive_entries(state, ADMISSION, variant)
            with self.subTest(variant=variant, field="requestedStart"):
                state = with_intervening_restored_paint(state_for(variant))
                early_start = state["trial"]["secondPaintRequestElapsedMs"] - 1
                for frame in (state["trial"]["secondFrame"],
                              state["trial"]["secondSample"], state["current"],
                              state["lastCompletedPaint"]):
                    frame["paintStartedElapsedMs"] = early_start
                with self.assertRaisesRegex(host.TrialError, "APP_PROOF_DRIFT"):
                    subject.derive_entries(state, ADMISSION, variant)
            with self.subTest(variant=variant, field="requestGap"):
                state = with_intervening_restored_paint(state_for(variant))
                state["trial"]["secondPaintRequestElapsedMs"] = (
                    state["trial"]["interveningRestoredFrame"]
                         ["completedPaintElapsedMs"] + 1001)
                with self.assertRaisesRegex(host.TrialError, "APP_PROOF_DRIFT"):
                    subject.derive_entries(state, ADMISSION, variant)

    def test_restore_after_keeps_first_frame_paint_provenance(self) -> None:
        for variant in RESTORING:
            for with_extra in (False, True):
                for field in ("startedPaintRevision", "paintStartedElapsedMs",
                              "paintStartParentRevision", "paintStartWriteOrdinal",
                              "completedPaintRevision", "completedPaintElapsedMs"):
                    with self.subTest(variant=variant, with_extra=with_extra,
                                      field=field):
                        state = state_for(variant)
                        if with_extra:
                            state = with_intervening_restored_paint(state)
                        state["trial"]["restoreAfter"][field] += 1
                        with self.assertRaisesRegex(host.TrialError,
                                                    "APP_PROOF_DRIFT"):
                            subject.derive_entries(state, ADMISSION, variant)

    def test_restored_paint_counters_must_match_restore_after(self) -> None:
        for variant in RESTORING:
            for with_extra in (False, True):
                with self.subTest(variant=variant, with_extra=with_extra):
                    state = state_for(variant)
                    if with_extra:
                        state = with_intervening_restored_paint(state)
                    restore = state["trial"]["restoreAfter"]
                    self.assertIsNotNone(restore)
                    cuts = [state["trial"]["restoredFrame"],
                            state["trial"]["secondFrame"],
                            state["trial"]["secondSample"], state["current"],
                            state["lastCompletedPaint"]]
                    if with_extra:
                        cuts.append(state["trial"]["interveningRestoredFrame"])
                    for frame in cuts:
                        frame["parentPreCallRevision"] = 99
                        frame["observedWriteOrdinal"] = 99
                        frame["rootLayoutCallCount"] = 99
                        frame["paintStartParentRevision"] = 99
                        frame["paintStartWriteOrdinal"] = 99
                    with self.assertRaisesRegex(host.TrialError, "APP_PROOF_DRIFT"):
                        subject.derive_entries(state, ADMISSION, variant)

    def test_proof_version_and_non_restoring_variants_cannot_use_extra(self) -> None:
        state = state_for("parent-plus-one")
        del state["trial"]["paintOrderProofVersion"]
        with self.assertRaisesRegex(host.TrialError, "APP_TRIAL_NOT_VALID"):
            subject.derive_entries(state, ADMISSION, "parent-plus-one")
        for variant in NON_RESTORING:
            with self.subTest(variant=variant):
                state = with_intervening_restored_paint(state_for(variant))
                self.assertIsNone(state["trial"]["restoreAfter"])
                with self.assertRaisesRegex(host.TrialError, "APP_PROOF_DRIFT"):
                    subject.derive_entries(state, ADMISSION, variant)


if __name__ == "__main__":
    unittest.main()
