"""Pure validation of independent synthetic app proof cuts.

This derives the expected root-layout calls from the app's own trial record,
not from Frida output. It never infers complete write coverage.
"""
from __future__ import annotations

from typing import Any

from host_protocol import Admission, ExpectedEntry, TrialError, need


SCHEMA = "layout-fence-synthetic-v1"
SCENE_PREFIX = "probe://disposable/layout-fence/nine:"
RESTORING_VARIANTS = frozenset(("parent-plus-one", "parent-minus-one",
                                "direct-root-layout", "direct-root-offset"))


def _int(value: Any, minimum: int = 0) -> int:
    need(type(value) is int and minimum <= value <= 2**63 - 1,
         "APP_PROOF_INVALID")
    return value


def _bounds(value: Any) -> tuple[int, int, int, int]:
    need(type(value) is dict and set(value) == {"left", "top", "right", "bottom"},
         "APP_PROOF_INVALID")
    result = tuple(_int(value[name], -(2**31))
                   for name in ("left", "top", "right", "bottom"))
    need(all(number <= 2**31 - 1 for number in result) and
         result[2] > result[0] and result[3] > result[1], "APP_PROOF_INVALID")
    return result  # type: ignore[return-value]


def _cut(value: Any, admission: Admission, baseline: dict | None = None) -> dict:
    need(type(value) is dict and value.get("rootToken") == admission.root_token and
         type(value.get("scene")) is str and
         value["scene"].startswith(SCENE_PREFIX) and
         _int(value.get("childCount")) == 9 and
         type(value.get("exactNinePainted")) is bool,
         "APP_PROOF_INVALID")
    _bounds(value.get("bounds"))
    _int(value.get("rootIdentityHash"), -(2**31))
    for key in ("parentPreCallRevision", "observedWriteOrdinal", "rootLayoutCallCount",
                "startedPaintRevision", "paintStartedElapsedMs", "paintStartParentRevision",
                "paintStartWriteOrdinal", "completedPaintRevision",
                "completedPaintElapsedMs"):
        _int(value.get(key))
    children = value.get("children")
    order = value.get("effectivePaintOrder")
    need(type(children) is list and len(children) == 9 and
         type(order) is list and len(order) == 9,
         "APP_PROOF_INVALID")
    identities = []
    for index, child in enumerate(children):
        need(type(child) is dict and child.get("index") == index and
             type(child.get("parentIsRoot")) is bool and
             child["parentIsRoot"] is True and
             type(child.get("evidence")) is str and child["evidence"] and
             len(child["evidence"]) <= 1024, "APP_PROOF_INVALID")
        identities.append(_int(child.get("identityHash"), -(2**31)))
    need(0 not in identities and len(set(identities)) == 9 and
         all(type(item) is int for item in order), "APP_PROOF_INVALID")
    if value["exactNinePainted"]:
        need(order == identities,
             "APP_PROOF_INVALID")
    if baseline is not None:
        need(value["rootIdentityHash"] == baseline["rootIdentityHash"] and
             value["scene"] == baseline["scene"] and
             [child["identityHash"] for child in children] ==
             [child["identityHash"] for child in baseline["children"]] and
             [child["evidence"] for child in children] ==
             [child["evidence"] for child in baseline["children"]],
             "APP_PROOF_DRIFT")
    return value


def _entry(old: dict, proposed: dict, *, before_write: int | None = None,
           before_layout: int | None = None) -> ExpectedEntry:
    return ExpectedEntry(
        _bounds(old["bounds"]), _bounds(proposed["bounds"]),
        str(_int(proposed["parentPreCallRevision"])),
        None if before_write is None else str(_int(before_write)),
        None if before_layout is None else str(_int(before_layout)),
        None)


def derive_entries(state: dict[str, Any], admission: Admission,
                   variant: str) -> tuple[ExpectedEntry, ...]:
    """Require app PASS and derive exact expected hook cardinality/order."""
    need(type(state) is dict and state.get("schema") == SCHEMA and
         state.get("activityPresent") is True and
         state.get("activitySerial") == admission.activity_serial and
         state.get("activityToken") == admission.activity_token and
         state.get("rootToken") == admission.root_token and
         state.get("rootAttached") is True and
         state.get("rootHasFocus") is True and
         state.get("parentSoleChild") is True and
         state.get("rootLost") is False and
         state.get("originalsExact") is True and
         state.get("sessionTainted") is False and
         state.get("cleanupVerified") is True and
         state.get("commandClaimed") is True and
         state.get("revisionScope") == "PARENT_LAYOUT_CALL_ONLY",
         "APP_PROOF_INVALID")
    process = state.get("process")
    need(type(process) is dict and process.get("pid") == admission.pid and
         process.get("incarnation") == admission.incarnation and
         process.get("activitySerial") == admission.activity_serial and
         process.get("activityPresent") is True and
         process.get("armState") in {"TRIAL_WATCHDOG_ACTIVE",
             "DISARM_SENTINEL_DONE", "UNLOAD_SENTINEL_DONE"},
         "APP_PROCESS_DRIFT")
    proof = state.get("trial")
    need(type(proof) is dict and proof.get("command") == variant and
         type(proof.get("paintOrderProofVersion")) is int and
         proof["paintOrderProofVersion"] == 2 and
         "interveningRestoredFrame" in proof and
         proof.get("state") == "PASS" and proof.get("currentlyValid") is True and
         proof.get("rollbackVerified") is True and
         proof.get("completeMutationCoverage") is False and
         proof.get("bypassObserved") is
           (variant in ("direct-root-layout", "direct-root-offset")),
         "APP_TRIAL_NOT_VALID")
    base = _cut(proof.get("baseline"), admission)
    first = _cut(proof.get("firstAfter"), admission, base)
    first_frame = _cut(proof.get("firstFrame"), admission, base)
    restored_frame = _cut(proof.get("restoredFrame"), admission, base)
    counters = ("parentPreCallRevision", "observedWriteOrdinal",
                "rootLayoutCallCount")
    need(all(first_frame[key] == first[key] for key in counters) and
         _int(first_frame["startedPaintRevision"]) >
             _int(first["startedPaintRevision"]) and
         first_frame["paintStartParentRevision"] ==
             first_frame["parentPreCallRevision"] and
         first_frame["paintStartWriteOrdinal"] ==
             first_frame["observedWriteOrdinal"],
         "APP_PROOF_DRIFT")
    restore_value = proof.get("restoreAfter")
    if variant in RESTORING_VARIANTS:
        restore = _cut(restore_value, admission, base)
        prior_paint = ("startedPaintRevision", "paintStartedElapsedMs",
                       "paintStartParentRevision", "paintStartWriteOrdinal",
                       "completedPaintRevision", "completedPaintElapsedMs")
        need(all(restore[key] == first_frame[key] for key in prior_paint) and
             all(restored_frame[key] == restore[key] for key in counters) and
             restored_frame["paintStartParentRevision"] ==
                 restore["parentPreCallRevision"] and
             restored_frame["paintStartWriteOrdinal"] ==
                 restore["observedWriteOrdinal"] and
             _int(restored_frame["startedPaintRevision"]) >
                 _int(restore["startedPaintRevision"]) and
             restored_frame["completedPaintRevision"] ==
                 restored_frame["startedPaintRevision"],
             "APP_PROOF_DRIFT")
    else:
        need(restore_value is None and restored_frame == first_frame,
             "APP_PROOF_DRIFT")
        restore = None
    intervening_value = proof["interveningRestoredFrame"]
    need(intervening_value is None or variant in RESTORING_VARIANTS,
         "APP_PROOF_DRIFT")
    anchor = restored_frame
    if intervening_value is not None:
        intervening = _cut(intervening_value, admission, base)
        need(intervening["exactNinePainted"] is True and
             intervening["effectivePaintOrder"] ==
                 restored_frame["effectivePaintOrder"] and
             _bounds(intervening["bounds"]) == _bounds(base["bounds"]) and
             all(intervening[key] == restored_frame[key] for key in
                 ("parentPreCallRevision", "observedWriteOrdinal",
                  "rootLayoutCallCount")) and
             _int(intervening["startedPaintRevision"]) ==
                 _int(restored_frame["startedPaintRevision"]) + 1 and
             intervening["completedPaintRevision"] ==
                 intervening["startedPaintRevision"] and
             intervening["paintStartParentRevision"] ==
                 intervening["parentPreCallRevision"] and
             intervening["paintStartWriteOrdinal"] ==
                 intervening["observedWriteOrdinal"] and
             _int(intervening["paintStartedElapsedMs"]) >=
                 _int(restored_frame["completedPaintElapsedMs"]) and
             _int(intervening["completedPaintElapsedMs"]) >=
                 _int(intervening["paintStartedElapsedMs"]) and
             _int(intervening["completedPaintElapsedMs"]) -
                 _int(restored_frame["completedPaintElapsedMs"]) <= 1000,
             "APP_PROOF_DRIFT")
        anchor = intervening
    second_frame = _cut(proof.get("secondFrame"), admission, base)
    second = _cut(proof.get("secondSample"), admission, base)
    current = _cut(state.get("current"), admission, base)
    latest = _cut(state.get("lastCompletedPaint"), admission, base)
    need(base["exactNinePainted"] is True and
         first_frame["exactNinePainted"] is True and
         restored_frame["exactNinePainted"] is True and
         second_frame["exactNinePainted"] is True and
         second["exactNinePainted"] is True and
         base["effectivePaintOrder"] ==
            first_frame["effectivePaintOrder"] ==
            restored_frame["effectivePaintOrder"] ==
            second_frame["effectivePaintOrder"] ==
            second["effectivePaintOrder"] and
         _bounds(first["bounds"]) == _bounds(first_frame["bounds"]) and
         _bounds(base["bounds"]) == _bounds(restored_frame["bounds"]) ==
            _bounds(second_frame["bounds"]) == _bounds(second["bounds"]) ==
            _bounds(state.get("rootBounds")) and
         _int(second_frame["startedPaintRevision"]) >
            _int(restored_frame["startedPaintRevision"]) and
         _int(second_frame["completedPaintRevision"]) >
            _int(restored_frame["completedPaintRevision"]) and
         _int(second_frame["paintStartedElapsedMs"]) >=
            _int(restored_frame["completedPaintElapsedMs"]) and
         second == second_frame == current == latest,
         "APP_PROOF_DRIFT")
    request_ms = _int(proof.get("secondPaintRequestElapsedMs"))
    floor = _int(proof.get("secondPaintStartRevisionFloor"))
    need(floor == _int(anchor["startedPaintRevision"]) and
         request_ms >= _int(anchor["completedPaintElapsedMs"]) + 25 and
         request_ms - _int(anchor["completedPaintElapsedMs"]) <= 1000 and
         all(second_frame[key] == anchor[key] for key in
             ("parentPreCallRevision", "observedWriteOrdinal",
              "rootLayoutCallCount")) and
         second_frame["paintStartParentRevision"] ==
             second_frame["parentPreCallRevision"] and
         second_frame["paintStartWriteOrdinal"] ==
             second_frame["observedWriteOrdinal"] and
         _int(second_frame["startedPaintRevision"]) > floor and
         second_frame["completedPaintRevision"] ==
             second_frame["startedPaintRevision"] and
         _int(second_frame["paintStartedElapsedMs"]) >= request_ms and
         _int(second_frame["completedPaintElapsedMs"]) >=
             _int(second_frame["paintStartedElapsedMs"]) and
         _int(second_frame["completedPaintElapsedMs"]) -
             _int(anchor["completedPaintElapsedMs"]) <= 1000,
         "APP_PROOF_DRIFT")
    base_rect = _bounds(base["bounds"])
    first_rect = _bounds(first["bounds"])
    base_rev = _int(base["parentPreCallRevision"])
    base_write = _int(base["observedWriteOrdinal"])
    base_layout = _int(base["rootLayoutCallCount"])
    first_rev = _int(first["parentPreCallRevision"])
    first_write = _int(first["observedWriteOrdinal"])
    first_layout = _int(first["rootLayoutCallCount"])
    aba = proof.get("abaAway")
    if variant in ("parent-plus-one", "parent-minus-one"):
        delta = 1 if variant == "parent-plus-one" else -1
        need(first_rect == (base_rect[0], base_rect[1], base_rect[2] + delta,
                            base_rect[3]) and first_rev == base_rev + 1 and
             first_write == base_write + 1 and first_layout == base_layout + 1 and
             aba is None, "APP_PROOF_DRIFT")
        need(_bounds(restore["bounds"]) == base_rect and
             restore["parentPreCallRevision"] == base_rev + 2 and
             restore["observedWriteOrdinal"] == base_write + 2 and
             restore["rootLayoutCallCount"] == first_layout + 1,
             "APP_PROOF_DRIFT")
        return (_entry(base, first, before_write=first_write,
                       before_layout=base_layout),
                _entry(first_frame, restore,
                       before_write=restore["observedWriteOrdinal"],
                       before_layout=first_layout))
    if variant == "unchanged-bounds":
        need(first_rect == base_rect and first_rev == base_rev + 1 and
             first_write == base_write + 1 and first_layout == base_layout and
             restore is None and aba is None, "APP_PROOF_DRIFT")
        return (_entry(base, first, before_write=first_write,
                       before_layout=base_layout),)
    if variant == "direct-root-layout":
        need(first_rect == (base_rect[0], base_rect[1], base_rect[2] + 1,
                            base_rect[3]) and first_rev == base_rev and
             first_write == base_write + 1 and first_layout == base_layout + 1 and
             aba is None, "APP_PROOF_DRIFT")
        need(_bounds(restore["bounds"]) == base_rect and
             restore["parentPreCallRevision"] == base_rev + 1 and
             restore["observedWriteOrdinal"] == base_write + 2 and
             restore["rootLayoutCallCount"] == first_layout + 1,
             "APP_PROOF_DRIFT")
        return (_entry(base, first, before_write=base_write,
                       before_layout=base_layout),
                _entry(first_frame, restore,
                       before_write=restore["observedWriteOrdinal"],
                       before_layout=first_layout))
    if variant == "direct-root-offset":
        need(first_rect == (base_rect[0] + 1, base_rect[1], base_rect[2] + 1,
                            base_rect[3]) and first_rev == base_rev and
             first_write == base_write + 1 and first_layout == base_layout and
             aba is None, "APP_PROOF_DRIFT")
        need(_bounds(restore["bounds"]) == base_rect and
             restore["parentPreCallRevision"] == base_rev + 1 and
             restore["observedWriteOrdinal"] == base_write + 2 and
             restore["rootLayoutCallCount"] == first_layout + 1,
             "APP_PROOF_DRIFT")
        return (_entry(first_frame, restore,
                       before_write=restore["observedWriteOrdinal"],
                       before_layout=first_layout),)
    if variant == "away-back-aba":
        away = _cut(aba, admission, base)
        need(_bounds(away["bounds"]) == (base_rect[0], base_rect[1],
                                         base_rect[2] + 1, base_rect[3]) and
             away["parentPreCallRevision"] == base_rev + 1 and
             away["observedWriteOrdinal"] == base_write + 1 and
             away["rootLayoutCallCount"] == base_layout + 1 and
             first_rect == base_rect and first_rev == base_rev + 2 and
             first_write == base_write + 2 and first_layout == base_layout + 2 and
             restore is None, "APP_PROOF_DRIFT")
        return (_entry(base, away,
                       before_write=away["observedWriteOrdinal"],
                       before_layout=base_layout),
                _entry(away, first, before_write=first_write,
                       before_layout=away["rootLayoutCallCount"]))
    raise TrialError("VARIANT_INVALID")
