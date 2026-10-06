# T013B — deferred two-page saved-ink presentation batch

Status: APPROVED/RUN2026-10-06, HARD STOP at phase5 on exact1842e157/code50.
Reservation6005290839 cleanup was separately approved and completed; released
in issue23 comment6006327861. No further test phases or recovery actions follow
from this result. No new build or pen was needed. The T013
code50 direction-only session is complete/released6003825333; it cannot be reused
as this batch's reservation. Earliest gate is a separately approved device-free
session on the already installed, exact reviewed1842e157/code50 candidate.

## One bounded question

Do the two normally saved T008 source-page ink images keep their exact page
identity/registration through cover pairing, Single/Auto layout and rotation?
Option B remains unchanged: preview only; no writing in RTL, native-writer hook,
new annotation format, converted PDF, personal document or Bluetooth test.

## Preconditions / evidence

Fresh issue23 exclusive reservation and current-user availability/ownership.
Authenticate NomadSN078C10015092. Verify sourcebd0fd00b...e64,13309-byte
markcf444663...5724, code50 config, installedAPK3af19c5c...6147 and
bundleb9cd54ec...56f4, empty owned cache, four plugin IDs and unrelated prefs.
Retain exact current preference/config/mark backups without replacing old evidence.
Capture rotation controls (currently1/2); restore those exact values afterward.
Keep code49 rollback package; no installation is included in this batch.

The known stock half-page presentation after normal Close is retained as a
separate UNKNOWN, not presumed fixed and not an excuse for a rescue restart.
Document identity/footer must still be exact T008PAGE1. If the foreground belongs
to another workflow or any baseline changed ambiguously, stop before mutation.

Use normal native launcher/UI and the focused PluginHost overlay, not a private
intent. Every actual settled screenshot is compared against that page's retained
real1404x1872RGBA SDK reference. Measure observed viewport bounds/divider rather
than assuming a toolbar offset. ReferencePAGE1 SHA6f9fecfe...cd82;
PAGE2 SHA01ca74c6...f0f8. Require actual native readiness and completed SDK output;
"Ink shown" alone is not evidence. Blank halves must contain neither page's ink.

## Predefined sequence (printed page numbers, one-based)

1. Open exactT008. Portrait Auto/Fit/RTL/coverOff/PAGE1: PAGE1 line only.
2. Controlled landscape Auto: PAGE2left|PAGE1right, each own line.
3. CoverOn at PAGE1: BLANKleft|PAGE1right; no leaked PAGE2 line in blank half.
4. Logical Next: BLANKleft|PAGE2right (two-page document's final odd spread),
   PAGE2 line only. Logical Previous returns BLANKleft|PAGE1right.
5. CoverOff restores PAGE2left|PAGE1right, both lines; no stale cover-only image.
6. Landscape SinglePAGE1 -> NextPAGE2 -> PreviousPAGE1: correct own ink each time,
   missing other-page ink. Compare full-canvas uniform-Fit registration.
7. Auto returns two-sided landscape spread; portrait Auto returns SinglePAGE1;
   landscape Auto returns the original spread. Check settled phase after each.
8. One normalClose after SDK/lease settlement. Verify exact source/mark, all
   owned cache entries drained, unrelated preferences/plug-ins unchanged,
   correct stockT008PAGE1 and original rotation restored. Record final stock
   full-page geometry UNKNOWN if half-page retention remains; no rescue loop.

Record result before the next numbered phase. No long-running observer, raw
upload or unattended retry loop. Retain outputs before transitions retire them.

## Outcomes / hard stops

PASS for this presentation batch: all tested source pages/blank halves correct,
each line registration within1displaypixel; original PDF/mark unchanged; observed
normalClose/cache drainage and verified owned-file cleanup. This does not prove
native save atomicity, margin/Native-fill geometry, highlights or arbitrary PDFs.

FAIL: wrong/missing/stale ink, cross-page leak, displacement, unexpected crash or
file change. UNKNOWN: identity, actual SDK settlement, ownership or cleanup cannot
be established. Stop subsequent trial phases on either. Predefined normalClose
is cleanup only when ink/settlement authority is clean; otherwise preserve all
evidence and report the exact blocker. Never restore an old private .mark or
restart the reader as rescue. Remove only explicit local-backed, hash-matched
temporary copies, release the reservation and preserve historical results.

No physical pen action is required. The user needs only to approve this separate
scope and make the Nomad exclusively available. No merge/PR finalization.

## Actual bounded result — 2026-10-06

NomadSN078C10015092/Chauvet.E103.2606161001.2393_release; installed exact
1842e157044c1f4950b2a3acc0221b7355b1b0f4,0.4.24-ink-exp6/code50. Initial
code50 config/APK/bundle, T008 source and13309-byte mark, four plug-ins,
empty owned cache and rotation1/2 verified. Fresh local backups retained at
tmp/t013b-nomad-20261006; original documents never written.

Phases1-4 PASS: portraitAuto PAGE1; landscapeAuto PAGE2left/PAGE1right;
CoverOn BLANKleft/PAGE1right; Next BLANKleft/PAGE2right; Previous returns
BLANKleft/PAGE1right. Actual native READY tokens1-5 and fresh page-bound SDK
outputs observed. Retained outputs equal the respective Single references.
Independent line registration <=0.13662displaypixel; blank halves and each
opposite-page distinctive-ink region remain clean.

Phase5 FAIL to settle: CoverOff shows both correct pages and both saved lines,
but "Rendering..." persists, Edit stays disabled, and no native READY token6
arrives. SDK reports ready/pages1,2 and both actual retained outputs hash-match
their exact page references. The new PAGE2 native view renders/displays; retained
PAGE1 receives no new background render completion. This is not annotation-loss
evidence: sourcebd0fd00b...e64 and markcf444663...5724 remain exact.

cover-off-paired/cover-off-ready screenshots retained; loading badge crosses the
divider, so the generic complete-frame measurement rejects its divider witness.
That rejection is not a measured ink displacement. One host measurement was
started before its capture command completed and returned FileNotFoundError;
excluded from device outcome. Existing capture command completed normally.
Subsequent phases6-8 NOTPERFORMED. No page-turn/rotation/restart rescue.

Hard-stop-logcat and both actual SDK outputs retained. At that hard stop the
underlying nativePID24482/focused PluginHost stayed unchanged on T008 PAGE1
paired landscape, rotation temporarily0/1, pending separately approved cleanup.
That historical state is superseded by cleanup below, not a phase5 retry.

Source inspection identifies a concrete completion-boundary defect: generated
foreground effect resets expected/loaded for both slots, but unchanged PAGE1
native view props/signature yield no new callback. Prepare a generation-bound
view identity/callback correction offline; no fresh hardware/build claim yet.

## Separately approved normal-Close cleanup — PASS

2026-10-06: one observed normal Close, no force-stop/page rescue/pen. Existing
handoff restarted stock24482->1908 once. Settled stock DocumentActivity displays
exact T008PAGE1/2 and the saved BoxA line. Stock still retains cropped half-page
presentation; full-page geometry remains UNKNOWN and was not rescued.
Rotation restored to captured1/2. PDFbd0fd00b...e64,13309-byte
markcf444663...5724, code50 config5acd42c7...9d98, APK3af19c5c...6147 and
bundleb9cd54ec...56f4 unchanged. Four original plug-ins retained; all28unrelated
preference entries exact. T008 alone retainsRTL/Auto/Fit/coverOff/PAGE1.
Owned saved-ink cache is fully empty (files and directories). All49explicit
T013B scratch copies hash-matched their local backups before removal, removed
once and absence verified. No originals/installed files/local evidence deleted.
Final captures/config/prefs and deletion manifest remain local in the batch
folder. Phases6-8 remain NOTPERFORMED; normal Close is cleanup evidence only.
