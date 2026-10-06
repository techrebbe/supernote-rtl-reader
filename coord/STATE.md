# STATE — RTL Reader (updated 2026-10-02 by codex)

## Goal
RTL two-page spread reading of PDFs (Hebrew books) on Supernote Nomad with Supernote's native annotation kept intact. Original PDFs/.mark are never rewritten by RTL Reader.

## Decisions (user, 2026-09-29)
- Native-writer viewport line (stock writer inside a custom split viewport) = bounded **NO-GO**; reopen only on genuinely new evidence.
- Direction = **Option B**: RTL spread for reading; explicit "Edit this page" hands off to the stock reader; user later returns to RTL.
- Repo is the shared channel. Share broadly, write narrowly; occasional blinded reviews are intentional.
- Hardware-first: after basic host safety validation and independent review, use the earliest decisive bounded Nomad gate; do not add speculative offline prerequisites. See `SAFETY.md`.

## Canonical refs
- `main` = `69e2aa2` (PR #22, Native Reader v2; remote-confirmed 2026-09-29). v2 README says "not shippable yet"; `README.md` top sections are stale/contradictory — trust this file first.
- NO-GO record: `agent/native-writer-witness` @ `d8f6120` -> `native-viewport-probe/NATIVE_VIEWPORT_FINAL_VIABILITY.md`.

## Branches (owner)
- Codex, read-only for Claude: `agent/native-writer-witness` d8f6120 (NO-GO tip), `agent/native-paint-order-readonly` ea392b0 (hierarchy v2 read-only Nomad evidence, not in tip), `agent/saved-ink-probe-gate-fix` 7c3331c, `agent/target-owned-helper-app` 845434f, `agent/native-viewport-alpha`/`paint-order-observer` e3162ad.
- Claude: `claude/edit-return-groundwork` (base 69e2aa2) — task T-001.
- Codex: `agent/edit-return-correction` — reviewed/built software candidate `66ac1d56546db1102d3a50ae0c021d57653d6c35`; subsequent documentation commits do not replace that binary identity.
- T006 local implementation at `981c74141e184ba8e90b92c0bbcfd8298a2fd335`,
  `0.4.24-ink-exp1`/code45. Reviewed offline saved-ink display alpha; exact-source
  signed build/package verifier PASS. User-approved normal install now verified
  exact candidate APK/bundle hashes. Reservation5937822106 followed humanPAGE3
  setup; portrait/spread/away-back/portrait DISPLAY gates PASS and native source/
  mark/PID5212 unchanged in first session. User subsequently approved one
  separate SETTLED Close/reopen including existing stock restart: PASS under
  reservation5938943171, native5212->6472 once, ink/highlight/files unchanged,
  fresh RTL request/identical display. FinalNextPAGE4 naturally cleaned owned
  cache; rotation1/2 unchanged, no pending SDK or background device work.
  No push/merge/PR advancement. Earlier PAGE2 setup stop remains NOTPERFORMED.

## Tasks
| id | owner | branch | status |
|----|-------|--------|--------|
| T-001 Edit/Return groundwork | claude | claude/edit-return-groundwork | Historical input at `904ee54`; branch untouched. Its exp1 candidate/build claims, E5-E7 fallback table and hardware execution order are superseded by T-002; preserve its E3 stock-ink safety questions. |
| T-002 Edit/Return correction and first gate | codex | agent/edit-return-correction | Findings 1-6 CLOSED; software gates PASS. Exact candidate `66ac1d5`, `0.4.24-edit-exp2`, code 44 installed with user approval. A, fresh uninterrupted B, both C halves/returns, D1 and D2 PASS. Earlier interrupted B remains UNKNOWN. Saved-stroke/page-identity gate only; not a release. See `tasks/T-002.md`. |
| T-003 One fresh-ink transition | codex | agent/edit-return-correction | User-approved one-shot no-manual-save route PASS at observed timing. Stock reported save before RTL activation; pen-up to kill 185.307s. Not immediate or dirty-at-kill validation. Complete E3 remains open. See `tasks/T-003.md`. |
| T-004 Rapid transition/completed tools | codex | agent/edit-return-correction | Complete: PEN05 narrow PASS (human new-geometry witness), ERASER01 persistence PASS, LASSO01/HIGHLIGHT01 bounded committed-result PASS; independent reviews. Postflight nativePAGE3/PID5212, rotation1/2 restored, annotations retained, observers absent, device RELEASED/safe to unplug. No dirty-at-kill/fullE3 claim; prior UNKNOWN/notperformed unchanged. See `tasks/T-004.md` and `handoffs/T-004-handoff.md`. |
| T-005 Save-safe contract / separate ink PNG diagnostic | codex | agent/edit-return-correction | GateA reviewed design only; no save ACK endpoint implemented. GateB c4a95e5/0.0.1-ink-probe/code1: one-shot PAGE3 portrait PNG PASS, transparent saved ink exactly matches native reference mask; text highlight NOT INCLUDED. Cleanup/diagnostic removal verified, final PAGE3/PID5212/files/production reader/screen unchanged. Prior setup mismatch remains NOTPERFORMED. Device released/no queued work. See `tasks/T-005.md` and `handoffs/T-005-handoff.md`. |
| T-006 Read-only native ink composition | codex | agent/edit-return-correction | Exact981c741/code45 installed/payload-verified. Portrait/spread/away-back/rotation PASS; separately explicitly approved SETTLED Close/reopen PASS with one existing restart, fresh request/identical ink/native highlight preserved. Bounded fixture gate COMPLETE, not general release/fullE3. PDF/mark unchanged, natural cleanup, candidate/PAGE4/nativePID6472/rotation1/2. Device released/no queued work. See `tasks/T-006.md`, `handoffs/T-006-handoff.md`. |
| T-007 Unattended display batch / exit quiescence | codex | agent/edit-return-correction | Code45 display batch PASS; rapid page-away pending overlap NOTEXERCISED. Exit fix e8f9c7d/code46 exact clean-archive build/review PASS; installation and bounded T009 exit checks complete. No source push/merge. See `tasks/T-007.md`. |
| T-008 Restricted ordinary-page ink geometry | codex | agent/edit-return-correction | Exact local be24db0/ink-exp3/code47 installed/payload-verified. First trial remains STOPPED/UNKNOWN (incomplete native mark finalized beforeSDK). Fresh approved continuation5951713480 PASS: normal native reopen20983->1555 establishes saved baseline; initial portrait, page-away/back, landscape unavailable fence, portrait return preserve exact line (0px difference) and stable finalized mark. Independent review PASS. Cleanup/cacheempty/rotation1-2/currentPAGE2/native1555; released, safe unplug. Next bounded source step landscape ink; no new pen/build/merge. See `tasks/T-008.md` and `handoffs/T-008-handoff.md`. |
| T-009 Code46 installation and exit gate | codex | agent/edit-return-correction | Exact e8f9c7d/code46 installed. Settled and one rapid post-navigation Close/reopen preserve native/RTL PAGE3 ink exactly; pending SDK overlap NOTEXERCISED. Cleanup terminal cache empty; release5947230746, no queued device work. See `tasks/T-009.md`. |
| T-010 Ordinary-PDF background baseline | codex | agent/edit-return-correction | Resumed after explicitly recorded battery shutdown. Stock/RTL page navigation, portrait centering, RTL landscape ordering and rotation return PASS for prepared612x792 source; placement residual<1px. Footer clipping limits full-page equivalence; no saved-ink claim. Released5946842260. See `tasks/T-010.md`. |
| T-011 Ordinary-page landscape saved ink | codex | agent/edit-return-correction | Local d740a8e diagnostic/code2 one-shot extraction PASS under5952960763: fixed1404x1872PNG byte-identical portrait, actual pre/post native size1404x1872 despite landscapeUI. Normal cleanup/removal/rotation1/2 complete; release5953419533/no queued hardware. Production code47 unchanged. App/test-only bounded landscapeFit/presentationABA-fence work now underway; exact package/review/display gate next. Windows replay fix8tests/build11/failclosed and independentreviewPASS. See `tasks/T-011.md`. |
| T-012 Production landscape Fit display | codex | agent/edit-return-correction | Exact localc52ba715/code48 independently reviewed CLEAN, relevant tests/provenance PASS. Normal clean-archive signed build/package verification PASS, SNPLGd3b2525a...; no manual correction or production upgrade/device access. Strict1404x1872 witness/native geometry/controller/legacy authority unchanged. Await explicit production-upgrade/display task approval and fresh issue23 reservation; no pen needed. See `tasks/T-012.md`. |

## Known unknowns (do not claim otherwise)
- Native `.mark` annotations were NOT_RENDERED in T002, not lost. Code47 reads
  saved-ink thumbnails for exactT004PAGE3 and exactT008PAGE1 portrait-Fit only.
  Other pages/PDFs and native text highlights remain unsupported. T008B proves
  saved/reopened display registration, not general annotation support.
- T006 settled Close/reopen PASS. Pending-generation Close and external host-hide
  cleanup remain unverified. Close does not directly await globalinkcleanup and
  always schedules stock restart even at same page. AndroidBack is not certified
  complete cleanup; no rapid/pending/dirty-at-kill claim follows from settled PASS.
- Whether SIGKILL of `com.supernote.document` (existing Close handoff, reused by Edit) can lose unsaved stock ink. Hardware test E3. T-003 retained one new stroke after an observed native save, not an immediate/dirty-at-kill guarantee.
- Immediate handoff success acknowledges config/restart scheduling, not the target activity's completed load. T-002 tests that gap on disposable data.

## Device
Latest T008B continuation5951713480 COMPLETE/RELEASED: code47/be24db0 retained;
one approved ordinary stock restart20983->1555, fresh saved PAGE1 baseline PASS.
Portrait/page-return/rotation-return saved-line registration exact, finalized
T008mark/source/T004mark unchanged, landscape explicitly ink-unavailable. Final
RTL PAGE2/2, completed cache empty, original rotation1/2 restored,28unrelated
prefs unchanged,28owned remote capture files removed with local copies retained.
Released in issue23 comment5951926113. No pending SDK, observer or queued hardware
task; safe unplug. Earlier first
T008 stopped result remains UNKNOWN separately. No source push/PR/merge.

Historical reservation5938943171 complete/released: explicit user approval for ONE
existing stock restart, native5212->6472. CorrectT004PAGE3/allink/highlight in
stock and fresh identical RTL ink display. FinalNextPAGE4/cacheempty/filesunchanged,
rotation1/2 retained, candidate45 installed/rollbacknotneeded. No pending SDK,
observer or queued device action; safe unplug. Earlier no-restart omission is
preserved as historicalNOTPERFORMED, not retrospectively reclassified.

Earlier T006 session5937822106 complete: candidate45 remains installed, RTL
disposablePAGE4 displayed, nativePID5212 never restarted, source/mark unchanged.
Owned SDK PNG/request directory naturally removed before release; only this
session's named XML/PNG scratch and staged SNPLG removed, all retained locally.
Rotation settings restored1/2. No active observer/test or queued device action;
safe to unplug. Close/reopen not performed, not waived or claimed PASS.

Nomad session used issue #23 reservation comment 5907996113. User approved bounded T-002
installation/testing and configuration-backed plug-in-only rollback if needed;
also approved publishing observed test results (comment 5917644922). Current
hardware work is complete. The explicitly approved fresh check and original C/D
sequence passed; interrupted evidence remains UNKNOWN separately. Final stock
PAGE 3 has intact saved ink. Rotation settings restored (accelerometer=1,
user_rotation=2); exp2 remains installed, rollback not needed/performed. Device
released with [final results in issue #23](https://github.com/techrebbe/supernote-rtl-reader/issues/23#issuecomment-5918877444).
The separately user-approved T-003 followed on 2026-10-01 with reservation
5922413859: one new hooked stroke on a new disposable PAGE3 survived Edit's
confirmed stock restart at matching geometry. Stock reported saving before RTL
activation. Timing and limited scope are recorded in `tasks/T-003.md`; no E3
completion claim. Rotation again restored to 1/2; candidate/T-002 preserved.
No further hardware action or merge authorized after T-003 closeout.
Nomad is released in [T-003 results, issue #23](https://github.com/techrebbe/supernote-rtl-reader/issues/23#issuecomment-5923475062);
no background hardware operation remains. Safe to unplug.
Subsequent explicit user approval opened T-004 under reservation5923586203.
Root alone operated Nomad; the pen-only watcher expired300s before the human
stroke, with no transition. Hard stop applied; rotation1/2 restored, late ink
preserved, observers stopped. Reservation released in issue23 comment5924220716.
User subsequently confirmed "I'm at the device"; new reservation5924235721
resumed with declared existing-ink baseline. Trial03 stopped before Edit due
host package-only window-title mismatch; same stockPID17400 and known RTL page3
remain. No background runner, rotation1/2 restored, source unchanged. Corrected
host parser has12tests/independent review PASS. Await explicit new-trial decision;
do not perform Edit as ad-hoc cleanup or claim rapid retention PASS.
Device released in issue23 comment5924354259 with the incomplete result; a new
trial needs fresh reservation. No outstanding automatic device operation.
User explicitly approved NEW trial04; reservation5925116260 now exclusively
root Codex. One normal Edit3 setup preserved both strokes in nativePID26935.
Reviewed pen-only observer armed300s; current session85398 awaits one physical
stroke. Temporary rotation0/0, captured restorebaseline1/2. No hardware result
yet; no other agent has device access.
User then requested disconnect before any stroke/transition. Session85398
interrupted; exact owned driver/logcat processes absent, nativePAGE3/PID26935
unchanged, rotation1/2 restored/read back. Trial04 NOTPERFORMED/user-stop. Safe
to unplug; no queued device action. Release posted at closeout.
Subsequent user resume/reconnection opened NEW trial05, reservation5927476576.
Read-only preflight exact source/candidate; chrome revealed atPAGE1, ordinary
Next1->2->3 setup verified both baseline lines/PID26935/selected0.6pen. Observer
session17764 armed300s; awaits one human hook. Rotation0/0 temporary; restore1/2.
No outcome yet; prior UNKNOWN/NOTPERFORMED not reclassified.
Trial05 route then completed, observer exited0/stopped, exactnativePAGE3/PID30122;
all timing limits met and two prior strokes pixel-identical. New upper hook
visible afterward, but not in beforePNG (wet/direct output capture limitation).
Await explicitly labelled human geometry confirmation before tool advance; no
background test, no E3/durable-save claim. Reservation remains root for approved
batch; rotation0/0 temporary, restorebaseline1/2 retained.
User answered Yes to new-line geometry; narrow PEN route PASS recorded with
human witness distinct from prior-ink pixels. Root remains sole device operator;
next is already-approved separate ERASER gate, not ordinary pen completion.
ERASER01 automatic route completed/nativePID31495; gap and whole document pixels
match completed-erasure capture exactly. Measured timing within bounds; stock
toolbar returns0.6pen, not selected-tool preservation. Preparing LASSO only after
recorded result; no observer active, reservation root persists/rotation0/0.
LASSO01 subsequently committed by explicit human PEN blank tap/framegone. One
normal reviewed UI route31495->1185/exactPAGE3/pending2-of8; committedreference/
before/after whole document pixels identical, priorink/BOXB unchanged. Independent
boundedresult review PASS; manualcommit latency notcaptured/no fullE3claim.
Final text-selection tool selected normally on exactPAGE3/PID1185; human asked
select BOXB sentence, leave selectionmenu open. No contact-triggered handoff or
observer armed while awaiting this action. Reservation/rotation unchanged.
HIGHLIGHT01 subsequently explicitly applied by human; alignedgray sentence and
all ink exact after one normal reopen1185->5212/PAGE3/pending2of8. Independent
boundedresultreviewPASS. All four predefined tools complete; no more pen action
or hardware experiments. Closeout rotation1/2/localevidence/release only.
T-004 closeout verified: final nativePAGE3/PID5212/threeinklines/highlight intact,
source and installedAPK/bundle unchanged, consistent local annotation snapshot,
rotation1/2 restored/read back, exact owned observers absent. Released in
https://github.com/techrebbe/supernote-rtl-reader/issues/23#issuecomment-5929290902
User explicitly told safe to unplug; no background hardware work remains.

T-005 completed under fresh reservation5934678778 after user PAGE3 portrait setup.
One native saved-ink PNG request PASS; independent fixed-size ink mask comparison
exact, text-highlight coverage absent. Owned cache cleaned, only diagnostic
removed normally, staged package/named scratch deleted; local evidence retained.
Final nativePAGE3/PID5212, PDF/.mark and installed RTL hashes unchanged; entire
screen pixel-identical to preflight. Device release is recorded in the T-005
handoff and issue23 comment5935378066; user-approved summary at comment5935384866.
No background hardware process, queued operation or further test remains.

## Next permitted
Preserve completed T002-T007 evidence and earlier UNKNOWN/NOTPERFORMED outcomes.
User authorizes continued unattended project testing while asleep, including
document/page/rotation setup; physical pen actions go last. T007 installed-code
display batch is complete/released with natural cleanup; do not repeat it as
filler. Root remains sole device operator under any fresh issue23 reservation.
The pending-ink Close/Edit source fix, focused tests, independent review and exact
signed code46 build are complete at e8f9c7d. All three found Back-fence gaps are
closed. User authorized proceeding; code46 installed and T009 settled/rapid
postnavigation Close/reopen PAGE3preservation gates PASS on2026-10-02. Pending
overlap NOTEXERCISED (SDKfinished beforeClose), not a racePASS. Nativecleanup ack
is source-awaited but not independentlytimestamped. No source push/merge.
T010 ordinary-PDF centeredreading/rotation batch PASS after separately recorded
battery interruption. Current T004markcompaction-lookingchange preserves all
capturednativePAGE3ink/highlight exactly; no unseen-page/durability inference.
T008 bounded ordinary-PDF portrait saved-ink geometry now COMPLETE in a separate
fresh saved-baseline continuation5951713480; original first trial remains UNKNOWN.
Code47 installed and retained, no new pen required for that finished slice.
Next bounded source step: establish the landscape SDK/canonical-canvas contract
and extend read-only composition for the existing vetted page, not repeat the
portrait gate. Nominal dimensions alone cannot authorize placement. Save-safe
companion endpoint/native text highlights remain separate; current read-only
bitmap consistency is not durable-save proof.
Do not revive the stock-writer/custom-viewport NO-GO. Nothing merges without the
user's decision; originals/annotations and rollback evidence remain preserved.

## Needs user approval
No physical action is required for current offline work. New physical pen/tool
validation waits until the user is awake. Destructive/irreversible device work,
firmware changes, uncertain annotation state, merge and release still require a
separate decision. Current installedcandidate be24db0/code47 has passed the
bounded fresh T008B portrait saved-ink gate; no pendingrace/generalPDFrelease or
landscapeink claim. Current RTL T008PAGE2/2/cacheempty/native1555/rotation1/2.
T008B release5951926113 recorded; no queued hardware action. Preserve
scoped reviewed source pins; no native writer/save/handshake change is implied.

T008 source candidate be24db05ff2d130c7861341e06e9a82daccea9d4 is committed
locally, reviewed and built from an exact clean archive. Code47 packageSHA256
05634ba91ec3732d43bf76fc1267d706f70e2b7cfaa481813ad9e0296ac652b1;
APK883f34a124b2489b1afe55d053fbeb352a9a4bde78dfbad5822b3187e3f0994e;
bundleff017c96aecb8c78c9ba39c288a79940228f8af8318753342d735ca64ed53b56.
Same installed code46 signer verified. No push/merge; T008B hardware gate complete
and device released. Local tmp/t008-be24db0-build1/candidate-result.md records
software checks and limits; tasks/T-008.md records fresh hardware result. The
next hardware scope needs explicit task approval/reservation, not another
speculative emulator cycle. No new physical stroke needed for the finished gate.

## Retained feature request
Bluetooth page-turner support remains requested but unimplemented. The current
authored App/native path handles hardware Back fencing only, with no paging
keycode dispatch bridge or focused key tests. Do not claim injected-key or paired
Bluetooth support from touch/footer navigation. After the ordinary ink slice,
implement bounded configurable key mapping and test injected keys separately
from the physical Bluetooth device/transport.

## Latest continuation — 2026-10-02 after T011

Nomad released5953419533, final stockT008PAGE1/native6593/rotation1-2/cacheempty;
no SDK/observer/runner/queued hardware. User told safe to disconnect. T011
fixture-only landscape extraction PASS is preserved; original T008 UNKNOWN and
unsupported general PDF/highlight/durability claims are not changed.

Root-owned branch currentc52ba715bdd463d7f460b25c1605af2f6693c82d, preceded by
reviewed Windows replay fix738f766. Code48 candidate source/tests/pins reviewed;
full build from exact clean archive in tmp/t012-c52ba71-build1 PASS. Installedcode47
remains unchanged. Software/build work complete; next hardware task
requires explicit production-upgrade/display approval and fresh issue23 reservation.
No new physical stroke is needed. No push/PR finalization/merge in this work.

## Latest hardware completion — T012B, 2026-10-02

Standing user direction reaffirmed2026-10-03 and persisted in coord/SAFETY.md:
advance immediately between safe tests/tasks without routine proceed requests.
Report actual blockers explicitly; continue independent work where possible.
Required device approvals/reservations, hard stops and no-merge rule remain.

Supersedes the above pending-install status. Exact c52ba71/code48 is now
installed and its bounded T008 saved-ink production display gate PASS. Native
baseline refresh separately approved; portrait Single Fit, landscape AutoSpread
and Single1/2/1, portrait return and settled normal Close all measured PASS.
Independent registration <=0.02055pixel; no blank-page leak; return frames
byte-identical; stock saved line/source/marks unchanged; ownedcache empty.
First T012 UNKNOWN preserved. T012B reservation5954671272 completed/released.
63exactownedscratch/staging removed after hashes, local evidence retained;
rotationcontrols1/2 restored, final stockT008PAGE1/native15664. Four plugins remain,
28 unrelated prefs equal; disposable T008 Single/PAGE1 intentionally retained.
No queued SDK/probe, physical action, source push, PR finalization or merge.
Release5955153306 published; device safe to disconnect. Next offline preparation
first proves both T008 pages as separate saved-ink identities; broader-PDF
eligibility follows that two-sided slice, not an immediate arbitrary-source enable.

Next separate slice is broader-original-PDF saved-ink display eligibility; current
alpha is still allowlisted T004/T008, Fit only. Native text highlights, general
geometry/durability and Bluetooth page-turner gates remain unimplemented or
unverified as previously stated. Do not revive stock-writer/custom-viewport NO-GO
or reinterpret fixture PASS as general-product completion.

## Latest T013 hardware result — 2026-10-05

Exact0e5ef9a/code49 is now installed, payload/hash verified. Human PAGE2 line and
old PAGE1 line normally saved/reopened; final markcf444663...5724 retained.
PortraitSingle and AutoRTLspread registration PASS within1pixel (0.01163/0.13662px
spread), page-specific SDK batch outputs exact. LTR side swap FAIL: settled
pages correct but both ink layers absent, header still "Ink shown". Files/SDK PNGs
unchanged. Other remaining layout gates NOTPERFORMED; native full-page postflight
UNKNOWN due stock retained half-page mode after rotation. Do not declare whole
T013 PASS or annotation loss. See tasks/T-013.md and REGRESSION.md.

Other workflow's DayWeave interrupted first session; user confirmed/paused it.
Renewed reservation6002365818/preflight reconciled; normal launch restored exact
RTL frame before LTR failure. NormalClose/cache cleanup passed; normalBack returns
prior DayWeave task, not another unexplained action. Rotation1/2 restored;
source/mark/code49/four plugins and28unrelated preferences unchanged.94exactowned
remote scratch/staging copies verified/removed, raw local evidence preserved.
No queued hardware, merge or PR finalization. Next is concrete source regression/
correction and independent review, not another speculative hardware sequence.

## Latest T013 direction correction — 2026-10-06

Supersedes the pending correction: exact1842e157/code50 installed and verified,
0.4.24-ink-exp6. Direction-only hardware retry PASS: RTL->LTR->RTL retains both
correct source-page inks, new distinct SDK tokens/images each phase,<=0.13662px
registration. Code49 direction failure preserved as historical evidence.
NormalClose/cache drainage PASS; source/final mark unchanged, original four
plugins/28unrelated prefs preserved, rotation1/2 restored. T008 alone retains
RTL/Auto/Fit/coverOff/PAGE1. Stock half-page/full-page comparison still UNKNOWN.
72explicit remote scratch/staging copies hash-verified/removed; local evidence
tmp/t013-code50-20261006 retained. Device reservation6003209754 released through
issue23 comment6003825333. No queued hardware, source push, PR finalization or merge.
Code50 exact clean build and two source reviews PASS; older unrelated dirty
evidence untouched. See tasks/T-013.md/REGRESSION.md for scope and exact identities.

Next safe work is the deferred bounded layout/cover/rotation test plan and
independent T014 Bluetooth bridge preparation. New hardware requires explicit
scope/reservation; do not infer general PDF/highlight/product completion.

## Current T013B hard stop — 2026-10-06

Fresh approved reservation6005290839 on installed exact1842e157/code50. Phases1-4
PASS: portrait/paired landscape, coverOn blank/page1, Next blank/page2, Previous
blank/page1; exact real SDK images and <=0.13662px registration, blank/no-leak.
Phase5 CoverOff FAIL to settle: correct visible pages/lines and SDK batchready,
but persistent Rendering/Edit disabled; only newly inserted PAGE2 emits native
completion, retained PAGE1 does not. Source/13309-byte mark remain exact;
no annotation-loss inference. See tasks/T-013B-hardware-plan.md/raw local
tmp/t013b-nomad-20261006. Remaining phases NOTPERFORMED, no rescue mutation.
Separately approved normal-Close cleanup now PASS: stockT008PAGE1/saved line
visible, rotation1/2 restored, source/mark/code50 payload unchanged, owned cache
empty, four plug-ins/28unrelated preferences exact.49local-backed scratch copies
hash-verified/removed once and absence verified; raw local evidence retained.
Stock half-page geometry UNKNOWN, no rescue/pen/force-stop. Issue23 release
follows this evidence; no additional phases or new hardware pass implied.

T013C source-only correction now prepared/reviewed: generation-bound native
React keys and completion/error callbacks, focused red->green regression,
198host TAP tests plus59lifecycle checks, core85407assertions,271mutations and
native/v2/Edit/cross-layer/packaging/provenance gates PASS. Independent review
reports no correctness/annotation-safety blocker, but P2 reverse-cache/performance
regression remains a hardware/release gate. Only reviewed direct-patch frozen
digest updated; no native/controller/save/handoff pins changed. No new candidate
identity/build/install/commit/push/merge; installed code50 still the tested failing
package. Cleanup has completed. User additionally authorizes safe project work
while sleeping: continue exact-candidate preparation/review/build and bounded
disposable testing under a fresh reservation; physical pen actions deferred.
No merge/firmware/original-document work. See tasks/T-013C-render-completion.md.

## T013C overnight candidate preparation — 2026-10-06

Supersedes the preceding source-only/no-build status. User approved continued
safe project work while sleeping, including project commits/pushes/testing; no
merge. Source candidatef834e2d59812b1c786c52327cb2ee896e561ced8 is committed as
0.4.24-ink-exp7/code51. Eight scoped source/test/version files only, no native
writer/save/handoff/controller change. Candidate-only index/workflow markers and
version assertions agree, exact scoped LF pins reviewed. Independent narrow
confirmation found no new critical/high blocker; P2 reverse-cache/performance
remains a measured gate.198host TAP tests,59lifecycle checks,6wiring tests,
85407core assertions,271mutations and source/package/provenance gates PASS.
Exact clean signed build is running in tmp/t013c-f834e2d-build1; code50 still
installed, no new hardware PASS. T013B cleanup PASS/released6006327861.
Next: verify exact package/signer, reserve the free Nomad, and execute the fixed
T013C no-pen cover/layout/rotation retry. Never rescue failure with page/restart
loops. Physical pen/visible-flash acceptance deferred until awake. Overnight
heartbeat continue-rtl-reader-overnight active, skips concurrent work; safe
independent T014 preparation may continue if hardware is blocked. No raw upload,
other worktree changes, firmware/originals/BOOX or PR finalization.

## T013C exact overnight hardware result — 2026-10-06

Supersedes earlier build-running/code50-installed status. Exact clean source
f834e2d59812b1c786c52327cb2ee896e561ced8, exp7/code51 now normally installed,
signature/payload/hash verified. SNPLG1192f6f7...bcc9, APK0cdab5ef...f701,
bundle230a58d5...0bfe. All12 predefined no-pen presentation generations PASS:
coverOn/Next/Previous/CoverOff (old stuck-render now READY6), Single1/2/1,
Auto/portrait/landscape. Exact fresh native completion/SDK output, enabledEdit,
no stale Rendering, correct blank/no-cross-page ink, <=0.253523px registration.
Historical code49 direction/code50 readiness failures retained, not relabeled.

NormalClose/nativeT008PAGE1 saved BoxA line, unchanged source/13309-byte mark,
empty owned SDK cache, original four plugins/28unrelated prefs and rotation1/2
restoration PASS.92local-backed regular/non-symlink scratch/staging copies
hash-verified/removed once/absence verified. Raw evidence retained locally at
tmp/t013c-nomad-20261006; final config17807c59...8006/prefse5a3db55...64e7f.
Reservation6006541260 released via issue23 comment6007047362. No queued hardware.

Open: P2 reverse-cache loss confirmed (reverse rerasterization); measured
interaction84–135ms/native22–166ms does not close visible-flash acceptance.
Memory snapshots226380->258027->256523KB PSS, views14->40->40 are NOT leak proof.
Human visible-flash/physical-input gates deferred; stock half-page comparison
UNKNOWN. No general PDFs/text highlights/Bluetooth/release or merge claim.
Next autonomous source task is existing T014 reader-owned focus/key bridge,
separate candidate/review, no global native hook/device changes. Overnight
follow-up should consume this result, not repeat the build/install/hardware.

## T014 isolated native key-host slice — 2026-10-06

Owned worktree work/page-turner-bridge, branch agent/page-turner-bridge based on
4c3465a. One unregistered ReaderKeyHost wrapper and pure native contact/activation
Core implemented. No installer/manager/App/frozen digest change; installedcode51,
the hardware branch, original documents and released Nomad remain untouched.
2134 Core assertions,25 actual-Host callback-model assertions,four accepted-defect
mutation rejections, actual Android35/RN0.79.2 API compile and existing21 JS route
tests PASS; unchanged native/Edit/v2 gates PASS. First independent review's three
P2 findings closed (Sink failures, detach ABA,long repeats); second exact-slice
confirmation CLEAN. Reviewers inspected only; no independent test/hardware claim.

Not a Bluetooth-delivery or package/hardware pass. Next autonomous source work:
one atomic RN config-request identity and ordered noncoalescing native state/key
transport, then current JS modal/transition/focus fences and existing logical
navigation. Preserve Native Reader/OptionB; no global stock hooks. Integrated
focused tests/review/package/signing and new reservation before injected-key
hardware. Actual paired-turner physical button/hold mapping remains deferred.
Do not repeat consumed T013C build/install/device gate. No merge/PR finalization.
