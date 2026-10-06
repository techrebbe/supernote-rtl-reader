# T013C — generation-bound display completion after CoverOff

Status: CORRECTION COMMITTED, EXACT CLEAN BUILD RUNNING; NOT INSTALLED. User
authorized safe project work while sleeping on2026-10-06; fresh exclusive
reservation and exact package verification remain required. T013B stopped on installed
1842e157/code50 at phase5; preserve that failure and all preceding passes.

## Concrete observed defect

CoverOn -> Next -> Previous -> CoverOff recreates the left PAGE2 native view but
retains the right PAGE1 with identical native render signature. The generated
foreground effect resets its completion set to both source pages. The retained
right view has no new background completion to emit: native ready never arrives,
Rendering persists and Edit remains disabled. Both saved SDK images and original
source/mark were unchanged; this is a completion-boundary defect, not ink loss.

## Small correction under review

Change only the direct-view App generator and existing generated-source tests:

- Carry the monotonic foreground render token into each generated display.
- Key each left/right/single native React view by slot and presentation token, so
  every requested presentation gets an actual fresh draw/completion, including a
  page retained in the same slot after a cover/layout transition.
- Bind rendered/error callbacks to that exact presentation token and ignore late
  same-page callbacks/errors from older generations. Do not seed readiness from
  a previous page event or declare a pending presentation complete on a timer.
- Keep original PDF/mark identity, SDK extraction, saved-ink token authority,
  lease drain, native writer, stock saving and Edit/Close handoff unchanged.

Tradeoff: remounting can add background rendering/bitmap churn relative to a
retained native view. Its material device cost is unverified and belongs in the
bounded retry, not a speculative renderer redesign. Future optimization must
preserve exact fresh presentation completion authority.

## Current focused evidence

Both new regressions fail on unchanged code50 generator: native slots have no
generation key and stale same-page completion can enter a newer request. After
the two-file correction, the full generated Edit/Return suite passes40/40.
All selected existing Edit/lifecycle/saved-ink/annotation/Bluetooth host suites
pass198 TAP tests; lifecycle script additionally reports59/59 checks.
Native renderer/v2/Edit invariants, packaging fail-closed and deterministic
provenance tests pass. Native source/App remain unchanged. Subsequent candidate
version markers identify exp7/code51 in config/index/workflow/version assertions.
Independent narrow read-only review completed: no correctness/annotation-safety
blocker found; one P2 reverse-navigation bitmap-cache regression remains a
performance gate before release. Native core85407 assertions and all271 mutation
checks pass. Review output is retained locally at
tmp/t013b-nomad-20261006/independent-correction-review.md; no review/build/device
process remains running after these checks.

The cross-layer frozen direct-patch digest initially intentionally rejected the
changed generator (old4cbb85d3...d927, current214e5218...8b33). After the independent
review explicitly confirmed the source/pin change legitimate, only that digest
was updated with its review rationale; the cross-layer gate now passes.
No native/writer/save/handoff/controller pin was changed. Candidate identity now
0.4.24-ink-exp7/code51, runtimeRTL_READER_OPEN v0.4.24-ink-exp7-native-reader-v2.
Exact source commitf834e2d59812b1c786c52327cb2ee896e561ced8 includes only eight
source/test/version files. Normal clean checkout build is underway at
tmp/t013c-f834e2d-build1. Code50 remains installed and is not relabeled.
Independent narrow confirmation found no new critical/high safety blocker,
confirmed generation fencing and legitimate three scoped digest changes; P2
performance concern remains. Current198host TAP tests (177plus21page-turner),
59lifecycle checks,6wiring tests,85407core assertions,271mutations and native/
v2/Edit/cross-layer/packaging/provenance gates PASS. Two harness invocations first
rejected stale version assertions/unsupported unittest positional argument;
candidate assertions corrected without changing safety requirements and all
properly invoked gates rerun. Confirmation retained locally at
tmp/t013c-confirmation-review.md. No merge or new package installation yet.

## Earliest safe hardware gate

Finish independent source review, explicit scoped pin/identity update, relevant
software/package checks and exact clean signed build. Retain code50 and code49
rollback packages. User's overnight project authority covers the bounded test
below subject to issue23 reservation and exact package/preflight verification.
T013B normal-Close cleanup PASS, release6006327861; originals/cache/unrelated
state verified. Never reuse the consumed T013B reservation.

Use existing disposable T008 saved lines, Fit/RTL only, no new pen. Repeat the
cover sequence through CoverOff: each requested frame must produce actual
current-generation completion and settle Edit/Rendering, with correct page-bound
ink/blank-half registration within1pixel. Only then run the already-designed
Single/Auto/rotation phases and verified normal Close. Record both correctness
and observed transition timing. Stop on wrong/missing ink, file drift, ownership
conflict, unsettled readiness or uncertain cleanup; no rescue restart/page loop.

## Fixed no-pen overnight retry scope

Install only a verified upgrade-compatible code51 via normal native plugin UI;
retain code50/code49 packages and captured code50 configuration for rollback.
Reserve serialSN078C10015092 through issue23 after checking no other task owns
it. Exact T008sourcebd0fd00b...e64/markcf444663...5724, four original plug-ins,
28unrelated preferences and empty owned cache must match before mutation.
Start T008PAGE1/RTL/Auto/Fit/coverOff. Run the predefined T013B cover/layout/
rotation sequence, each phase bounded to10seconds after actual input.
Record actual current native READY and real SDK output, not merely a screenshot
or stale token. Retain each SDK output before transitions retire it.
Compare source-page ink registration within1pixel, blank and other-page absence.
Record native interaction/render times and cache-hit status for cover-return/
Next->Previous, plus before/after PluginHost memory snapshots. These are bounded
timing/memory observations, not a leak or e-ink-flash proof. Human visible-flash
acceptability is deferred until awake; no release acceptance from timings alone.
A failure ends further phases; normal Close/restore cleanup follows only with
clean source/annotation authority. No turn/restart as an ad-hoc rescue. Unknown
cleanup preserves evidence and holds reservation. On clean completion restore
captured rotation, verify source/annotation/payload/unrelated state, drain owned
cache, remove only hash-verified local-backed scratch, post outcome/release.
No physical input is required for this bounded presentation retry.

This does not authorize general PDF previews, highlights, Native-fill, Bluetooth
device input, user documents, a native-writer/custom-viewport revival or merge.

## Review disposition

Do not silently close the P2 or describe the patch as release-ready. For a future
alpha retry, measure navigation/visible flashing and correctness on hardware
before deciding whether remount cost is acceptable or requires a separately
reviewed native presentation-token/cache-preserving mechanism. Do not add a
native lifecycle rewrite merely to suppress an unmeasured timing concern.
The current saved-ink/Close safety authority remains unchanged and fail-closed.
