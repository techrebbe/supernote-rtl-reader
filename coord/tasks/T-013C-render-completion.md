# T013C — generation-bound display completion after CoverOff

Status: EXACT CODE51 BOUNDED HARDWARE/CLOSE/CLEANUP PASS; human performance
acceptance and P2 reverse-cache concern remain open. Reservation6006541260
released6007047362. User authorized safe project work while sleeping on2026-10-06.
T013B stopped on1842e157/code50 at phase5; preserve that historical failure.
Earlier preparation/build notes below are historical, superseded by the result.

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

## Exact T013C hardware result — 2026-10-06

Pushed sourcef834e2d59812b1c786c52327cb2ee896e561ced8 clean-built in
tmp/t013c-f834e2d-build1; normal native plug-in upgrade installed exp7/code51.
Outer SNPLG1192f6f729ab116c157f53c8ec2aea58819af8e2c58fc7d35c79c830ba40bcc9,
APK0cdab5ef00322976c3b3ed6d79f610937c7eee3a975b516295944b471bf2f701,
bundle230a58d56bc3206acc34f921a8fe0e52d43545e83f6abb97e22f93305a7c0bfe.
Signerfac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c,
v2/v3 verified compatible. Installed payload matched exactly. Nomad
SN078C10015092 at10.0.40.1:5555, Chauvet.E103.2606161001.2393_release.

| Native generation | Settled presentation | Result |
| --- | --- | --- |
| 1 | portrait Auto/Single PAGE1 | PASS |
| 2 | landscape Auto, PAGE2 left/PAGE1 right | PASS |
| 3 | CoverOn blank left/PAGE1 right | PASS |
| 4 | Next blank left/PAGE2 right | PASS |
| 5 | Previous blank left/PAGE1 right | PASS |
| 6 | CoverOff PAGE2 left/PAGE1 right (old stuck-render reproduction) | PASS |
| 7 | landscape Single PAGE1 | PASS |
| 8 | Next Single PAGE2 | PASS |
| 9 | Previous Single PAGE1 | PASS |
| 10 | Auto landscape PAGE2 left/PAGE1 right | PASS |
| 11 | rotation to portrait Single PAGE1 | PASS |
| 12 | rotation to landscape PAGE2 left/PAGE1 right | PASS |

Each actual READY token/pages and page-specific SDK batch settled, Edit enabled;
retained SDK outputs match PAGE1 6f9fecfe...ecd82/PAGE2 01ca74c6...f0f8.
All12 retained settled frames rerun offline: uniform Fit registration<=1pixel,
maximum0.253523px; blank halves and other-page ink absence PASS. No new pen.
Sourcebd0fd00b...e64 and13309-byte markcf444663...5724 unchanged throughout.

NormalClose once PASS, native T008PAGE1 existing BoxA line visible. Handoff
restarted stock Document1908 through its existing normal route, not a rescue.
Owned SDK cache empty files AND directories; four original plug-ins/28 unrelated
prefs exact. Only T008 retains RTL/Auto/Fit/coverOff/PAGE1. Captured rotation1/2
restored; final config17807c59...8006 and prefs e5a3db55...64e7f retained.
92 exact regular/non-symlink scratch/staging copies hash-verified, removed once,
absence verified; local PDFs/mark/screenshots/logs remain under
tmp/t013c-nomad-20261006. Final-postflight-pass.json and complete
all-pixel-measurements-pass.json retained locally. No raw evidence uploaded.
Reservation release: issue23 comment6007047362.

Scope/exclusions: initial portrait-ready capture preceded actual readiness;
original cover-return capture has a transient root-permission toast across its
blank half. Both excluded, not masked/repinned. Clean read-only recapture of the
same READY5 frame passed without page/settings changes. One host PageOrder
argument lacked quotes and failed before verification; corrected exact current
stage verification passed. Earlier historical-stage/current-token and optional
interactionMs parser rejections were host harness errors, not hardware passes.

P2 reverse-cache concern CONFIRMED, NOT CLOSED: cover return and Single reverse
rerasterized (cacheHit=false). Observed interaction84–135ms; displayed native work
22–166ms. These timings do not establish visible e-ink flashing acceptance.
PluginHost PSS226380KB before ->258027KB after transitions ->256523KB immediately
afterClose; views14 ->40 ->40. Snapshot timing/application caches/GC were not
controlled: NOT a memory-leak PASS or diagnosis. Human flash/feel remains deferred.
Stock half-page geometry comparison remains UNKNOWN; no rescue turn/restart.
No general-PDF/native-highlight/Bluetooth or release/merge acceptance implied.
