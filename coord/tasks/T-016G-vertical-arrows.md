# T016G — vertical-arrow support, earliest hardware gate

## Evidence and scope

T016F-E (2026-10-09, issue23 reservation6079400773/release6079451520)
registered78 Linux EV_KEY transitions:20 KEY_UP and19 KEY_DOWN complete pairs
from the Galaxy Watch8 Classic Keyboard interface. User confirmed presses in
the actual READY window. All three exact watch interfaces were observed without
grabbing or injecting input. No repeat or unmatched contact; mouse/consumer had
no events. Monitor stopped at its80-second host deadline, all owned target
children/wrappers retired, sysfs postflight PASS. Raw evidence local only;
no PDF/mark/screen/UI/config/reader change by the monitor. This was input arrival,
not an RTL-navigation or Android mapping pass. Prior D had no user presses;
prior T016C functional FAIL/upstream UNKNOWN is not retroactively fixed.

Source has a concrete gap: native Configuration/Core reject Android DPAD19/20,
Host diagnostics exclude them and JS navigation maps only21/22/92/93.
[Android KeyEvent](https://developer.android.com/reference/android/view/KeyEvent)
defines DPAD_UP19 and DPAD_DOWN20. Upstream Android11
[Generic.kl](https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android-11.0.0_r1/data/keyboards/Generic.kl)
maps Linux103/108 to those directions; actual Nomad layout/delivery is UNVERIFIED.
Do not translate Linux/HID codes or infer firmware interception in our app.

## Bounded software change

Extend the existing opt-in navigation profile: Up19 = logical Previous;
Down20 = logical Next in RTL and LTR. Left/Right retain direction-dependent
meaning, PageUp/PageDown retain logical meaning. Volume profiles unchanged.
No new preference/schema/migration, automatic enablement or watch-specific
global binding. Explicit Off remains Off. Native/JS validators and bounded
Host dispatch diagnostics cover both keys; eight-key configuration bound stays
unchanged. Use only existing logical callbacks, render/ink epochs, atomic request
and ordered event transport. No Activity/stock-reader hook, new listener/focus
claim, annotation/save/pen/restart path or writer-viewport revival.

Candidate identity:0.4.24-keys-exp3/code55. Runtime marker and CI artifact agree.
Index pin changes are marker-only; workflow pin changes are label and one new
in-memory regression suite only. Other protected source pins remain unchanged.
Code54/01df18b stays installed until a later separately authorized hardware trial.

## Offline gates

New vertical tests must fail against the pre-change code, then pass after change.
Exercise exact DOWN/UP, repeats, stale/rejected contacts, OFF/focus/modal/ABA,
volume exclusion, disposal, RTL/LTR, actual App Single/Spread steps and boundaries,
existing ink invalidation, and native atomic six-key configuration/event stamps.
Mutation checks remove native Core/config/diagnostic coverage and omit/reverse
each JS vertical binding. Keep prior mutation/regression tests and actual Android/
RN compile. Focused assembly, native/Edit/v2/provenance/package checks, independent
narrow exact-diff review and clean exact-commit signed build precede device use.
Do not weaken a frozen pin or test to obtain a pass; review scoped version pins.

## Earliest decisive hardware gate — NOT EXECUTED

Offline checkpoint2026-10-09:229 JS tests,2155 Core/57 Host/93 bridge assertions,
seven native omission/prior-defect mutations and four JS omission/reversal mutants
PASS. Actual Android35/RN0.79.2 compile PASS (retained dependency/deprecation
warnings). Native85407Core/all271mutations, native/Edit/v2/cross-layer invariants,
actual generated key/saved-ink assembly, packaging/provenance, saved-ink524math/
171runtime/seven module-fence/10renderer checks PASS. Geometry fixture four
optional cases and pinned-template scanner one case SKIPPED, not claimed passed.
229 JS covers existing Edit lifecycle, saved-ink batch and actual App route.
App/Edit/Preferences/ink/render/installer/build source unchanged. Independent
input-only source review CLEAN (no P0/P1/P2), after normal read-only review shell
failed setup. Reviewer executed no tests and computed no hashes; host verifies
exact pins/assembly separately. Clean exact-commit signed build still pending.

User is away. Physical watch presses are deferred; no unattended injection or
device mutation is part of this source task. Do not use the released reservation.
After independent review and exact signed package verification, obtain approval
for normal code55 upgrade and a fresh exclusive issue23 reservation. Use only
existing disposable T008, with exact saved-line/PDF/mark/payload/config baseline
and known-good code54 rollback. Native T008PAGE1, fixed orientation; normal RTL
launch, Single/On/Arrows-Page-keys, settled PAGE1/READY/Edit/TurnerReady and current
eligible Host/request/diagnostic budget. Announce readiness before user acts.

ONE Down press/release: record actual Android dispatch code, native decision,
ordered original-stamped JS packet/decision and PAGE2 fresh completion. If that
passes, ONE Up press/release after settle must restore PAGE1 with fresh READY
and the original saved line. Logical navigation PASS requires exactly one page
change per press plus correct ink; raw input alone is insufficient. If no Host
dispatch, Android delivery remains UNKNOWN; if code differs, stop, do not cycle
profiles or add global hooks. No hold/mode/rotation/modal follow-ups after failure.
Record result, normal Off/Auto/Close, exact integrity/cache/owned-scratch cleanup
and release. Human pen/feel, generic PDFs and complete-memory/leak proof remain
separate. No package merge/PR finalization without user's explicit decision.
