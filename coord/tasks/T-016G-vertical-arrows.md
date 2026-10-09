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
symbolic-link subcases SKIPPED because host link creation is not permitted;
they are not passed. Pinned-template packager scanner now8/8PASS with the exact
normal build's authenticated template, closing the previous scanner skip.
229 JS covers existing Edit lifecycle, saved-ink batch and actual App route.
App/Edit/Preferences/ink/render/installer/build source unchanged. Independent
input-only source review CLEAN (no P0/P1/P2), after normal read-only review shell
failed setup. Reviewer executed no tests and computed no hashes; host verifies
exact pins/assembly separately. Clean exact-commit signed build completed below.

### Exact clean candidate — 2026-10-09

Executable/source commit: `bb9dbf635f76aef7ef92a60b64015888d6918981`.
Built once from a fresh exact `git archive`, not the mutable implementation
checkout. Normal unmodified `build.sh` exit0; Android Gradle75/75tasks executed.
Build warnings retained (upstream resources, SDK/CMake metadata, deprecations,
existing SavedInkModule nullable receiver and strictfp), not rewritten as errors.

Local output root: `tmp/t016g-bb9dbf6-build1/out/` in the project workspace.

- `SupernoteRtlReader.snplg`:7414230bytes; SHA256
  `1fc3693a8a1119334ad03d09d75671bfedb3940c53adfaaf648e7d4ff4d0df47`.
- `build-provenance/app.npk`:7296999bytes; SHA256
  `c0a47966e21e0f0d07d985068e3969785f52d6024983fc0ee06eaf8012a52b49`.
- `build-provenance/SupernoteRtlReader.bundle`:1151551bytes; SHA256
  `9211fa88db9aec740ca9bd043b45dc356373fc4369eba693125ab8fff55e8df8`.
- Exact source archive `tmp/t016g-bb9dbf6-source.zip`:1493205bytes; SHA256
  `cd434243a7139e9c9793e3a2fe61534ff7d0715f11334a30104c0ed7aceb044c`.

Strict package verifier PASS against exact archived source plus independently
named build bundle/APK. Packaged plug-inID `snrtl20260726001`, version
`0.4.24-keys-exp3`, code55; marker exactly
`RTL_READER_OPEN v0.4.24-keys-exp3-native-reader-v2`. Embedded native APK package
`com.supernotertlreader`, template version1.0/code1 (NOT plug-in code55), minSDK27,
targetSDK35, arm64-v8a. Built DEX contains the six expected key Host/Core/config/
manager/Module/PdfRendererPackage class definitions; bundle contains the exact
Up19/Down20 logical bindings and retained horizontal/Page bindings. This checks
payload inclusion, not runtime delivery or independent hardware behavior.

APK v2/v3 signature verified. Signer certificate SHA256
`fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c`
exactly matches the retained code54/01df18b APK, verified locally without ADB.
Known-good code54 rollback retained. Source commit is pushed; no GitHub CI run
for this branch was available at this checkpoint. Local checks are not CI.
No package installation, device access or raw artifact upload. No active build,
test, review or device process. Later documentation HEADs do not change this
executable identity. Timer remains PAUSED; no PR finalization or merge.

### First user-ready attempt — setup stopped

User returned and explicitly approved the normal code55 upgrade and bounded
watch trial. Reservation6080347973 released6080400065: exact serial/firmware/
battery100%/code54/source/13309-byte mark/29preferences/fourplugins/rotation1-2/
empty owned cache baseline PASS. Native UI lacks exact T008 title witness,
so hard stop before package staging/install, screenshot, UI/page/config/reader/
rotation/pen/key action. NOTPERFORMED, not a Bluetooth functional failure.
Only generated XML retained locally/hash-verified/removed once; absence and
strict postflight files/payload/preferences/plugins/rotation/cache PASS.
Local tmp/t016g-watch-20261009 preserved; no device process, code55 uninstalled.
Required setup: user closes current book normally and opens disposable T008
PAGE1 without drawing, then signals test-ready. Same approved scope remains;
new namespace/reservation/exact preflight before resume. No unchanged software
gate repetition or use of consumed reservation.

### Initial source-only limitation (historical)

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
