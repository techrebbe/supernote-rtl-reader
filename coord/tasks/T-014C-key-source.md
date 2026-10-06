# T014C — distinguish injected source from reader delivery

## Concrete source evidence, not a presumed firmware fix

T014B code53 result remains functional FAIL/upstream cause UNKNOWN, released
6008737877. No Host dispatch despite established eligible Host/budget. Inspecting
the retained PluginHost source shows the visible plug-in uses a service-owned
PluginContainer/ReactRootView, not MainActivity. Container has no key override;
ReactRootView observes then delegates key events normally. Do not add an Activity
hook or infer an intercepted key from absence of Host output.

Android11 upstream Input.java defaults inputSource to SOURCE_UNKNOWN and display
to INVALID_DISPLAY. Unlike text/tap, InputKeyEvent does not substitute KEYBOARD:
it constructs KeyEvent with inputSource unchanged. An explicit `keyboard` source
sets SOURCE_KEYBOARD before the same key constructor. Our prior `input keyevent
93` therefore differs from real keyboard/HID input at this boundary. This is a
concrete hypothesis, NOT proof that Nomad's firmware follows upstream exactly or
that source explains the missing arrival. Source:
https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android-11.0.0_r1/cmds/input/src/com/android/commands/input/Input.java

## Smallest decisive next gate

Use exact installed reviewed dce6529/code53, no production changes/build/install.
Independent focused plan review before a fresh exclusive issue23 reservation.
Use only existing disposable T008, retain baseline/rollback/source/.mark. Exact
serial SN078C10015092 at10.0.40.1:5555, no competing owner, battery>=20% or charging.
StockPAGE1 and exact installed package/ink integrity preflight. Capture actual
Android input help read-only to confirm parser supports explicit keyboard source;
if unsupported or device state differs, stop without key injection.

Normal existing UI open RTL; Settings Single/On/navigation/Done, settlePAGE1/
Editp1/TurnerReady/nativeREADY1 and eligible native generation/available128budget.
Capture current window and InputDispatcher focus/display state read-only before
the key, retaining evidence locally (no raw upload). Require current plugin window
focus and no unresolved different input-owner evidence. Exactly ONE command:
`adb -s 10.0.40.1:5555 shell input keyboard keyevent 93`.

Change only source; leave key, display default, document, profile, settings and
candidate identical to T014B. Do NOT add `-d0`, another key, alternate profile,
second injection or global key listener. This is not a physical HID test.

Within10seconds record native Host dispatch/Core decision, emit attempt, actual
JS decision and actual resulting page/native completion. PASS functional requires
PAGE2 exactly once and native display completion, original ink preserved. FAIL
if unchanged/wrong/multiple page, UNKNOWN if disconnected/focus/budget/evidence
ambiguous. Distinguish functional outcome from each observed boundary; an emit
attempt alone does not prove JS delivery. Missing Host is still UNKNOWN upstream,
not proof of system interception. Stop after that one key/first mismatch.

## Closeout / hard stop

Record result before normal SettingsOff/Auto/Done/Close. With settled known state,
verify resulting stock page/saved geometry, exact source/.mark/installed payload,
28 unrelated preference values/four plug-ins/rotation1-2/empty owned cache. The
legitimate test lastPageIndex may be0 or1 according to outcome, not forcibly
reverted by another page turn. Hash-verify/remove only a fresh T014C-owned scratch
namespace and retain local evidence. No install/staging/PDF copy is needed.
Release device in issue23. No pen/paired remote/extra key/Frida/stock hooks/new
writer/save/restart path/force-stop/firmware/originals/BOOX/merge. Existing normal
Close handoff is the sole permitted stock restart route. Data/focus/cleanup
uncertainty stops hardware; independent safe source work can continue.

If keyboard source arrives/turns, next separate gate exercises guarded logical
keys, repeats/direction/modal/Close after a fresh bounded plan/reservation. Do not
relabel prior UNKNOWN-source failure PASS or claim physical Bluetooth support.
If it still fails, use the captured actual input focus to choose one concrete
next boundary, not speculative global hook/rewrites. Physical input waits awake.
