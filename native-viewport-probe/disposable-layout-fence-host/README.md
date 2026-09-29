# Disposable layout-fence host (synthetic API 30 only)

This is a separate emulator-only package, built unsigned by default; the
reviewed runtime artifact was signed with a disposable test key. It contains
exactly nine visible `TextView` children under one `TrialRoot` inside its sole
`TrialParent`.
It does not open a reader, document, PDF, annotation, pen input, storage,
network, overlay, or Supernote process. No child is added during a trial.

`TrialParent` increments `parentPreCallRevision` synchronously before its own
`root.layout(...)` call. `TrialRoot` is a named Java class with public pure
`getRootToken()`, `getParentPreCallRevision()`, `getObservedWriteOrdinal()`,
`getLayoutCallCount()`, `getCompletedPaintCount()` and
`getStartedPaintRevision()` methods. `TrialActivity.getTrialRoot()` returns the
actual root object. An observer must compare that Java object by Java/JNI
identity, not a wrapper's `===` or an identity hash. The revision scope is
**PARENT_LAYOUT_CALL_ONLY**, never complete mutation coverage.
The root token uses a colon-free `UUID-root-UUID` form so it can be supplied as
an `adb shell content call --extra rootToken:s:<value>` string binding.

`TrialRoot.dispatchDraw` captures the actual completed `drawChild` identity
sequence. A layout request or index order is not paint evidence. A trial starts
only from a fresh, completed nine-child frame after initial focus. A changed
trial requires a completed changed frame, an app-owned parent restoration call,
a fresh completed restored frame, and a second explicitly requested completed
restored frame whose paint starts after a monotonic gap. A final live check
must match that second frame. A stale paint begun before the write or before
the second-paint request is rejected by its paint-start provenance. All commands
are one-shot per process incarnation. A replacement Activity in that process is
rejected, and a rejected command is not retried.

For `parent-plus-one`, `parent-minus-one`, `direct-root-layout`, and
`direct-root-offset`, one additional completed paint may occur after the first
restored frame but before the explicit second-paint request. These four
commands have a separate restore phase; `unchanged-bounds` and `away-back-aba`
do not, and still reject an unsolicited frame. The allowed extra paint is
retained separately as `interveningRestoredFrame` and is **non-voting**: it
must have the exact original root, scene, children, paint order, baseline
bounds, and unchanged parent/write/layout counters, with the next paint
revision and monotonic timing. The first restored frame remains immutable.
The 25 ms quiet gap is restarted from this extra frame, and a distinct
app-requested paint plus a stable final sample are still mandatory. Another
unsolicited frame, any drift, or an expired window remains `UNKNOWN`.
`paintOrderProofVersion=2` exposes this bounded event order and the second
request timestamp/revision floor for independent validation. It does not
identify the cause of the extra redraw or expand mutation coverage.

Provider authority: `com.techrebbe.supernote.layoutfencetrial.probe`.
Read-only `/identity`, `/state`, and `/events?after=<sequence>` are available to
the own, shell, or root UID. Before any external observational hook is armed,
call `ContentProvider.call("prearm", null, pins)` with exact `pid` (int),
`incarnation` (string), `activitySerial` (long), `activityToken` (string), and
`rootToken` (string) from `/state`. This Binder-thread call starts a separate
app-owned 30-second elapsed-realtime hard-stop thread **before** returning
`armToken` and `armDeadlineElapsedMs`. No second prearm is accepted. After
observer attach/load and before command, call
`ContentProvider.call("refresh", null, pins+armToken)` once. On the main Looper,
the app verifies the exact focused nine-child scene and calls only
`root.invalidate()`: no layout or child mutation. Its response gives
`refreshToken`, `paintFloorRevision`, `completedPaintCountFloor`, and
`requestedElapsedMs`. The runner must wait for a **new completed actual paint**
whose started revision exceeds that floor and whose paint began after the
request, then issue `call("command", command, pins+armToken+refreshToken)`
within the 2-second baseline freshness window. The command rechecks those
conditions, exact scene/geometry/children, and unchanged layout/write
revisions. Refresh is one-shot; an ambiguous response or absent new frame
consumes the process and is never retried. The 30-second prearm watchdog stays
armed throughout. Commands, each requiring a fresh process, are:

- `parent-plus-one` and `parent-minus-one`: request a real parent `onLayout`
  that calls the root with its width shifted by one pixel, then restore.
- `unchanged-bounds`: request the same parent call with unchanged root bounds.
- `direct-root-layout`: call the root's final `ViewGroup.layout` without the
  parent pre-call; this deliberately demonstrates a bypass.
- `direct-root-offset`: offset the root directly without a layout call; this
  deliberately demonstrates another bypass.
- `away-back-aba`: two synchronous parent-owned `root.layout` calls, away and
  back before an intervening paint; the revision must advance twice. The trial
  JSON includes the exact `abaAway` proof cut for this command and JSON `null`
  for all other command variants; no separate entry array is inferred.

`PASS` means this command's path and exact restoration were observed, **not**
that the root has complete mutation coverage. Direct-control PASS is labeled
`BYPASS_CONTROL_RESTORED`; `completeMutationCoverage` is always false. Any
ambiguity is sticky `UNKNOWN`. `currentlyValid` additionally requires the
current exact root, scene, untainted lifecycle, no pending layout, and the same
latest completed paint as the second restored frame; historical PASS alone is
insufficient. The pre-PASS trial deadline remains 5 seconds for every proof
transition. After PASS, current validity is bounded by the independent active
30-second prearm lease, not the already-completed trial deadline or a separate
paint-age grace period. `/state` reports both `trialDeadlineElapsedMs` and
`activeArmDeadlineElapsedMs`; after `finish`, PASS remains historical and
`currentlyValid` is false because the arm is no longer active.

After a verified PASS, two ordered app-owned no-op sentinels are required:
`call("sentinel", "after-disarm", pins+armToken)` after observer replacement
is reverted while its script remains loaded, and
`call("sentinel", "after-unload", pins+armToken)` after script unload. Each
uses the main Looper to call `root.layout` with identical bounds and returns
`ok`, `unchanged`, `stage`, and JSON showing exact process/root identity,
before/after live cuts, and unchanged last completed paint. A failed,
replayed, out-of-order, or timed-out sentinel is not retried. Only
`call("finish", null, pins+armToken)` after both successful sentinels disarms
the prearm watchdog, and finish rechecks the exact live nine-child scene and
same second restored completed paint on the main Looper before disarming.
`call("abort", null, pins+armToken)` is a terminal
Binder-thread self-kill; a response is not guaranteed. Neither sentinel adds
a child or grants complete mutation authority.

A main-Looper trial deadline uses `SystemClock.elapsedRealtime` on dispatch;
a Handler's uptime scheduling is not treated as proof of timeliness. The
shorter trial watchdog is independent of the main Looper and kills the exact
disposable PID if two-paint restoration cannot complete. The separate prearm
watchdog remains live even after trial PASS, through both sentinels, until
explicit `finish`. It also self-kills the exact PID if an observational hook
stalls before command, during a sentinel, or after PASS. On
process death there is no live-restoration claim. Root/Activity loss allows
restoration only of the exact original still-attached root; otherwise it is
quarantined and the in-flight watchdog terminates the process. Root/parent
detachment is a sticky taint even if the same objects later reattach. After a
completed PASS, later drift invalidates `currentlyValid`; without both
successful sentinels and `finish`, the prearm watchdog still terminates the
process at its hard deadline. No child was introduced, and no replacement root
or other app is touched. This does not implement or install a Frida hook. An
app-owned thread cannot run while the entire process is OS-frozen; an external
runner must also treat absent deadline evidence as UNKNOWN.

Run `test-host.ps1` for pure-Java evidence tests and static isolation checks.
Run `build.ps1` for the same checks plus an offline API-30 unsigned APK build.
Both create fresh ignored `build/` generations and do not sign, install, run
ADB, or operate a device. No emulator trial result is claimed by source/build.

`sign-emulator.ps1` accepts only this host's ignored unsigned APK and an
independently reviewed SHA-256 assertion. It creates a fresh seven-day
emulator-only key, signs into a separate ignored generation, and verifies the
single signer plus exact synthetic package/version. It never uses the user's
Android debug key and never contacts a device. Each invocation creates a new
certificate; it is **not** upgrade-compatible with a previously installed
test APK. Replacing that exact disposable package requires a separately
reviewed emulator-only uninstall/install, which erases the synthetic app's
private state. No such operation is implied by building or signing.
