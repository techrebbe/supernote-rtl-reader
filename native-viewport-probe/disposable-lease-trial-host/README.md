# Disposable no-child layout preflight

This is a **separate Android API-30 emulator app** and provider. It does not
modify or launch the existing `ProbeActivity`, install a lease child, open a PDF,
touch annotations, request root, or access the Nomad. Its manifest declares no
permissions. The only trial command requests one real layout of a fixed
nine-visible-child synthetic scene.

The first gate answers a narrow question: after a completed paint of the nine
original views, can a controlled layout callback leave their identity,
geometry, scene, and evidence revision unchanged, then produce another actual
completed nine-child paint? A successful result includes a second stable sample
at least 25 ms later. `dispatchDraw` and actual `drawChild` calls supply the
paint witness; neither a pre-draw listener nor inferred index order counts.

The command is accepted only for a resumed, focused, attached Activity with a
fresh completed nine-child paint, no outstanding layout request, and no earlier
trial in that Activity. It calls `requestLayout()`; the real `onLayout` callback
may skip `FrameLayout.onLayout` **only** when all nine children are already
laid out, no child requests layout, root bounds and scene are unchanged, and
the previous paint/revision remains current. Any other layout uses the normal
path, invalidates the trial, and increments the mutation ledger before laying
out children. Pause, stop, detach, focus loss, activity reuse, stale paint,
extra layout, timeout, or uncertain evidence reports `UNKNOWN`. There is no
automatic retry. The app never adds a tenth child.
Activity reuse or lifecycle loss also sets a sticky session taint, even before
a trial starts or after a historical `PASS`. A tainted instance cannot start
another trial or report `currentlyValid=true`.
On the first eligible window-focus gain, the host requests one additional real
paint. The runner waits until a completed paint revision exceeds the revision
at that focus gain before anchoring its event witness or sending the command.
The command itself also rejects any earlier paint. This does not extend the
2-second baseline freshness limit.

The provider accepts only its own, shell, or root UID. Its distinct authority
is `com.techrebbe.supernote.leasetrial.probe`. Queries return process
incarnation, live state, before/onLayout/after paint cuts, exact original
identity and geometry evidence, paint revisions, result, and a bounded event
ring. `PASS` records the completed historical trial; `currentlyValid` is a
separate live fence and becomes false if subsequent layout, scene, paint, or
lifecycle state differs. The runner requires both. The command vocabulary is
only `preflight-noop-layout` and `finish`.
Missing paint/proof cuts are explicit JSON `null` values, so initial polling
cannot mistake absent keys for a paint witness. After reading events, the
runner takes a final live sample and rejects drift or an unexpected event tail.

## Offline checks and build

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\test-host.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\emulator-gate.ps1 -ParserSelfTest
```

`build.ps1` creates a new generation directory and an **unsigned** APK. It
does not sign, install, or invoke ADB. After the exact source/build review,
`sign-emulator.ps1 -UnsignedApk <generated unsigned APK>` can create an
ephemeral, seven-day local test keystore and sign one copy. That keystore,
signed APK, and all evidence stay under ignored `build/`; the script never
reads the user's Android debug keystore or GitHub secrets. The signing script
also never installs or invokes ADB. Preserve the printed signed APK hash and
certificate hash for review before an emulator run.
Offline scripts reject reparse points in ignored build/evidence paths; the
host tests cover lexical escape and a disposable junction.

The emulator runner does not install; it requires that reviewed signed APK
and its exact SHA-256 and signer-certificate SHA-256. It is hard-pinned to `emulator-5554`, the
`RTL_Lease_API30` AVD, API 30, and `ro.kernel.qemu=1`. Before touching the app,
it proves the installed APK bytes equal that reviewed local artifact. It then
performs one bounded trial and saves raw ADB records plus a summary in a new
evidence directory. No runner/device execution is part of this change.

## Authority limit

This is **observation**, not insertion authorization. On API 30,
`ViewGroup.layout(...)` is final. A subclass cannot guarantee a ledger bump
*before* Android changes root bounds on an unrelated parent layout. This app
therefore rejects a changed root/scene when it reaches `onLayout`, but does
not claim complete pre-mutation authority for a future visible child. A
separately reviewed lower-level boundary is needed before any lease insertion.
Nor does this nine-visible-child emulator scene prove stock compatibility:
the pinned Supernote document hierarchy has a `GONE` direct child, so its
actual paint order requires its own read-only observation.
