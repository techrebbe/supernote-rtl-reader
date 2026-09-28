# Disposable nine-child lease host

This is an isolated Android API-30 test target, **not** a Supernote reader
component. It opens no PDF or `.mark`, uses no storage/network/pen API, has no
Android permissions, and is not a Nomad deployment artifact. Its only purpose
is to exercise a separately reviewed target-process visual-lease helper on an
API-30 emulator. Nothing here authorizes insertion into the stock reader.

## Fixed target and evidence

`ProbeActivity` constructs one attached `ProbeRoot` (`FrameLayout`) with exactly
nine direct original children, in a fixed order. IDs `0x71000100` through
`0x71000108` and role names come from `ProbeContract`. Child 0 is an
`ImageView` PDF *surrogate*; child 1 is a digest `TextView` surrogate; child 2
is an ink `TextView` surrogate; six further `TextView`s stand in for chrome.
All nine are app-owned references retained in `originals[]`. The app never
removes, reparents, or reorders them. A lease helper may temporarily add its
own child, so live child count can exceed nine during a trial.
`singleTask` launch mode reuses the live activity, and an independent
process-local strong-reference admission gate rejects a second instance before
it installs a root. The gate pins the admitted activity/root pair and reports
collisions and their identity in `/identity`.

The `/state` query is assembled on the main Looper. It reports every current
direct child's index, Java identity hash, class, ID, parent identity, bounds
(root and screen coordinates), visibility, alpha, Z/elevation, raw drawing
position, and layout parameters. `originals[]` is separately reported even
if a child was removed or moved. Direct reference comparisons, not identity
hashes alone, determine presence, order, and baseline equality. `ProbeRoot`
also records the last actual `drawChild` dispatch order, with a timestamp and
layout-pass number. It retains only weak references to drawn children, so an
old paint record cannot keep an injected child alive. Every command, resume,
pause/stop, focus/configuration change, global-layout pass, lease-slot change,
and child add/remove invalidates a monotonically increasing paint revision.
`paintFreshForRevision` is true only after a complete later draw; a draw that
started before an invalidation is stale. `paintFreshForLayout` and the paint
timestamp are separate supporting evidence.
The root itself logs every direct child add/remove with the child's ID and
diagnostic identity hash, including a later helper's child after Frida detaches.

`exactNineBaseline` is a **structural** comparison with the first attached,
laid-out nine-child baseline. `liveNineBaselineCandidate` additionally requires
resumed/attached activity and a fresh nine-child paint order. Neither field
is a complete rollback verdict: a test runner still needs two stable samples,
the lease event sequence, deadline measurements, and separate postflight.
The process identity includes PID, a random incarnation token, and elapsed/
wall-clock timestamps sampled when `ProbeState` initializes. These timestamps
are *not* claimed to be the kernel process-start tick. Compare PID **and**
incarnation across reconnects; process death/restart cannot be a live rollback
pass. The in-memory event ring retains at most 256 events, with monotonically
increasing per-process sequence numbers and capped text. Its `PROCESS_INIT`,
activity lifecycle, command, layout, and lease-slot events persist after a
Frida client detaches, but not after process death.
Slot changes and their events are one atomic ledger operation. `/identity`
reports slot state and event bounds from one locked evidence cut; each
`/events` row includes the same captured PID, incarnation, and window bounds.

## Query and synthetic controls

The exported test provider accepts only the app, shell, or root UID at runtime.
It exists solely for a disposable emulator. These commands are examples for a
future emulator matrix; this scaffold was **not** installed or run on a device.

```text
adb shell am start -n com.techrebbe.supernote.disposableleasehost/.ProbeActivity
adb shell content query --uri content://com.techrebbe.supernote.disposableleasehost.probe/identity
adb shell content query --uri content://com.techrebbe.supernote.disposableleasehost.probe/state
adb shell content query --uri 'content://com.techrebbe.supernote.disposableleasehost.probe/events?after=0'
adb shell content call --uri content://com.techrebbe.supernote.disposableleasehost.probe --method command --arg page
```

`command` arguments are `page`, `uri`, `render`, `layout`, `orientation`,
`cover`, `uncover`, and `finish`. The first four are independent deterministic
toggles: page cycles 1/2; URI alternates between two synthetic `probe://`
identities; render replaces a Java token and recolors the surrogate; layout
increments its epoch and alternates root padding. Orientation requests a
configuration change and increments layout epoch when Android delivers it.
`cover` starts an ordinary non-exported activity to cause pause/stop;
`uncover` finishes it; `finish` destroys the probe activity. Cover requests
carry a generation. A second cover is rejected until the first is destroyed;
an uncover before cover creation is remembered and finishes the arriving
cover immediately. Orientation delivery applies the same padding parity as
an explicit layout toggle. Commands are
main-thread dispatched with a five-second bound. A timeout has **unknown**
outcome if execution had already started, so a caller must reconnect and
inspect the event ring rather than blindly retrying.

`content call` also supports `--method identity` and `--method state`, returning
the JSON in a Bundle. `/events` supports `?after=<nonnegative-sequence>`.
Reading a provider can start a *new* process after a kill, so always compare
incarnation before attributing events to the prior process.

## Lease insertion point and remaining gate

`ProbeApplication` initializes `ProbeState` in the app's primary ClassLoader.
`ProbeState.claimLease(owner)` and `releaseLease(owner)` are main-thread-only,
identity-checked operations backed by one strong `LeaseSlot` reference. A
dynamic test helper must explicitly use this app-primary slot, not only a
static field in its own later-loaded Dex. The slot reports occupancy and
claim count through `/identity` and logs claims/collisions/releases. It does
**not** implement a lease, expiry, draw guard, lifecycle watcher, cleanup,
bootstrap, or Frida integration. No helper Dex is bundled. Those mechanisms,
the Frida detach/host-death matrix, and actual emulator observations remain
separate gates. A successful host compile proves none of them.

## Offline build and checks

Run `./test-host.ps1` for deterministic pure-Java tests of the nine descriptors,
independent toggles, bounded event ring, exact-owner slot, and manifest/source
guardrails. `./build.ps1` runs those tests, then compiles with Android platform
30 and D8 minimum API 30, packages and zip-aligns an **unsigned** APK, and
prints its SHA-256. Both scripts use new `build/` generation directories and
never invoke the inherited full probe gate, sign, install, launch ADB, or
change a device. They require a local JDK and Android SDK build-tools 35.0.0.
The built APK must be separately reviewed and signed for a disposable emulator
run. Do not reuse it on a personal device or on Nomad.
