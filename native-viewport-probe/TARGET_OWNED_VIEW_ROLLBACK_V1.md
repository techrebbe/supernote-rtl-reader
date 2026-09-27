# Target-owned visual-child rollback v1: design gate

Status: **design only; NO-GO for Nomad insertion.** This note specifies the
minimum rollback contract for the one-page, no-pen visual experiment in
`IN_PROCESS_VISUAL_HOST_V1_GATE.md`. It does not authorize installing code,
inserting a view, changing a native reader, or making the PDF/page writable.
The read-only runtime hierarchy capture, independent review, and a fresh
hardware reservation must precede any mutation trial. A candidate insertion
slot inferred from stock XML is not runtime authority.

## Ownership boundary

The desktop runner and Frida may authenticate a disposable PDF, attach to the
exact reader process, deliver a pinned helper, request start/stop, and collect
evidence. **They cannot own rollback.** A host `setTimeout`, Frida JavaScript
timer, script unload callback, RPC finally block, ADB disconnect handler, or
process exit is insufficient: Android can retain an inserted `View` after its
Frida client/script disappears. Conversely, death of the document process
destroys its view hierarchy but must not be presented as successful *live*
restoration of the original reader.

`NativePageHostLifecycle.java` models an external display host's
destroy/release semantics. That host-task cleanup is not proof that an
in-process child was removed from `DocumentActivity` after Frida detaches;
this design must not reuse it as the rollback owner or success witness.

One reviewed, process-local Java/Android `TrialLease` must own exactly one
ordinary visual child, its in-process monotonic expiry, drift watchers, and
idempotent cleanup. Its code and callbacks must remain callable after the
Frida session detaches and the desktop runner terminates. It must use the
document process's main `Looper` for all hierarchy reads and writes. No
hook, setter, or replacement of native page, pen, save, tool, navigation,
history, or `.mark` authority is part of this trial. No input-routing claim
or physical-pen test follows from a successful visual cleanup.

### Bootstrap is a separate proof, not an implementation assumption

Two possible delivery mechanisms need independent review:

1. A pinned, minimal Dex loaded into the **document process** (for example,
   an API-compatible in-memory class loader) whose Java `Handler`, callback,
   and lease objects are rooted by Android/Java references independent of
   Frida JavaScript. Bundle bytes, source digest, ABI/API compatibility,
   class-loader lifetime, constructor behavior, and unload/detach behavior
   require exact reproducible checks. A `Java.registerClass` object or a
   callback that still delegates to Frida must not be presumed durable.
2. An already-installed, narrowly scoped native companion/LSPosed entry
   point could provide the target-process helper, but its package, signer,
   version, activation scope, and ordinary-reader side effects would need a
   separate explicit gate. A companion in a **different** Android process
   cannot own the reader's `View` or main-loop cleanup. Installing or
   enabling such a package is outside this design note.

Neither option is selected yet. If a tiny helper cannot prove target-process
execution **and** cleanup after Frida detach/host death in a disposable
helper-app test, insertion remains **NO-GO**. Do not weaken this by extending
the host timeout or relying on a later device reboot.

## Pre-insertion lease and single-writer rule

Before insertion, the host independently verifies the disposable PDF's
no-follow descriptor, full hash, and absent/unchanged `.mark` state. The target
main thread then authenticates an immutable snapshot of only the state it can
observe and binds the host-attested file-identity token:

- exact process PID/start identity; resumed `DocumentActivity` Java identity,
  task/display, attached root `FrameLayout` identity, window attachment;
- exact ordered nine-child set, each child's Java identity, class, ID,
  parent, raw/effective drawing-order evidence, visibility, bounds,
  elevation/Z, and relevant layout parameters; field-to-child identity for
  PDF, digest, and handwriting views;
- exact disposable PDF/URI, the host-attested descriptor/hash token, native
  source-page identity, current bitmap/render identity, orientation,
  root/window geometry, page-fit state, and layout epoch. The target does not
  re-hash file bytes or promote the token into its own file-integrity proof.

Any getter missing, unstable, non-main-thread-only, or contradictory to the
two-sample hierarchy gate is **NO-GO**. Native bitmap identity is an open
question: a Java field reference may be replaced while depicting the same
page, and a stable reference may be repainted. The runtime observation must
establish the strongest available page/render witness before defining its
comparison; a guessed surrogate cannot authorize insertion.

Acquire one process-local trial slot atomically before constructing a view.
Reject a second start while a lease is `PREPARED`, `INSERTED`, or `REMOVING`;
never remove an older trial's view to admit a newer one. The lease has a
random, process-local trial ID and a direct reference to its uniquely typed
owned `View`. A tag, integer ID, child index, or drawing-order position is
diagnostic only, never removal authority. Register the expiry and lifecycle
cleanup callbacks **before** `addView`, then reauthenticate the snapshot and
insert exactly once at the separately proven slot. If an exception occurs
during or immediately after `addView`, transition into the same cleanup path
before reporting failure. `addView` may attach the owned object and then
throw before the lease records `INSERTED`; cleanup must inspect that exact
object's parent even from `PREPARED` and remove it if attached to the
authenticated root. An unexpected parent is quarantine, not permission to
remove another view. No stock child is removed, reparented, relaid out, or
given altered parameters.

The child must be non-focusable, non-clickable, and have no accessibility
action, input listener, pen listener, or native-page authority. Its touch,
hover, generic-motion, and key handlers return unhandled. That is not by
itself proof of input transparency: Android `ViewGroup` dispatch, pen-service
routing, and accessibility behavior require isolated tests. Physical pen is
excluded from this visual experiment.

## In-process expiry and drift response

Use a short, fixed lease lifetime measured against
`SystemClock.elapsedRealtime()` (monotonic and sleep-inclusive), stored in
the target lease. A target-owned Java `Handler` on the main `Looper` schedules
expiry and bounded health checks; each callback compares the current
monotonic time before doing anything else. The owned view's `onDraw` must also
check this deadline before painting, because an expired draw can run before a
queued expiry callback after a main-loop stall. This deadline guard is distinct
from the still-unproven native page-epoch guard. Activity pause/stop/destroy,
window/root detach, page/URI/bitmap/render change, rotation/split change,
geometry/layout epoch change, and an explicit host stop all converge on
`requestCleanup(reason)`. A new source page must **never** inherit the child.
Any such drift makes the visual result UNKNOWN until removal and external
postflight are verified; lifecycle teardown is not a live rollback PASS.

A `Handler` callback cannot execute while the target main thread is blocked.
The contract is therefore *cleanup by the next live main-loop dispatch*, not
an absolute wall-clock guarantee through an indefinitely frozen UI thread.
The bounded helper-app tests must measure expiry latency under normal load,
main-loop delay, sleep/resume, and Frida/host detachment. If the UI loop fails
to process the deadline within the reviewed bound, or no independent
in-process evidence can show the callback remained armed, classify the trial
UNKNOWN/NO-GO and quarantine; do not attempt pen input or force-stop the
reader. A separate background watchdog may observe lateness, but it cannot
remove an Android child off the main thread and is not a substitute for the
main-loop cleanup owner.

Polling alone cannot prevent a stale frame if stock page state changes
between polls. A draw-path check could guard a **new** draw, but cannot erase
pixels already composited if stock state changes without invalidating the
owned view. A synchronous native pre-transition invalidation/epoch source is
therefore a separate hypothesis to prove before claiming safe behavior across
page or layout changes. Until then, the Nomad visual trial remains one fixed
page with no intentional navigation or rotation; any observed or suspected
drift is UNKNOWN and requests cleanup, never a transition PASS. Helper-app
simulated drift cannot authenticate the stock reader's transition path.
Layout and lifecycle callbacks should request cleanup immediately, but cannot
replace this evidence. Likewise, an unexpected stock redraw or writer/save
event is a failure only if a passive, reviewed event source identifies it;
without one, claim no writer silence beyond the external PDF/`.mark` witnesses.

## Idempotent, exact-object removal

All cleanup triggers serialize on the main `Looper` into one state machine:

`PREPARED -> INSERTED -> REMOVING -> REMOVED` or `QUARANTINED`.

`requestCleanup` is idempotent: concurrent deadline, lifecycle, layout,
host-stop, and failure callbacks may enqueue it, but only the first main-loop
transition performs removal. In `PREPARED`, inspect the owned object's actual
parent: if unattached, release its watchers/slot; if attached to the exact
root, remove it as an interrupted insertion; otherwise quarantine. An
`INSERTED` lease checks that its **same owned object** is attached to the
**same authenticated root** and calls
`removeView(ownedView)`; it never uses `removeViewAt(1)`, a tag lookup, or
clears the root. If the owned child moved to another parent, disappeared
unexpectedly, or an impostor occupies its position, do not mutate that other
hierarchy: mark `QUARANTINED` and collect read-only evidence.

For a still-live root, the target helper runs a fresh main-thread structural
comparison to the original nine children: exact object identities, order,
classes, IDs, parents, drawing-order/Z, geometry, layout parameters, and
available page/URI identity. Account for expected system layout settling with
a bounded two-sample equality check; never simply assert
`getChildCount()==9`. The helper retains a bounded cleanup event for a later
host query. It must not hash the source PDF or infer `.mark` integrity on the
UI thread. A fresh independent **host** postflight after reconnect must check
the exact source descriptor/hash and `.mark` state before the overall trial
can pass. If the host never reconnects, file integrity remains UNKNOWN even
if the target reports structural cleanup. Unregister listeners and cancel
callbacks only after removal and the appropriate structural verification;
the lease must remain rooted until then. A second cleanup request after
`REMOVED` is a no-op; after `QUARANTINED` it must not guess a repair.

Activity/root destruction may make live nine-child comparison impossible.
Remove the exact owned object before teardown when the lifecycle permits, but
classify an unobservable teardown as lifecycle abort/UNKNOWN, not live
restoration PASS. Process death is process loss and likewise cannot produce
a live nine-child PASS.

If rollback cannot be observed exactly, outcome is UNKNOWN even if the view
seems gone. Stop further trials, preserve diagnostics and device state, and
request a deliberate recovery decision. Do not use force-stop, reboot,
cache clearing, or `.mark` replacement as an automatic rollback. A reader
process death is separately recorded as process loss, not the nine-child
restoration PASS.

## Disposable helper-app matrix before any Nomad insertion

Build a tiny, controlled Android app with a nine-child `FrameLayout`,
replaceable page/URI/bitmap/layout identities, lifecycle toggles, and event
logging. Use an emulator or a dedicated disposable app process, **not** the
Nomad or a personal PDF, to test the exact packaged helper and bootstrap
mechanism. Assertions inspect the app's view hierarchy and event sequence
from inside the target process, not only a host script's return value.

| Trial | One changed condition | Required result |
| --- | --- | --- |
| Baseline | No insertion | Nine exact children; no helper effects. |
| Normal lease | Add then explicit stop | Exactly one owned child, then nine exact originals. |
| Deadline | Add, no host stop | Target callback removes it within the measured bound. |
| Frida detach | Detach immediately after insertion | Target deadline still fires; exact restoration. |
| Host death | Kill only the desktop/Frida client | Target deadline still fires; exact restoration. |
| Lifecycle | Pause, stop, destroy separately | Exact-object cleanup before teardown when observable; otherwise lifecycle abort/UNKNOWN; no child carried into a new activity. |
| Authority drift | Change page, URI, bitmap, layout, orientation separately | Target cleanup/quarantine and UNKNOWN; simulated drift does not prove stock pre-transition invalidation. |
| Bootstrap collision | Start twice or stop twice | One lease; idempotent exact-object removal. |
| Replacement/race | Remove/move owned view or insert impostor | No removal of unrelated view; QUARANTINED. |
| Failure injection | Throw before, during, after `addView` and `removeView` | No silent success; exact restoration or quarantine. |
| Main-loop delay | Stall UI across deadline; then release | No draw after expiry; measured next-dispatch cleanup; UNKNOWN if bound missed. |
| Sleep/resume | Suspend across elapsed-time deadline | Expired lease removed before another draw. |
| Process death | Kill/restart only helper app | Classify process loss, fresh nine-child start, no false rollback PASS. |
| Input isolation | Tap, hover, generic motion, key, accessibility in helper app | Stock simulated sibling receives expected events; no child action. |

Use deterministic event IDs, monotonic timestamps, fault injection, and
before/after hierarchy snapshots. Include a test with the Frida script
unloaded and another with the host process gone; proving only a host-controlled
timer is a test failure. Pin the helper Dex/APK hash and bootstrap revision
used in this matrix. Separately verify the target Android API level and
actual package-loading constraints before proposing that mechanism for the
reader. A helper-app PASS does not by itself authenticate the stock reader's
runtime child order, prevent indirect pen-service effects, or authorize a
Nomad insertion.

## Promotion decision and open questions

The next decision is still **read-only**: obtain a fresh, successful stock
hierarchy capture after its current diagnostic is reviewed. Then review the
helper implementation and run the complete helper-app rollback matrix.
Only with both PASS results, a scoped mutation plan, independent exact-diff
review, and a fresh device/PM reservation within the user's existing
authorization may one disposable-PDF, no-pen FULL visual
trial be proposed. LEFT, RIGHT, and return-to-FULL are separate later runs;
any UNKNOWN halts the sequence. No merge follows without the user's decision.

Open questions to resolve before implementation:

1. Which exact Android/firmware mechanism can load and root plain Java
   cleanup code in `com.supernote.document` without retaining Frida JS?
2. Which safe native bitmap/page epoch is both observable and sufficient for
   draw-time drift rejection? Does a bitmap object identity alone fail?
3. What main-loop deadline and measured lateness bound are acceptable on the
   e-ink device, including suspend/resume and slow native rendering?
4. Can exact root-child geometry/layout be restored after the layout pass
   caused by `addView/removeView`, with no indirect pen/save side effects?
5. Does Android input/accessibility dispatch truly leave the underlying
   native chrome and handwriting untouched with the chosen child type?

Until those are answered with evidence, keep insertion and pen trials NO-GO.
