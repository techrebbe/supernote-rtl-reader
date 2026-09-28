# Disposable tile trial host

The first isolated API-30 emulator run and its exact 9 → 10 → 9 evidence are
recorded in [EMULATOR_VALIDATION.md](EMULATOR_VALIDATION.md). This does not
authorize installation on a Supernote or prove native-reader compatibility.

This is a third, isolated Android API-30 test app with package
`com.techrebbe.supernote.leasetiletrial`. It is not a reader integration, a
`TargetOwnedVisualLeaseCore` Port, or a PDF/pen test. It declares no Android
permissions and contains no storage, network, overlay, or document path. Do
not install it on a Supernote/Nomad or use it with a personal document.

The Activity retains nine visible synthetic `TextView` objects under one
`FrameLayout`. Its root records the identities and order of actual `drawChild`
calls only after a stable `dispatchDraw` pass completes. A completed order is
never inferred from indices or carried across a hierarchy mutation. The
one-shot `start-tile` command posts an app-owned two-second Handler expiry
**before** ordinary indexed `addView(tile, 1, ...)`. The colored tile is
non-clickable, non-focusable, and accessibility-inert, but this scaffold does
not claim input transparency. `stop-tile` and expiry remove only the exact
retained tile object from its exact root. The root accepts an add/remove layout
only if root geometry and all nine original identities, parents, and evidence
remain unchanged; any other layout, lifecycle/focus loss, parent ambiguity,
or rejected callback is sticky `UNKNOWN`. There is no second start in the
same Activity or process incarnation.

The `/state` query reports PID plus random process incarnation, Activity/root
tokens, structural child identities and metadata, last completed actual paint
order, and retained baseline-nine, added-ten, ten-paint, removed-nine, and
nine-paint cuts. Immediately after add/remove, `current.paintCount` is zero
until a genuinely new completed pass. The event ring retains 256 entries with
monotonic sequence numbers; compare PID **and** incarnation and require a
gapless event window. Provider reads after process death can create a new
process; they cannot prove live restoration of the prior one. A provider
command timeout has unknown outcome: inspect identity/events before any
further action. Only app, shell, and root UIDs may call the provider. Every
`command` call requires `expectedPid` (integer), `expectedIncarnation`,
`expectedActivityToken`, and `expectedRootToken` (strings) in its Bundle;
these are checked again on the main thread immediately before mutation.
Missing or stale values reject the command. A controller must read a fresh READY
paint, pin those identities, and complete explicit stop and postflight before
the two-second deadline; timeout/late completion is not a success. No reusable
controller is bundled here; the recorded emulator run used a one-off local
controller.

The model reports `RESTORED` only after the exact 9 → 10 → 9 structural
sequence and actual ten- then nine-child paint frames. An early stop still
attempts exact-object removal, but cannot manufacture missing ten-paint
evidence and ends `UNKNOWN`. Later redraws revalidate the restored nine-child
paint and revoke `RESTORED` on drift. This is synthetic draw-dispatch evidence, not a
pixel, input, reader-rollback, or hardware PASS. No automatic retry or repair
is attempted on ambiguity. If exact removal or parent identity becomes
ambiguous, the app records `VISUAL_QUARANTINE` and finishes its own disposable
Activity without claiming live restoration; prior pixels may remain until
the window goes away.

`test-host.ps1 -Jdk <JDK>` runs deterministic pure-Java evidence, timing,
layout-fence, one-shot, and source/manifest isolation checks. `build.ps1`
requires a JDK plus Android SDK platform 30/build-tools 35.0.0, reruns those
tests, and creates a fresh **unsigned** APK under ignored `build/`; it does not
sign, install, launch, or call ADB. Neither script is an emulator observation.
The package and provider authority are distinct from both earlier disposable
hosts. Emulator use requires separate review and authorization.
