# Native viewport: Android write-edge audit (2026-09-28)

Status: **read-only audit; no stock-reader mutation authorized**. This note
narrows the next disposable-emulator experiment. It does not certify complete
mutation coverage or permit a visual lease, Nomad insertion, pen input, or
release.

The locally retained firmware `framework.jar` was checked against the
SHA-256 pin in `NATIVE_PAGE_FIRMWARE_FIELD_MAP.md`:
`c3a525a7ef16363a93412182cce693f46dfa1395a570e9620da0d4e27a59631d`.
Its relevant method bodies have **not** been proven byte-for-byte equivalent
to AOSP. The ordering below comes from Android 11 AOSP source and is a
candidate model, not an OEM-firmware claim.

| Path | Earliest relevant change in Android 11 AOSP | Consequence for the current Port |
| --- | --- | --- |
| `ViewGroup.addView(child,index,params)` | Calls `requestLayout()` and invalidates before `addViewInner` changes the child array, parent, and attachment. | The Port's pre-add bump covers its own synchronous call. A hierarchy listener is too late; alternate add/attach paths remain outside this call. |
| `View.requestLayout()` | Clears measurement cache/sets layout flags and propagates to ancestors. | An eventual layout/global-layout callback cannot be the first mutation witness. |
| `View.measure()` / `FrameLayout.onMeasure()` | Updates measurement bookkeeping before the subclass's `onMeasure`; the frame layout may measure children. | A root `onLayout` override cannot certify measurement changes. |
| `View.layout()` | May remeasure, then `setFrame()` can invalidate and write bounds before calling `onLayout()`. | `AndroidLeasePaintRoot.onLayout()` bumps too late to fence root-frame writes. |
| Child layout/property setters | Child `layout`, visibility, params, transforms, Z and clipping can change evidence independently. | One root-layout hook cannot establish complete scene coverage. |
| Add/remove attachment | Array, parent, focus/touch, attach/detach and layout effects straddle the callbacks. | Attach-state listeners are evidence after an initiating mutation, not universal pre-write authority. |
| `dispatchDraw` / `drawChild` | Draw machinery may change dirty/animation state before any `drawChild` call. | Actual `drawChild` order is useful paint evidence, not a pre-write or final-pixel proof. |

Primary references: [AOSP Android 11 `View`](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-11.0.0_r48/core/java/android/view/View.java),
[`ViewGroup`](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-11.0.0_r48/core/java/android/view/ViewGroup.java),
[`FrameLayout`](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-11.0.0_r48/core/java/android/widget/FrameLayout.java),
and [`ViewRootImpl`](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-11.0.0_r48/core/java/android/view/ViewRootImpl.java).
`ViewRootImpl` measures before `performLayout`, runs global-layout observers
after layout, and runs pre-draw observers later still. Neither observer is a
complete pre-write fence.

## Firmware-specific boundary still missing

The stock reader root is a plain nine-child `FrameLayout`, not an
`AndroidLeasePaintRoot`. Its `DocumentActivity` binds stock PDF, digest and
handwriting children and has a global-layout listener. Page rendering,
split-crop geometry and writer refresh also cross `DocumentViewModel` and
`HandWritePresenter`; layout can indirectly affect the native pen path.
Structural XML order and the disposable PAGE 1 hierarchy capture do not
establish the stock draw order or e-ink composition. The original PDF,
native `.mark`, and stock writer/history remain authoritative.

The controlled `AndroidLeasePort.add()` records one revision before its
ordinary `addView`, while its root records a later revision in `onLayout`.
The Core requires exactly one owned-add revision through admission. Treating
that later revision as harmless, accepting `baseline+2`, or merely comparing
the eventual geometry would permit an intervening mutation or away/back ABA
to escape. Keep `hasCompleteSynchronousEvidenceMutationCoverage()` false and
the uncertified Port revision at `-1`.

## Next discriminator: synthetic no-child method-entry observation

A separately reviewed, emulator-only trial may use a fresh nine-child app
process and one exact-root method-entry observation. A custom sole parent is
the positive control: it bumps a revision before asking its root to change
width by one pixel. The observer records the old/proposed bounds and revision
**before** the framework call, forwards the original exactly once, then
records `onLayout` and a fresh completed nine-child paint. Separate fresh
processes test unchanged bounds, a direct root-layout bypass, a direct bounds
setter/offset bypass, and an away/back ABA. Bypasses must reject any claim of
complete coverage. Restore the original bounds on the app main Looper and
verify the exact nine children, scene, and two spaced completed paint samples.

PASS would establish only synchronous observation for that exact synthetic
call path. A missing/late signal, duplicate forwarding, changed sibling,
or undetected ABA is FAIL. Process death, instrumentation failure, missed
deadline, or uncertain restoration is UNKNOWN, with no automatic retry or
stock-reader inference. A process-wide replacement or emulator-only JVMTI
agent is **not** production authority: its durability, OEM compatibility,
exact-root scope, and complete setter coverage remain unproven. No child is
added in this trial. Even a PASS leaves the Native Reader insertion and pen
gates closed.
