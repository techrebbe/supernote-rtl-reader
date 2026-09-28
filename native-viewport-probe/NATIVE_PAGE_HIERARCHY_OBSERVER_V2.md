# Display-0 stock hierarchy and predicted order v2

Status: **one bounded read-only Nomad capture passed on 2026-09-29**. This
replaces the v1 wire contract, not its historical evidence. It does not
authorize a visual child, pen input, PDF mutation, or release.

The observer uses one heap walk and two UI-thread samples of the exact
`DocumentActivity`, disposable URI and zero-based `currentPage == 0` (PAGE 1).
It requires the pinned nine direct children of the plain
`document_main_layout` `FrameLayout`, their resource IDs/classes/parents and
the PDF/digest/handwriting field identities. It records each child's raw bounds,
visibility, binary64 `getZ()` and direct inherited `View.mCurrentAnimation`
reference presence. The PDF, digest, and handwriting children must all be
visible. On the root it records `isHardwareAccelerated()`, the
custom-order flag (cross-checked against `ViewGroup.mGroupFlags`), and direct
presence of `mTransientViews`, `mTransientIndices`, `mDisappearingChildren`,
`mVisibilityChangingChildren`, `mTransitioningViews`, and `View.mOverlay`.
The two samples must match, including the original object identities. Missing
or inaccessible fields reject the observation; the code never calls
`buildOrderedChildList()`, `getOverlay()`, `draw()`, `invalidate()` or a setter.

The `frameworkPredictedDirectChildOrder` is populated only when custom order is
off, all direct-child Z values compare equal to zero, no child animation is
present, the root's layout-animation flag is clear, and all sampled
transient/disappearing/visibility-changing/transition/overlay references are
null. In that narrow case it is the ascending indices of **visible** direct
children. A non-null reference, even to an empty cached list/overlay, leaves
the prediction `null`; no method is called to inspect or clear it. The
prediction models the simple traversal in Android 11 AOSP `ViewGroup` and
does not claim a completed OEM draw. The pinned OEM framework bytecode was
separately checked against the exact SHA-256
`c3a525a7ef16363a93412182cce693f46dfa1395a570e9620da0d4e27a59631d`:
its `dispatchDraw`, `isChildrenDrawingOrderEnabled`, field declarations, and
`View.getAnimation()` follow the sampled-field model. That static check does
not elevate a predicted traversal to an observed draw. `actualDrawObserved`, `finalPixelsAdmitted`,
`effectiveCompositingAdmitted`, and `hardwareAdmission` are always false.

In AOSP Android 11, `dispatchDraw` has transient and disappearing-child paths,
and calls `drawChild` for children that are visible **or** animated. Its
software path calls `buildOrderedChildList`, which mutates the cached
`mPreSortedChildren`; the RenderNode recording path leaves Z reordering to the
hardware renderer. `View.isHardwareAccelerated()` reports window attachment,
not the Canvas used for any specific draw. Thus a stable v2 snapshot cannot
prove a naturally completed `drawChild` sequence, actual overlap/occlusion,
rendered pixels, SurfaceFlinger composition, or the e-ink panel result.
`dumpsys gfxinfo` supplies frame timing, not per-child drawing order. A real
paint or pixel claim needs a separately reviewed observation mechanism.

Primary framework references: [Android 11 AOSP `ViewGroup.dispatchDraw` and
`buildOrderedChildList`](https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android-11.0.0_r48/core/java/android/view/ViewGroup.java),
[Android 11 AOSP `View.isHardwareAccelerated` and `getAnimation`](https://raw.githubusercontent.com/aosp-mirror/platform_frameworks_base/android-11.0.0_r48/core/java/android/view/View.java),
and [Android hardware-accelerated drawing model](https://developer.android.com/topic/performance/hardware-accel).

Offline checks (use the available Python 3.12 executable):

```text
node native-viewport-probe/test_native_page_display0_hierarchy_observer.js
python native-viewport-probe/test_native_page_display0_hierarchy_trial.py
python native-viewport-probe/native_page_display0_hierarchy_trial.py --build-only
```

The bounded hardware gate used only the disposable
`/storage/emulated/0/Document/RTL_DISPLAY0_CAPTURE_20260927.pdf` PAGE 1 in
landscape on Nomad serial `SN078C10015092`. Independent code review was GO.
The preflight passed, exactly one `--run` exited 0, and a separate postflight
preflight passed. The v2 source SHA-256 was
`8f1807c4acd75901f4ac1bb79d671e6005763ffea729b6491dddf86f85e5b1e0`,
bundle SHA-256 was
`475e19b8e98448725dca4936922f875e4734b168ea4914245f6839642c75b24d`,
and the device-bound manifest SHA-256 was
`70340225a0363ac99d3c59e658910d678ab3ecfa5ae85e40e51461e80bc34f82`.

The live root was `FrameLayout` ID `2131296783`, bounds `[0,0,1872,1404]`.
Nine direct children were stable across both UI-thread samples: PDF/digest/pen
at indices `0/1/2`; child `7` was `GONE`. Every child had zero Z, no child
animation was present, custom order was off, and transient, disappearing,
transitioning, visibility-changing, and overlay references were absent. The
framework-predicted visible direct-child traversal was `[0,1,2,3,4,5,6,8]`.
The record still had `actualDrawObserved=false`, `finalPixelsAdmitted=false`,
`effectiveCompositingAdmitted=false`, and `hardwareAdmission=false`.
The runner reported `readerStable=true`, `pdfUnchanged=true`, `markAbsent=true`,
`serverRemoved=true`, and `forwardRemoved=true`. No pen, page change, package
installation, view insertion, PDF or `.mark` mutation occurred. The one-shot
device reservation was [released in issue #23](https://github.com/techrebbe/supernote-rtl-reader/issues/23#issuecomment-5880030779).

The remaining gate is not another identical snapshot: prove a target-owned
restore boundary and then a genuine native page/writer viewport before claiming
that FULL/LEFT/RIGHT presentation is safe. A visual overlay alone is not that
proof.
