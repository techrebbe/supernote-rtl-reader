# Display-0 stock hierarchy observation v1 (offline candidate)

This is a diagnostic, not a visual-host installation gate. It has not run on
the Nomad. It neither inserts a View nor proves that a child index is the
effective compositing position. The sibling external-overlay prototype is not
the target of this observation.

The one-shot observer inspects the pinned stock `DocumentActivity` and its
`mContentView` `FrameLayout` using one heap walk and two UI-thread samples. It
records root/child class, ID, order, bounds, visibility, and binary64 Z; the
direct `mImage`, `digestImage`, and `handWriteView` field identities must match
three different children in PDF → digest → pen index order. Every child must
report that root as its parent. The samples must match in identity and value.
Visible child bounds must have positive area; `GONE`/`INVISIBLE` children may
report zero-size raw bounds, but inverted bounds are rejected.
`customDrawingOrder` is raw state; `effectiveCompositingAdmitted` is always
false. A mismatch fails closed, including process/document drift or an
unavailable getter.

The host runner reuses the fixed serial, disposable PDF, no-`.mark`, stock
task/process, pinned firmware/APK/framework, and no-Frida-server/forward
preflight and postflight. It starts only its own short-lived server/forward,
unloads and detaches its exact script, and verifies cleanup and unchanged
reader/PDF afterward. This can briefly interrupt the native reader, so only
`--build-only` is authorized for the offline checkpoint. `--preflight-only`
and especially `--run` require a fresh shared hardware reservation. No
original or personal document is eligible.

Before authorizing any in-process visual child, independently authenticate
the complete expected child set (including exact numeric IDs/classes and
indices), drawing-order behavior when custom order or nonzero Z is present,
the main-thread callback on real hardware, and an exact add/remove rollback
contract. The first live hierarchy capture is read-only. A separate visual
trial would need its own review and hardware gate; pen input must remain out
of scope until the one-page visual geometry is proven.

Offline checks:

```text
node native-viewport-probe/test_native_page_display0_hierarchy_observer.js
py -3.12 native-viewport-probe/test_native_page_display0_hierarchy_trial.py
py -3.12 native-viewport-probe/native_page_display0_hierarchy_trial.py --build-only
```
