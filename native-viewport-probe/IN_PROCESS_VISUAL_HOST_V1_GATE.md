# In-process native-page visual host: bounded gate

Status: **offline design only**. No reader mutation, installation, pen trial,
or release is authorized by this file. The separate `shadow-page-overlay/`
prototype remains an offline fallback; it is not the next Nomad trial because
an external opaque window would cover native ink and chrome.

## Hypothesis and fixed authority

Keep the one existing `DocumentActivity`, source PDF, current page,
`DocumentViewModel`, `HandWritePresenter`, note, pen service, history, and
`.mark` save authority unchanged. Draw one independently rendered source page
as an ordinary child `ImageView` inside the existing root `FrameLayout`, above
only the stock PDF image and below native digest, handwriting, and controls.
This tests **visual composition**, not input mapping or saved annotations.

The pinned firmware's `activity_document.xml` has nine direct children of
`document_main_layout`: stock PDF at XML index 0, digest at 1, handwriting at
2, then scale/chrome and other overlays. `DocumentActivity` binds those views
from that root on both activity-creation paths. XML order is only a candidate
slot, not runtime proof; custom drawing order, Z, or a replaced child would
invalidate the hypothesis.

The source for this gate is only the SHA-verified disposable
`RTL_DISPLAY0_CAPTURE_20260927.pdf`. Never select a personal PDF. Keep the
first page and its native page identity fixed. Do not turn pages, rotate, or
use a pen during a visual trial.

## Gate 0: read-only runtime hierarchy authentication

Before creating any view, a separately versioned one-shot observer must reuse
the fixed-serial, exact-PID/start-time, firmware, document-URI, PDF hash,
task/display, deadline, detach, and before/after `.mark` checks from the
successful display-0 graph trial. It must retain exactly one resumed
`DocumentActivity` and sample the *same* root twice on the UI thread.

Required runtime facts:

- `mContentView` is the attached `document_main_layout` `FrameLayout`.
- Exactly nine direct children retain the expected IDs, classes, parent,
  order, visibility, and bounds. Children 0, 1, and 2 are the same Java objects
  as the activity's PDF, digest, and handwriting fields, respectively.
- Effective drawing order and Z put digest, handwriting, and chrome above the
  proposed index-1 insertion slot. No custom ordering, unexpected elevation,
  `SurfaceView` in the relevant PDF/digest/handwriting subtree, or child
  substitution is present.
- The two samples agree, and the stock task, page, PDF, bitmap and lifecycle
  identities match before and after attachment.

Missing, changing, ambiguous or contradictory evidence is **NO-GO** for
insertion. Do not edit the already-pinned display-0 graph observer/bundle in
place merely to add this experiment.

## Gate 1: one view, no pen

Only after Gate 0 and an independent exact-diff review, a separate
mutation-authorized, deadline-bounded one-shot diagnostic may add exactly one
uniquely owned ordinary `ImageView` subclass
at authenticated child index 1 on the main thread. It must not hook or call
stock page, pen, save, navigation, or tool setters; alter, reparent, or replace
any stock child; or install an LSPosed module. It must independently verify
the pinned disposable PDF's read-only, no-follow descriptor, inode, size and
full hash before and after rendering. Its one owned view must draw an opaque
white canvas over the **entire root** and fit the complete source page only
inside the computed FULL/LEFT/RIGHT rectangle. Otherwise the stock cropped
PDF at child 0 could remain visible in unused margins or the opposite half.
The owned view must have no focus, click, custom input listener or
accessibility-action authority. Its overridden touch, hover, generic-motion
and key handlers must explicitly return unhandled, with isolated Android
ViewGroup fall-through tests; `setClickable(false)` alone is not
input-transparency evidence, and this does not establish physical-pen routing.
Physical-pen exclusion remains active.

First present one fixed page in **FULL only**. Collect the hierarchy, native
graph and screenshot, plus PDF and absent-`.mark` witnesses. Only after FULL
insertion and removal both pass may a separate run test LEFT, RIGHT, then
FULL while the stock reader keeps the same page/session.
The bitmap must not be accepted merely because it looks centered: source-page
corners, aspect ratio, structural native digest/handwriting/chrome stacking,
white masking of the unused root area, e-ink refresh,
and any stock redraw that overwrites the inserted child must be checked.

`addView()` can itself trigger layout/handwriting refresh on this firmware.
The diagnostic must not call stock pen setters **directly**, but the stock
global-layout/HandWriteView path may indirectly notify the pen service.
Inventory that unavoidable side effect before hardware mutation, collect its
events in the trial, and abort on any unexplained writer or save change.
Before insertion, the diagnostic therefore needs a reviewed rollback design:
on success, timeout, pause/stop/destroy, page/URI/bitmap change, split/rotation
or layout drift, remove *only* its owned child on the main thread. Verify the
original nine children, exact identities/order/parents/Z, task/page and source
PDF/`.mark` state before detaching. A Frida unload or process exit alone does
not remove a view retained by Android. The design also needs a target-process
expiry/cleanup mechanism that survives a host/Frida-client failure; without
one, insertion is **NO-GO**. If cleanup cannot be proved, stop and quarantine
the device state; do not force-stop the stock reader or continue to pen testing.

Visual PASS requires the full page in each rectangle, native chrome visibly
above it, structural digest/handwriting stacking, stable original reader/page
authority, and exact
hierarchy and file restoration. Any clipped/stretched/stale page, hidden
native layer, unexpected native event, or uncertain cleanup is FAIL/UNKNOWN,
not partial success.

## Later gates, only if visual PASS

1. Prove one physical stroke in one half, immediate/wet location, saved
   original-page coordinates, and reopen in the untouched native reader.
2. Test both erasers, Undo/Redo, lasso move/resize/commit, and text selection/
   highlighting as separate one-variable trials. Validate persisted meaning
   and geometry, not only screen pixels or `.mark` hashes.
3. Test writer focus separately from physical swipes, toolbar page commands,
   and links. Add a second simultaneously represented page only after the
   one-page writer gate passes.

Each trial starts from the same disposable file and known page, records
expected result and before/after evidence, assigns PASS/FAIL/UNKNOWN, and
proves rollback. Never write on an original PDF or proceed through uncertain
ink state. Nothing here authorizes a package merge without the user's decision.
