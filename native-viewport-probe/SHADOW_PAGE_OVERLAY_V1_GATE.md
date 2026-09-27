# Shadow page overlay v1: visual-only admission

Status: **offline preparation only**. The stock landscape split path was
measured on the disposable PAGE 1 PDF: it crops the 1404 x 1872 portrait
origin to `showRect=[0,0,1404,1053]` before producing a 1872 x 1404 display
bitmap. The simple 270-degree counter-rotation and finished-window placement
paths are NO-GO. This card is a new architecture, not a retry of those paths.

## Boundary

The stock `com.supernote.document` activity remains the sole page, pen,
annotation, history and save authority. A separately built Service may own one
non-focusable, non-touchable `TYPE_APPLICATION_OVERLAY` visual window. It must
not create an Activity, VirtualDisplay, second Document task, accessibility
service or input path, nor call a stock setter or touch `.mark`.

The stock reader opens
`/storage/emulated/0/Document/RTL_DISPLAY0_CAPTURE_20260927.pdf`. The Service
opens only its app-private copy with the same basename for reading. A later
hardware gate must seed that copy from the separately SHA-verified disposable
source and independently compare both files. The Service's opened descriptor,
not a prior path lookup, must match the fixed 2419-byte size and SHA-256
`28b126627dd5966e8975ae1bf48385d65e1f8189e8aa32ddc0eab778904859c9`
and the independently confirmed printed PAGE 1 on zero-based PDF page 0.
Any inaccessible file, replacement, page-count/geometry mismatch or uncertain
descriptor identity fails closed. No broad storage permission, alternate path,
or shared-storage fallback is authorized. The test package may need to be
debuggable solely to seed and remove its private copy; that is not a production
reader design.

Render the entire PDF page with a uniform, centered fit into an opaque white
1404 x 1872 bitmap. The source PDF's 612 x 792 point MediaBox is not the
bitmap size. Neither the stock cropped `displayBitmap` nor a screenshot may be
used as the source. The three physical landscape placements are:

| Phase | Physical rectangle | Scale from the 1404 x 1872 bitmap |
| --- | --- | --- |
| FULL | x=409, y=0, w=1053, h=1404 | 3/4 |
| LEFT | x=0, y=78, w=936, h=1248 | 2/3 |
| RIGHT | x=936, y=78, w=936, h=1248 | 2/3 |

The one-pixel FULL centering choice (left margin 409, right margin 410) is
deliberate. No crop, stretch or 90-degree text rotation is allowed.

## Gates before any installation

1. Build only the isolated Service package with an explicit source allowlist.
   Verify the APK declares the intended overlay capability but no Activity,
   storage permission, input service or unrelated component.
2. Run deterministic tests for fixed source identity, page/rectangle geometry,
   exact overlay flags, failure paths and teardown ownership. Review the full
   exact diff independently. A source/CI pass is not a Nomad pass.
   Current host tests execute geometry and stale-generation behavior, and
   inspect the Android Service source/manifest; they do **not** inject real
   Android file, render, `addView`, `removeView`, layout or callback failures.
   Those runtime failure-path tests remain an open pre-install gate.
   The offline build currently verifies a SHA-pinned host copy outside the
   repository; a portable, reviewed fixture-generation/import path is still
   required before a repository CI build can claim reproducibility. Do not
   upload the PDF or replace the pin silently.
3. Prepare a separate hardware card for exact private-fixture seeding and
   cleanup, package signer, exact existing overlay AppOps state, reversible
   permission change, starting the Service, stock task/focus invariance and
   emergency cleanup. Do not seed, install, start or alter AppOps under this
   offline card.

## Proposed bounded Nomad batch (not yet admitted)

Once the separate hardware gate is reviewed, bind the fixed Nomad serial,
firmware, stock APK/task/PID/start time, physical landscape rotation, opened
PDF identity, current native page and independent `.mark` absence. Require no
unsaved pen state and acquire the reviewed physical-pen exclusion lease. The
observer's raw page tuple is diagnostic; it does not alone prove index base.

Run one no-input sequence:

`RENDER_BASELINE -> FULL -> LEFT -> RIGHT -> FULL -> CLEAN`

At baseline, capture the stock view and an independent full-source raster.
At every placement, capture the owned window/layer identity and generation,
rectangle, rendered content, two settled screenshots, stock task/focus/page
and PDF/`.mark` state. Check the four page edges and asymmetric fiducials
against the independent raster. An e-ink screenshot and layer existence alone
do not establish that the physical pixels have refreshed correctly.
Each SHOW generation has a 30-second emergency lifetime. The two captures and
their checks must finish within that bound. Expiry is an abort/cleanup event,
not evidence that the raster or placement failed. The Service has no Activity
and cannot observe the stock reader's task lifecycle by `stopWithTask`.

`CLEAN` removes only the exact owned overlay and helper, verifies both PDF
descriptors were already closed before window publication, removes only the
exact private fixture copy, restores the prior
permission/AppOps state, and proves the stock
reader/task/focus/page, PDF and absent `.mark` remain unchanged. If teardown
or annotation state is uncertain, stop and quarantine; do not retry by
force-stopping the native reader or deleting user files.

## Interpretation and next gate

A pass would establish only full-page **visual rendering, coexistence and
placement**. It would not prove pen pass-through, wet or committed ink,
selection, links, highlight, save geometry or two simultaneous writable pages.
An opaque overlay may obscure stock ink or controls where it covers them;
that limitation must be measured and solved separately. Android overlay
touch-pass-through behavior is likewise not an input admission.

Only after a clean visual batch may a separate writer-bridge design define
one authoritative source-page-to-screen transform and independently test
dry-ink parity before enabling the physical pen. No merge or release follows
from this card alone.
