# Native page viewport: integration boundary gate (2026-09-28)

This note preserves the current stop line. It does **not** approve an install,
stock-reader hook, Nomad view insertion, pen input, PDF mutation, or release.

## What has actually passed

The isolated API-30 emulator tile trial passed exact synthetic 9 → 10 → 9
structure and completed draw-dispatch evidence, with the same process,
Activity, root, and nine original child identities before and after. See
[disposable-lease-tile-trial-host/EMULATOR_VALIDATION.md](disposable-lease-tile-trial-host/EMULATOR_VALIDATION.md).
This was not a `TargetOwnedVisualLeaseCore`/`AndroidLeasePort` trial and did
not use Supernote, a PDF, a pen engine, or a hidden stock child. A separate
optional screenshot trial was rejected before insertion by its freshness gate;
there is no pixel-composition claim.

## Why the current Android Port remains closed

`AndroidLeasePort.add()` records one pre-add evidence mutation and calls
ordinary `addView`. `TargetOwnedVisualLeaseCore` requires exactly that one
revision, then an unchanged revision through admission and each allowed draw.
The controlled `AndroidLeasePaintRoot` records another mutation in `onLayout`
before laying out children. Ordinary `addView` requests later measurement and
layout, so the current path correctly fails closed. Skipping that second
revision because geometry *ended* unchanged would miss intermediate mutations
or an ABA. Android's `View.layout` may set the root frame before the root's
`onLayout` callback, and child measurement may occur earlier still. A token
checked only inside `onLayout` is therefore too late to certify complete
pre-mutation coverage.

Keep `hasCompleteSynchronousEvidenceMutationCoverage()` false and the Port's
uncertified revision at `-1`. Do not accept `baseline+2`, suppress generic
layout revisions, or weaken the existing deferred-layout/ABA tests. The
stock reader has a plain `FrameLayout`, not our owned paint-root subclass;
its hierarchy observation does not supply this missing authority.

The first ten-child admission frame under the Core is intentionally
pixel-silent. A future integration card needs a distinct *post-admission*
completed visual frame before stop. Structural rollback or `drawChild` order
alone is not a viewport/pixel pass.

## Next bounded discriminator

First perform an **offline exact write-edge audit** for the pinned Android
framework and the stock reader: root/ancestor frame and measurement, child
layout and property setters, root attachment/replacement, document/page state,
paint dispatch, and the separate EBC/DrawPath pen path. Identify method owner,
first field write, original-forwarding behavior, and whether an observation
or pre-hook can be scoped to the exact disposable process and root. Do not
infer complete coverage from an `onLayout` or global-layout listener.

Only after a separately reviewed and authorized emulator-only hook card should
one test a process-scoped pre-layout fence on a synthetic Activity. Its pass
criteria are: revision before every tested first write; original method runs
exactly once; no stale frame admits pixels; exact timeout/teardown cleanup;
no process-scope escape. A missing edge, changed forwarding, ambiguous frame,
or uncertain restoration is **NO-GO**. An emulator pass would establish only
hook mechanics for that fixture, not stock reader safety.

Any later Nomad card needs a fresh device reservation and the hash-pinned
disposable PAGE 1 PDF, exact activity/root/page and absent-`.mark` preflight,
independent postflight, and no view insertion until stock paint order,
physical composition, input routing, and target-process cleanup have separate
evidence. Preserve existing annotations and all prior branch/test evidence.

## Alternatives if this boundary fails

- A firmware/resource patch could own the stock root earlier, but signature,
  system-UID, framework-layout, and rollback risks require a separate design.
- A VirtualDisplay with one active native page and a passive adjacent page may
  solve visual two-page reading without stock-root insertion; it does not
  establish native writing on both pages or the physical DrawPath pen route.
- A direct native pen/page adapter targets the underlying writer boundary but
  has the largest unproven Binder, loader, and EBC surface.

None of these alternatives changes the current original-PDF/annotation
authority or authorizes a broad rewrite.
