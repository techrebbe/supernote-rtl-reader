# Transactional single-active-page architecture

## Goal

Keep the native Supernote document reader, toolbar, handwriting engine, `.mark`
format, Undo/Redo stack, eraser, lasso, links, highlights, and selection tools
authoritative while adding RTL navigation and a two-page landscape presentation.

The reader may display two pages, but Supernote has exactly one native current
page. This design never pretends otherwise.

## Ownership invariant

At every instant, only one visible page owns all of the following:

- `DocumentViewModel.currentPage`;
- `HandWritePresenter.currentPage`;
- the native DrawPath geometry and writable region;
- native handwriting layers and Undo/Redo history;
- native `.mark` persistence.

The other page is a display-only projection of canonical PDF and annotation
state. No inactive-page gesture may mutate it directly or be merged into its
`.mark` data by the module.

## Page activation transaction

An inactive-page finger tap, pen hover, or pen contact requests one serialized
ownership transfer:

1. Validate the exact document, spread, source page, and target page.
2. Under the ownership lock, reject an existing pen contact or publish the
   exact transaction/input guard before any persistence or page mutation.
3. Save the source page through Supernote's ordinary `saveTrails()` path using
   a thread-scoped bypass for only this intentional flush; all concurrent
   lifecycle saves remain blocked.
4. Disable native handwriting while the page owner changes.
5. Call the native `loadPage(target)` lifecycle.
6. Wait until both reader and handwriting presenter identify the exact target.
7. Recompose the spread from canonical page and annotation state.
8. Install writable geometry for only the target page.
9. Under the same ownership lock, recheck that no contact is held, remove the
   exact guard, and commit/re-enable native editing. If contact raced commit,
   retain the guard and writer disable through pen-up.

Input is serialized while those steps run. A stale timeout or completion may
act only on its own transaction ID.

## Pen behavior during activation

Hover normally starts the transaction early enough that the first subsequent
stroke can use the newly active page.

If physical contact begins before the transaction commits, that activation
gesture is deliberately discarded. The writer stays disabled through pen-up,
then the target page is armed for the next stroke. Losing one attempted stroke
is preferable to saving it on the wrong page, replacing unrelated trails, or
manufacturing a synthetic Undo record.

A stroke that begins on the active page never becomes an activation gesture if
it crosses the divider. Cross-divider coordinates are discarded and the stroke
remains owned by its original page.

### Low-latency callback boundary

The UI composition path publishes one immutable snapshot containing the
validated document configuration, current page pair, visible page bounds, and
writer-ready state. Supernote's native pen-position callback reads only that
snapshot plus the in-memory transaction/contact guards. It performs no marker
parsing, document metadata inspection, `stat`, hashing, or other filesystem
work before the native writer callback.

The snapshot is replaced whenever the page, document, orientation, validated
configuration, or spread geometry changes. Missing, stale, or not-yet-committed
geometry blocks protected landscape pen input rather than falling back to an
unverified mapping.

## Failure behavior

The transaction fails closed:

- writing remains disabled when page identity or geometry cannot be verified;
- one timed native reload is allowed and is bound to the same transaction ID;
- a final timeout rolls back toward the source page;
- source-page rollback is retried only a bounded number of times and every
  retry remains bound to the exact published transaction;
- if rollback still cannot reload or reconverge, the writer remains disabled
  and pen geometry is invalidated while the global UI/save guard is released,
  allowing navigation or reader recreation to recover without silently
  accepting uncertain page ownership;
- an RTL page turn rejected while pen contact, geometry publication, or another
  ownership transfer is in progress is retained and replayed against the exact
  source document/page once transactional activation is ready; it is cancelled
  only when a different document, orientation, or page supersedes the request;
- no module-written `.mark` merge is used as a fallback.

## Migration boundary

Native Spread v0.0.117 remains an experimental branch containing the prior
inactive-page capture/normalize/merge approach. The transactional line starts
from stable main (Native Spread v0.0.116). Its runtime path must not invoke the
experimental inactive-page `.mark` merge or synthetic page-edit history.

## Initial acceptance gate

- Finger activation switches either half and preserves all existing ink.
- Hover activation switches either half before writing is enabled.
- A too-fast contact activates the target but cannot create a partial or
  wrong-page stroke.
- Active-page pen, eraser, lasso, Undo, Redo, links, and highlights continue to
  use Supernote's native behavior.
- Page turns and internal links cannot overlap an activation transaction.
- Portrait/landscape and away/back round trips preserve canonical annotations.
