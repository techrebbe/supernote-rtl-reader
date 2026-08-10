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
2. Save the source page through Supernote's ordinary `saveTrails()` path.
3. Disable native handwriting before publishing the transition.
4. Call the native `loadPage(target)` lifecycle.
5. Wait until both reader and handwriting presenter identify the exact target.
6. Recompose the spread from canonical page and annotation state.
7. Install writable geometry for only the target page.
8. Commit the transaction and re-enable native editing.

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

## Failure behavior

The transaction fails closed:

- writing remains disabled when page identity or geometry cannot be verified;
- one timed native reload is allowed and is bound to the same transaction ID;
- a final timeout rolls back toward the source page;
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
