# Native Reader v2 architecture

## Product contract

Native Reader v2 operates on the user's original PDF. It does not generate a
replacement PDF or require a mapping sidecar. Portrait remains Supernote's
ordinary full-page reader. Landscape presents two original source pages in
book order and preserves the complete native tool set.

The implementation is deliberately pinned to the inspected Nomad firmware and
may replace native reader behavior aggressively. Delivery remains a reversible
root module rather than an in-place system-APK replacement so disabling the
module restores the vendor reader and its original signature.

## Non-negotiable page ownership

The screen may contain two page surfaces, but there is one native writer owner
per physical pen gesture. Each source page retains its own PDF page identity,
native `.mark` page, native operation history, links, text, digest data, and
annotations.

Landscape therefore consists of:

- one live native page surface;
- one complete read-only projection of the adjacent source page; and
- one serialized ownership transaction that can exchange those roles.

The module never merges an inactive gesture into a `.mark` file, never copies
an in-memory trail list between pages, and never fabricates an Undo record.

## Unified spread session

One `SpreadSession` owns all behavior for the active `DocumentActivity`:

- exact original-document identity;
- direction and cover-parity settings;
- current spread pair and physical left/right slots;
- active source page and live native component identities;
- one immutable page-to-screen affine per slot;
- one gesture-scoped route selected at `ACTION_DOWN`;
- one page-activation transaction; and
- one monotonically increasing layout/load generation.

Every callback validates the same session, generation, page, component, and
gesture token. No tool maintains a parallel interpretation of the current
page or geometry.

The controller is confined to the reader thread that constructs it. Pen,
finger, and hover input already arrive there; every asynchronous firmware or
Binder acknowledgement is marshalled back to that same thread before it may
advance the state machine. Cross-thread entry is a programming error and is
rejected before authority or native state changes. Native calls are made only
after releasing the controller's short state monitor, so a synchronous native
callback on the owner thread remains safe and cannot deadlock.

## Two page surfaces

Both slots use the same authoritative affine for PDF pixels, committed ink,
digest overlays, links, text geometry, selection overlays, and input.

The active slot displays Supernote's live native page state. The inactive slot
is rendered from the adjacent cached `PageInfo` and its canonical handwriting
and digest bitmaps. After a native edit commits, the departing active page is
rerendered before it may become the inactive projection.

Portrait destroys the spread session after a native save acknowledgement and
returns the original page stack to an identity transform. Only RTL navigation
remains active.

## Input routing

Routing is classified once at the beginning of a gesture and remains fixed
through `ACTION_UP` or `ACTION_CANCEL`:

1. Visible native chrome is always native pass-through.
2. A document gesture is bound to the source page under its initial contact.
3. A gesture beginning on the active page uses the native reader immediately.
4. Hover over the inactive page may preactivate it.
5. A finger tap on the inactive page activates it and may replay the original
   native hit after activation (for example an internal link).
6. A pen contact reaching the inactive page before activation completes is
   consumed through its matching `UP` or `CANCEL` while the writer transfer
   completes. That one contact is deliberately not persisted. The now-active
   page accepts the next native pen contact normally. The implementation must
   never fabricate, redirect, or inject pen samples.
7. If activation cannot be proven, the contact remains discarded and the
   exact source writer is restored before input is released.

This direct-contact loss is an explicit safety tradeoff, not an intended final
gesture experience. In ordinary use Supernote hover should preactivate the
page before pen-down, preserving the first written stroke. The inspected
firmware exposes no supported Java/Binder API for replaying raw EMR samples.
Injecting into DrawPath's undocumented C++ `PointMess` queue would couple the
module to an unverified native ABI and could corrupt ink, so it is prohibited.

Cross-divider motion retains the page chosen at gesture start and is clipped
to that page. It cannot activate the neighboring page or a toolbar control.

## Page activation transaction

Activation is one explicit state machine:

`IDLE -> SOURCE_SAVING -> TARGET_LOADING -> TARGET_VERIFYING ->`
`TARGET_PUBLISHING -> ACTIVE`, `DRAINING_CONTACT -> ACTIVE`, or
`REPLAYING -> ACTIVE`

Failure moves to `ROLLING_BACK -> ROLLBACK_PUBLISHING`, then either returns
to the exact source owner or enters `DISABLED` with native writing blocked.
A stale callback cannot advance another transaction.

The transaction:

1. freezes navigation and new document gestures;
2. saves the source through native `saveTrails()` and waits for acknowledgement;
3. disables the writer and invalidates the old affine;
4. loads the target original PDF page through the native lifecycle;
5. verifies `DocumentViewModel`, `HandWritePresenter`, `SuperNoteNote`, draw-path
   geometry, `.mark` page, and layout generation;
6. recomposes both source-page surfaces;
7. publishes the target affine and writable region atomically;
8. drains one already-started pen contact or replays one verified finger hit;
   and
9. releases navigation/input only after the native result settles.

## Native features

After a page owns the live surface, Supernote remains authoritative for:

- ordinary pen and recognized straight lines;
- stroke and area erasers;
- lasso selection, movement, resize, commit, and dismissal;
- Undo and Redo;
- text selection, highlight, underline, and strikeout;
- internal and external links;
- bookmarks, contents, search, digest, keywords, and export; and
- `.mark` persistence and conflict handling.

The module routes and presents these features; it does not implement substitute
annotation formats.

## Settings and InkBridge

RTL Reader stores per-document settings in private companion storage keyed by
the original PDF SHA-256. A narrow authenticated provider supplies those
settings to the injected reader. No file beside the PDF is required.

InkBridge reads and writes the original document's native page elements. Page
indices and normalized coordinates are already canonical; no Virtual Spread
manifest, inverse transform, generated cache, or cross-representation `.mark`
hydration is involved.

## Firmware and rollback policy

The implementation targets the exact inspected Supernote firmware, document
APK, DrawPath service, and native libraries. Future compatibility is not a
design constraint. Unknown binaries are rejected because invoking stale
offsets or methods can corrupt annotations or boot-loop the reader, not because
the module promises forward compatibility.

The original system APK is never resigned or overwritten. The root module is
the replacement layer and can be disabled from LSPosed/Magisk recovery. Before
the first editable run on a real document, the original PDF and `.mark` bytes
must have verified recovery snapshots.

## Release gate

The first full candidate must pass, on both physical landscape rotations:

- portrait native page fidelity and RTL turns;
- cover parity and RTL/LTR landscape spreads;
- active-page pen strokes and hover-preactivated inactive-page pen strokes;
- direct inactive-page pen-down containment (first contact dropped safely,
  subsequent contact native);
- pen hover, pen tap, and finger-tap activation;
- pen selection of every toolbar tool;
- both erasers, lasso move/resize/dismiss, Undo/Redo;
- text highlight/underline/strikeout;
- internal links, bookmarks, contents, and Back history;
- rapid page turns, rapid side switching, rotation during pending work;
- repeated close/reopen and process recreation;
- ordinary-document inertness; and
- InkBridge export/move/erase/idempotent re-import on original page indices.
