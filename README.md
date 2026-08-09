# Supernote RTL Reader

A Supernote plugin focused on right-to-left PDF reading and landscape two-page spreads, designed especially for Hebrew books.

## Stable baseline

v0.4.6 is the current merged hardware-validated stable baseline on Supernote
Nomad. v0.4.7 is a hardware-validated safety-hardening candidate for the native
reader pilot, paired with Native Spread v0.0.62.

The validated reader behavior covers:

- portrait and landscape reading;
- RTL/LTR navigation;
- Auto / Single / Spread modes;
- **Treat Cover Page Separately** parity;
- per-PDF settings and page persistence;
- boundary cases;
- direction-aware Prev/Next footer placement;
- renderer reuse;
- root-free native-reader page handoff on Close.

## v0.2.1 performance work — hardware validated

The v0.2.x performance phase improves page-turn responsiveness while preserving the v0.1.1 reader behavior.

v0.2.0 changes the native render lifecycle:

- keeps the active PDF file descriptor and Android `PdfRenderer` open across sequential page renders;
- reuses that renderer while the PDF path, file size, and modification time are unchanged;
- automatically reopens it when the document changes;
- serializes page access so only one `PdfRenderer.Page` is open at a time;
- logs native timing for document-open/reuse, raster rendering, PNG compression, Base64 encoding, and total render time.

Hardware timing on the test Nomad showed that after the initial document open, renderer reuse reduces open/reuse overhead to about 0–1 ms. Typical native rendering was then dominated by PNG compression rather than document opening or Base64 conversion.

v0.2.1 adds a four-page native LRU cache of recently compressed PNG page results. In the captured hardware run:

- 107 native render requests were recorded;
- 14 were native cache hits (about 13.1%);
- cache-hit median total time was about 16 ms;
- cache-miss median total time was about 419 ms;
- cache hits therefore avoided roughly 403 ms of native render work per hit;
- cache-hit logs showed `renderMs=0` and `pngMs=0` as intended.

The v0.2.1 hardware spot check also confirmed that rapid page turns produced no stale, blank, or out-of-order pages and that Close still returned the native reader to the correct focused page.

Diagnostic marker:

```text
RTL_READER_NATIVE_RENDER page=... reused=... cacheHit=... openMs=... renderMs=... pngMs=... base64Ms=... totalMs=...
```

## v0.3.0 direct native rendering — hardware validated

v0.3.0 replaces the foreground `Bitmap -> PNG -> Base64 -> React Native Image` path with a native Android `PdfPageView` that draws the `PdfRenderer` bitmap directly.

The Nomad timing capture confirms the intended bottleneck is gone:

- `pngMs=0` on every captured direct-view render;
- `base64Ms=0` on every captured direct-view render;
- renderer reuse remains active, normally `openMs=0–1` after initial open;
- steady-state completed page renders are typically around 140–145 ms total;
- v0.2.1 uncached native renders were about 419 ms median, so the direct foreground path is roughly 3× faster at the native-render stage.

The hardware behavioral pass also confirmed:

- no stale, blank, or out-of-order completed pages during rapid turns;
- portrait and landscape rendering remain correct;
- RTL/LTR spread order remains correct;
- **Treat Cover Page Separately** still preserves the expected virtual-blank parity;
- page jump still lands on the requested physical PDF page;
- Close still returns Supernote's native reader to the focused page.

Diagnostic marker:

```text
RTL_READER_NATIVE_VIEW_RENDER page=... reused=... openMs=... renderMs=... pngMs=0 base64Ms=0 totalMs=...
```

## v0.4.2 direction-aware bitmap prefetch — hardware validated

v0.4.2 adds a four-entry native bitmap LRU on top of the v0.3.0 direct renderer.

- only the page or spread in the most likely reading direction is pre-rendered;
- the bitmap leaving the screen is returned to the same native cache instead of being recycled immediately;
- one-step reversals therefore reuse the page or spread that was just visible;
- foreground navigation takes priority over speculative background rendering;
- queued stale foreground work is skipped after lock acquisition;
- stale rendered results are returned to cache instead of being displayed;
- PNG and Base64 remain absent from the foreground path.

The final Nomad validation produced:

- 43 completed Single-mode turns with a median interaction latency of about **50 ms**;
- Single-mode minimum/maximum interaction latency of **43/51 ms** in the captured run;
- normal and one-step-reversal spreads generally around **47–67 ms** with both pages served from cache;
- native cache-hit work normally around **0–4 ms**;
- consistent `RTL_READER_NATIVE_VIEW_VISIBLE_CACHED` handoff when a page left the screen;
- no stale, blank, or out-of-order pages;
- correct Close/native-reader handoff.

Very rapid spread bursts can still take roughly 200–350 ms when the reader advances faster than Android can rasterize two entirely new pages. That is now the expected two-page rendering limit rather than speculative work blocking the foreground.

Diagnostic markers:

```text
RTL_READER_NATIVE_VIEW_PREFETCH ...
RTL_READER_NATIVE_VIEW_PREFETCH_SKIPPED ...
RTL_READER_NATIVE_VIEW_VISIBLE_CACHED page=...
RTL_READER_NATIVE_VIEW_RENDER ... cacheHit=true|false ...
RTL_READER_NATIVE_VIEW_DISPLAY ... interactionMs=...
RTL_READER_NATIVE_VIEW_READY ... interactionMs=...
```

## v0.4.3 stabilization

v0.4.3 makes the tested v0.4.2 renderer the canonical native source instead of generating it through layered Kotlin string rewrites. The installer now copies and registers that source directly, and every build verifies the cache-key, foreground-priority, stale-request, and generated-source invariants.

The initial smoke build also exposed an orientation cold-start issue: PluginHost may initially report stale portrait window dimensions when RTL Reader is opened while the Nomad is already in landscape. The revised v0.4.3 candidate waits for the actual plugin page-area layout before:

- choosing Auto Single versus Spread mode;
- calculating native render width;
- mounting the first `PdfPageView`.

This prevents the initial landscape spread from being mounted against stale or incomplete dimensions. The focused hardware smoke test is recorded in `REGRESSION.md`.

Full validation details are recorded in `REGRESSION.md`.

## v0.4.11 settled native ink composition

Native Spread v0.0.81 separates additive pen commits from replacement-style
annotation updates. Ordinary pen and highlighter refreshes now draw the newest
captured trail over the canonical saved page, preserving every earlier settled
stroke. Eraser, lasso, undo, and redo refreshes still replace the active page
slot so transparent pixels can remove or move older ink. This addresses the
case where each newly settled stroke temporarily hid all earlier strokes until
the page was turned away and reloaded; the underlying `.mark` data was already
complete and is not rewritten by this display fix.

## v0.4.12 native spread appearance

Native Spread v0.0.82 adds two per-document appearance controls:

- **Spread divider — On / Off**. Off removes the dark center rule and gives
  each page the full physical half of the landscape display.
- **Page sizing — Fit page / Native fill**. Fit page preserves the previous
  whole-page view. Native fill uses the same aspect-preserving fill/crop rule
  as Supernote's full-screen native reader; it never stretches the page.

The setting now applies to the plug-in's own landscape spread as well as Native
Spread. The PDF view occupies the full display height; RTL Reader's header and
footer remain absolute overlays, like Supernote's native toolbox, instead of
reducing the document viewport.

The module stores a full-page transform separately from the visible half-page
bounds. PDF pixels, native ink, highlights, lasso geometry, links, eraser input,
and page activation therefore share the same scale and crop instead of each
feature approximating the new layout independently. Existing documents default
to **Fit page** with the divider **On** until changed.

Native Spread v0.0.84 waits for the native document view to finish its
portrait/landscape layout and then asks Supernote to reload the unchanged
current page after returning to portrait. This prevents the first portrait
frame from retaining the smaller landscape-rendered page until a page turn.

Native Spread v0.0.85 makes **Native fill** use Supernote's actual automatic
page-trimming geometry instead of filling each half from the uncropped PDF
page. The active page reuses the trim rectangle already calculated by the
native reader; the adjacent page calculates the same non-white content bounds
when it has not yet been active. The original PDF bitmap remains the drawing
source, and the full-page destination is derived from the trim transform, so
native ink, eraser, lasso, highlights, links, and activation all retain one
canonical coordinate system. On the Nomad hardware pass, both spread pages
extended behind the top toolbar and bottom page bar without stretching. A new
stroke remained aligned and persisted in the same position after turning away
and back.

Native Spread v0.0.86 fixes direct writing on the inactive half of an editable
spread. Supernote's `receiveTrials()` callback exposes the completed stroke but
does not invoke its later `saveTrails()` routine. The module now commits the
captured page-local transaction before completing the deferred page activation,
while retaining the existing fail-closed guard if that commit fails. Hardware
validation in both directions confirmed that inactive-page strokes remain
visible, preserve all earlier ink, and survive turning away and back.

Native Spread v0.0.87 protects an inactive-page stroke erase from the native
save that follows page activation. The page-local transaction already removes
the correct intersecting trail; the one deferred native save is now suppressed
before it can rewrite the page from stale in-memory trails. The guard is armed
only after a successful erase, is consumed once, and expires after two seconds.

Native Spread v0.0.88 registers protected inactive-page writes and erases with
Supernote's existing Undo/Redo controls after page activation finishes. Each
entry retains the page-local trail lists immediately before and after the edit.
Undo and Redo restore only that annotation-page transaction, while the native
stack continues to control button availability and operation ordering.

Native Spread v0.0.89 preserves the inactive page's prearmed writable region
when Supernote performs its one-shot pen-down refresh after opening a document.
That native refresh otherwise restores the still-visible original page's
geometry before the first stroke can reach the page-local transaction.

Native Spread v0.0.90 also primes the target page inside Supernote's native
handwriting engine before deferred inactive-page input begins. Its intermediate
annotation bitmap is suppressed, keeping the visible spread unchanged until
the page-local stroke has been captured and committed.

Native Spread v0.0.91 redraws a settled eraser result directly from the newly
saved native `.mark` page. This avoids replacing the active spread slot with
Supernote's sometimes incomplete post-eraser bitmap after an inactive-page
activation, while leaving the live low-latency eraser path and page-local data
format unchanged.

Native Spread v0.0.92 flushes a completed active-page native eraser transaction
to the `.mark` file immediately after pen-up, before the canonical spread redraw
can reread and restore the pre-erase file contents.

Native Spread v0.0.93 excludes the native top toolbar and bottom page-number
bar from inactive-page tap activation. Toolbar Undo/Redo taps therefore remain
on the current page instead of first switching to the page beneath the control.

Native Spread v0.0.94 redraws native Undo and Redo from the operation's updated
canonical `.mark` state. It no longer clears the active spread slot with the
incomplete transient bitmap Supernote can emit during those operations.

Native Spread v0.0.95 flushes Supernote's in-memory Undo/Redo result to `.mark`
before performing the canonical reload, so an erased stroke restored by Undo
and removed again by Redo is immediately visible and persistent. Nomad hardware
testing confirmed the complete active-page erase -> Undo -> Redo sequence,
including persistence of the redone erasure after a spread reload, without
changing unrelated trails or activating the opposite page.

Native Spread v0.0.96 keeps that deliberate active-eraser and Undo/Redo flush
eligible even while the one-shot stale activation-save guard is armed. The
guard remains available for the delayed stale native save instead of consuming
and suppressing the canonical transaction that must reach `.mark` first.

Native Spread v0.0.97 adds a per-document active-page header choice. Turning
it off removes the persistent red ACTIVE LEFT/RIGHT or READ ONLY banner while
retaining safety failures and annotation-save error messages.

Native Spread v0.0.98 adds an opt-in annotation trace laboratory for diagnosing
dual-page ink without changing the writing, eraser, lasso, or rendering paths.
A protected ADB control broadcast starts a session for the currently open
editable document. The module correlates pen transactions with active/mark
pages, save/load callbacks, trail-list fingerprints, `.mark` filesystem events,
and content-addressed `.mark` snapshots. Checkpoints add screenshots, and the
collector produces one ZIP suitable for comparing ordinary portrait behavior
with the same operation in a landscape spread. Trace data can contain document
paths and handwriting; it stays on the device until explicitly pulled.

Native Spread v0.0.99 fixes active-page eraser settling in a landscape spread.
Supernote's first committed-ink callback can run before the completed eraser
transaction reaches the canonical `.mark` file. The module now saves that
transaction and reloads the same mark page in that order, so the active page is
rebuilt immediately from the erased state instead of retaining stale ink until
focus moves to the other page.

Native Spread v0.0.100 narrows inactive-page eraser protection to the exact
deferred `loadPage()` save that carries stale activation data. It no longer
uses a two-second window that could consume a new pen or page-switch save.
Annotation-trace snapshots are now debounced on a serialized background worker,
and ordered trail fingerprints cover every trail while detailed JSON remains
capped at 256 entries.

Native Spread v0.0.106 keeps annotation tracing from perturbing pen timing on
trail-heavy pages. Hook threads now capture immutable scalar and point arrays;
the trace worker performs JSON serialization and SHA-256 fingerprinting. A
boundary reports its `.mark` hash as `pending` whenever the live file identity
does not match the most recently completed snapshot. Trail fingerprints include
rotation, redraw dimensions, and coordinate extents as well as points and pen
metadata. The canonical trace identity now covers every trail attribute used
by inactive-page ink matching, including layer, pen-up/special flags,
recognition and EMR modes, trail/draw versions, and writing-app identity.
Recognition, refresh, before/after-shift rectangles and contour point geometry
are captured immutably and included in the worker-side fingerprint as well.

The active settled-ink compositor now clips its transformed bitmap to the
same visible page-slot bounds used by Native Fill PDF and canonical-ink
rendering, preventing cropped-margin ink from crossing the spread divider.

The custom plug-in's Native Fill renderer now uses the same non-white content
bounds, seven-pixel padding, asymmetric margin anchor, and fit transform as
Supernote's native `TrimmingUtil`, with a local detector fallback when the
native helper is unavailable. Native and plug-in handoff therefore retain the
same page zoom and position. Failed trace startup also stops observers and
removes the stale active-session pointer.
Content-bound detection is requested only for Native Fill renders, so ordinary
Fit navigation does not pay the native-helper or fallback scan cost.

## v0.4.10 protected native editing pilot

v0.4.9 added an explicitly confirmed **RTL editable** choice alongside **Off**
and **RTL read-only**. Before an ordinary PDF can become editable, the plugin:

1. completes the live, document-bound Native Spread handshake;
2. preserves the current `.mark` state byte-for-byte (including the original
   absence of a `.mark` file);
3. writes and rereads a recovery manifest bound to the PDF path, length, and
   full-file SHA-256 (the native reader changes the PDF modification time when
   it reopens, so mtime is recorded only for diagnostics);
4. verifies the snapshot length and SHA-256; and
5. creates an editable marker bound to the recovery-manifest SHA-256.

Native Spread v0.0.75 independently verifies that attestation off the document
activity's main thread, with editing kept disabled until verification finishes.
A missing, changed, mismatched, or orphaned recovery file fails closed to
read-only. The
module also notices backup-file metadata changes during a running session
instead of trusting a stale editable configuration cache. It now includes the
open PDF's length, modification time, device/inode identity, and nanosecond
change time in that cache identity. Replacing the document while preserving its
path, length, and modification time therefore still forces a fresh full-file
attestation; rewriting it in place changes the filesystem change time and does
the same.

The plugin also creates, verifies, and retires those recovery files on a worker
thread rather than the PluginHost UI thread. Off/read-only transitions preserve
the prior marker bytes and restore them if recovery-baseline retirement fails,
keeping the cleanup retryable and the protected session recoverable. Initial
editable activation is transactional too: if marker creation fails after a new
backup is verified, the prior marker is restored and the new backup is retired.
Final full-file verification is inside that same rollback scope. While any of
these background transitions is pending, Settings dismissal, hardware Back,
and Close are blocked so native handoff cannot race the recovery transaction.
Immediately before the first editable marker is committed, the plug-in also
compares the live `.mark` presence, length, and SHA-256 with the new recovery
baseline. If the running native reader flushed annotations during backup
creation, the stale snapshot is retired and recreated; activation fails closed
after three unstable attempts rather than authorizing recovery from older ink.

After successful verification, v0.0.75 explicitly refreshes an already visible
landscape spread so native handwriting geometry is re-enabled without waiting
for a page turn or rotation.

v0.4.10 raises the protected-editing compatibility floor to v0.0.80. Its
canonical lasso transition preserves the selection's native width and height
during a pure move; only the translated origin is converted from the half-page
spread. This prevents the live selection from growing to roughly twice its
size when moved in landscape. Hardware validation on the protected 738-page
pilot confirmed that the moved X kept its size and position through a spread
turn and a cold native-reader restart.

Native Spread v0.0.75 also makes ordinary pen input on the inactive half of an
editable landscape spread durable. It prearms the low-latency writer for the
page under the pen without replacing the visible spread, captures the finished
stroke, normalizes it into the native document-page coordinate system, and
merges it with that page's existing `.mark` trails. The module bypasses the
native intermediate save that otherwise serializes only the currently loaded
subset and can delete older annotations. On the disposable Nomad test PDF, the
new inactive-page line remained visible, all seven existing trails were
preserved, and all eight trails survived a spread turn away and back.

Native Spread v0.0.78 extends that protected transaction to the stroke eraser.
It captures Supernote's eraser path, compares it with saved handwriting in a
scale-independent page coordinate system, removes only intersecting ink from
the target page, and bypasses the native combined-spread save that can otherwise
clear unrelated trails. On a fresh disposable Nomad document, erasing the
right-hand one of two separated strokes on the inactive page removed exactly
that stroke, preserved the control stroke and companion page 4, and remained
correct after leaving and returning to the spread.

Native Spread v0.0.79 incorporates the final review hardening. If the page-local
`.mark` transaction fails, the module no longer switches pages and discards the
pending edit; it cancels the activation and displays an explicit save-failure
banner. The protected-editing cache now binds the marker, recovery manifest, and
snapshot to device, inode, and nanosecond change time as well as length and
mtime, so metadata-preserving sidecar replacement forces fresh attestation.

Native Spread v0.0.80 strengthens inactive-page ink deduplication. A captured
stroke is considered already saved only when its complete sampled path, pressure,
angle, draw flags, timestamps, and ink-defining pen attributes match. Retracing a
line or drawing another dot at the same location can no longer be discarded just
because its point count and endpoints resemble an existing stroke.

**Restore snapshot** disables the marker, terminates the native document
process before touching `.mark`, re-enumerates the process list to catch a
replacement PID, and aborts unless every document process has exited. It then
rehashes the PDF and recovery snapshot immediately before touching `.mark`,
atomically restores and verifies the original bytes (or the original no-`.mark`
state), removes the completed recovery files, and reopens the native reader.
This prevents an in-memory native annotation model from overwriting the
recovered state. The Restore action now waits for that worker's verified result;
an asynchronous failure is returned to the settings UI and also shown as a
long device message if the document restart has already dismissed the plugin.

Selecting **Off** or downgrading to read-only retires the completed editable
session's recovery baseline. A later **Back up & enable** therefore snapshots
the current `.mark`, including legitimate annotations made during the ordinary
native-reader interval, rather than silently reusing an older baseline.
Retirement first moves the snapshot to a recoverable staging path and preserves
or reconstructs its manifest-bound state if cleanup is interrupted.
Backup creation removes a newly copied snapshot if manifest creation fails, and
restore uses the same staged cleanup transaction before reporting success.
Cover controls are disabled while any native-mode transition is pending so a
read-only Cover update cannot race a protected-editable handshake. A Cover
change also owns that transition lock until its native marker update finishes,
and leaving editable mode clears the retired recovery status from the UI. If a
marker remains configured while its live hooks are unavailable, Cover is
disabled so the UI cannot diverge from the sidecar's saved parity.
Switching to LTR now waits for that native-mode shutdown transaction to succeed
before committing the direction preference. A failed recovery-baseline
retirement leaves both the protected RTL marker and the RTL UI state intact.

The protected pilot validated that full rollback on hardware: an edited
147,752-byte `.mark` was restored byte-for-byte to its original 89,801-byte
snapshot and SHA-256, the reader reopened normally, and the completed marker,
manifest, and recovery snapshot were removed.

The final reviewed v0.4.10 build repeated the transaction from a clean Off
state with Native Spread v0.0.68. First-time backup creation survived attempted
Close and hardware-Back interruptions, native writing and erasing remained
functional, and Restore reproduced the original 89,801-byte annotation file's
SHA-256 exactly before removing all recovery sidecars and reopening page 145.

In landscape spread editing, Supernote's immediate low-latency pen preview can
look thicker than the settled stroke. The committed `.mark` keeps the canonical
Supernote thickness; the difference is limited to the transient preview and is
tracked for a later visual-polish revision rather than changing portable ink
data in this safety release.

Editable mode exposes the writing, eraser, lasso, text-highlight, embedded-link,
and active-page geometry paths previously proven on disposable calibration
documents. Native handwriting remains ordinary Supernote element data, so it
continues to work with InkBridge's validated schema-v2 page snapshot/export
path. Native text highlights are a separate PDF-annotation stream and still
need InkBridge's planned annotation adapter.

The protected pilot confirmed that interoperability directly: InkBridge
exported the lasso-moved X as two schema-v2 strokes with 84 pressure-bearing
samples, stable Supernote UUIDs, normalized geometry, and native style data.
Deletion tombstones still require InkBridge to compare a post-erase page
snapshot against a previously captured portable baseline.

## v0.4.7 native-reader pilot control

v0.4.5 added a safe per-document control for the rooted Native Spread module.
v0.4.6 raises the compatibility floor to the real-document-validated Native
Spread v0.0.61 module. v0.4.7 requires Native Spread v0.0.62 and adds a live,
nonce-based handshake with the hooked document process before the setting is
shown as active or a new read-only marker can be written.
In Reading settings, **Supernote native reader** offers:

- **Off** — remove this PDF's hidden native-spread setting;
- **RTL read-only** — enable RTL portrait navigation, automatic landscape
  spreads, and the current cover-separate parity in Supernote's native reader.

The plug-in verifies the exact supported firmware, SupernoteDocument build,
Native Spread module version, active hooked process, handshake protocol,
current document path, and document APK identity before enabling the setting.
It requires Native Spread v0.0.62 or newer. Its read-only mode forces a full-screen
handwriting-disabled region and blocks the native annotation commit callback as
a persistence fail-safe. v0.0.61 also composites saved `.mark` ink for both
visible pages, preserves the active left/right side while turning spreads, and
limits tap navigation to the outer edges. Experimental native writing remains
available only through the disposable test marker until a separate protected
editable-document pilot is explicitly enabled and validated.

After enabling the pilot, close RTL Reader normally. Its existing page handoff
restarts Supernote's native reader on the same page, where the LSPosed module
reads the per-document setting. Switching the plug-in to LTR automatically
turns the native RTL setting off.

The full disposable-PDF hardware pass is complete: enable/disable, portrait RTL
navigation, automatic landscape spreads, Cover Separate parity, and ordinary
native behavior after disabling all passed. In read-only mode, pen input
produced no visible trace and created no `.mark` file.

A protected copy of a 738-page annotated Hebrew PDF also passed the real-document
pilot. Saved ink remained visible on inactive spread pages, center taps no longer
turned pages, outer-edge taps and swipes turned one spread in RTL order, and the
active side was preserved. The protected copy's `.mark` SHA-256 remained
`c2155e51a686a3ba7066c8ef7d859c19053019e85d23d1414fa1a69dc9de2c21`
before and after the test.

The v0.4.7 / Native Spread v0.0.62 safety pass is also hardware validated. The
live document-process handshake succeeds only while the LSPosed module is
enabled and scoped to `com.supernote.document`; disabling the module and
restarting the document process makes **RTL read-only** unavailable, and
re-enabling it restores the feature. The native activity cleanup path clears
its retained activity reference and cached bitmaps on destruction. The same
protected `.mark` checksum remained unchanged throughout the enabled,
fail-closed, cleanup, and re-enabled smoke tests.

The v0.4.7-r1 follow-up also preserves marker configuration separately from
live hook availability. If the LSPosed hook is temporarily unavailable, the UI
continues to show that RTL read-only is configured instead of falsely showing
**Off**. Selecting **Off** or switching to LTR can still remove that read-only
marker without a handshake, preventing it from silently reactivating when the
module returns. Externally managed editable markers remain distinguishable from
the plug-in's read-only marker.

The exact v0.0.62 LSPosed companion source and its Windows build wrapper are
tracked in [`native-spread-module/`](native-spread-module/README.md). Generated
APKs remain build artifacts and are not committed.

## Proven hardware foundation

The reader has been validated on a Supernote Nomad running the plugin beta firmware:

- the official SDK supplies the currently open PDF path and page index;
- Android `PdfRenderer` renders that PDF inside PluginHost without root;
- RTL swipes and edge taps work on-device;
- landscape two-page spreads and **Treat Cover Page Separately** work;
- per-PDF RTL Reader settings and position persist independently of the source PDF;
- on Close, RTL Reader can synchronize its current PDF page back into Supernote's native document reader and return there automatically.

**Root is not required for the reading path or the native-reader page handoff on the tested Nomad firmware.**

## Native-reader handoff

Hardware investigation established that:

- Supernote stores the native document position in `CONFIG/config.data` as a Java-serialized `HashMap`;
- `currentPage` is a zero-based String;
- manually changing `currentPage` and restarting `DocumentActivity` reopens the PDF at that page;
- PluginHost and `com.supernote.document` are separate processes, but both run as `system` UID 1000 on the tested firmware;
- PluginHost itself can locate, deserialize, rewrite, and verify the native `config.data` without root;
- the working implementation uses direct Android process and Activity APIs rather than shell `am` commands.

On Close, RTL Reader:

1. flushes RTL Reader's normal per-PDF preferences;
2. locates the native per-document config by PDF inode;
3. verifies both the stored inode and file URI;
4. changes only `currentPage` and verifies the serialized write;
5. performs the ordinary PluginHost Close;
6. from a delayed PluginHost worker, locates the `com.supernote.document` PID;
7. signals only that process using Android's direct `Os.kill()` API;
8. starts the private `DocumentActivity` directly using an explicit Android `Intent`;
9. the native reader reopens the same PDF at the page where RTL Reader was closed.

This full sequence has been confirmed on the test Nomad without `su`.

## View modes

The Settings panel offers:

- **Auto**: portrait = single page, landscape = two-page spread;
- **Single**: force one page regardless of orientation;
- **Spread**: force two-page mode regardless of orientation.

## Reading direction

The reader starts in **RTL** mode unless that PDF has saved preferences.

RTL single-page navigation:

- swipe right / tap right edge -> next PDF page;
- swipe left / tap left edge -> previous PDF page.

LTR reverses those physical directions.

In spread mode, navigation moves two PDF pages at a time.

## Two-page order

RTL spreads are shown like a physical Hebrew book:

```text
later page | earlier page
     11    |     10
```

LTR spreads use the opposite visual order:

```text
earlier page | later page
      10     |     11
```

## Treat Cover Page Separately

`Cover: On` inserts a virtual blank after the PDF cover. The PDF itself is never changed.

RTL example:

```text
Blank | Cover
Page 3 | Page 2
Page 5 | Page 4
```

LTR mirrors the physical layout:

```text
Cover | Blank
Page 2 | Page 3
Page 4 | Page 5
```

## Reader controls

- Tap the center to hide/show controls.
- Prev / Next follow the selected RTL/LTR physical reading orientation.
- Tap the page/spread counter to jump to a PDF page.
- `Close` synchronizes the current PDF page back to Supernote's native reader and returns there.

## Build

The build follows Ratta's official React Native 0.79.2 plugin template:

```bash
chmod +x build.sh
./build.sh
```

The resulting package is written to:

```text
out/*.snplg
```

GitHub Actions uploads the current stabilization build as the `supernote-rtl-reader-v0.4.3` artifact.

## Install and diagnostics

1. Copy the `.snplg` to `MyStyle`.
2. Open **Settings -> Apps -> Plugins** and install/update **RTL Reader**.
3. Open a PDF in the native document reader and tap **RTL Reader**.

ADB diagnostics:

```powershell
.\adb logcat -c
.\adb logcat -v raw | Select-String RTL_READER
```
