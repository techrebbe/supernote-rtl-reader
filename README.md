# Supernote RTL Reader

A Supernote plugin focused on right-to-left PDF reading and landscape two-page spreads, designed especially for Hebrew books.

## Stable baseline

v0.4.2 is the current merged hardware-validated stable baseline on Supernote Nomad. v0.4.3 is a stabilization release candidate that preserves the v0.4.2 renderer while consolidating its source/build path and hardening initial layout handling.

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

## v0.4.5 native-reader pilot control

v0.4.5 adds a safe per-document control for the rooted Native Spread module.
In Reading settings, **Supernote native reader** offers:

- **Off** — remove this PDF's hidden native-spread setting;
- **RTL read-only** — enable RTL portrait navigation, automatic landscape
  spreads, and the current cover-separate parity in Supernote's native reader.

The plug-in verifies the exact supported firmware, SupernoteDocument build,
and Native Spread module version before enabling the setting. It requires
Native Spread v0.0.60 or newer, whose read-only mode forces a full-screen
handwriting-disabled region and blocks the native annotation commit callback as
a persistence fail-safe. Experimental native writing remains available only
through the disposable test marker until the read-only control is validated on
a backed-up real document copy.

After enabling the pilot, close RTL Reader normally. Its existing page handoff
restarts Supernote's native reader on the same page, where the LSPosed module
reads the per-document setting. Switching the plug-in to LTR automatically
turns the native RTL setting off.

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
