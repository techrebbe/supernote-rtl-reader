# Supernote RTL Reader

A Supernote plugin focused on right-to-left PDF reading and landscape two-page spreads, designed especially for Hebrew books.

## Stable baseline

v0.2.1 is the current merged hardware-validated stable baseline on Supernote Nomad. It includes the v0.0.9 reading engine, the v0.1.1 UI/settings pass, renderer reuse, and the validated recent-render cache.

The stable baseline covers:

- portrait and landscape reading;
- RTL/LTR navigation;
- Auto / Single / Spread modes;
- **Treat Cover Page Separately** parity;
- per-PDF settings and page persistence;
- boundary cases;
- direction-aware Prev/Next footer placement;
- renderer reuse and a recent-render cache;
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

## v0.3.0 direct native rendering — experimental, hardware measured

v0.3.0 replaces the foreground `Bitmap -> PNG -> Base64 -> React Native Image` path with a native Android `PdfPageView` that draws the `PdfRenderer` bitmap directly.

The first Nomad timing capture confirms the intended bottleneck is gone:

- `pngMs=0` on every captured direct-view render;
- `base64Ms=0` on every captured direct-view render;
- renderer reuse remains active, normally `openMs=0–1` after initial open;
- steady-state completed page renders are typically around 140–145 ms total;
- v0.2.1 uncached native renders were about 419 ms median, so the direct foreground path is roughly 3× faster at the native-render stage.

Diagnostic marker:

```text
RTL_READER_NATIVE_VIEW_RENDER page=... reused=... openMs=... renderMs=... pngMs=0 base64Ms=0 totalMs=...
```

The native view also uses a generation counter so a superseded render result is recycled and discarded rather than displayed after a newer page request. Full visual/navigation/handoff hardware validation is tracked separately in `REGRESSION.md`; the timing mechanism itself is now confirmed on the test Nomad.

## Proven hardware foundation

The reader has been validated on a Supernote Nomad running the plugin beta firmware:

- the official SDK supplies the currently open PDF path and page index;
- Android `PdfRenderer` renders that PDF inside PluginHost without root;
- RTL swipes and edge taps work on-device;
- a bounded render cache improves ordinary sequential page turns;
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

GitHub Actions uploads the current experimental direct-render build as the `supernote-rtl-reader-v0.3.0` artifact.

## Install and diagnostics

1. Copy the `.snplg` to `MyStyle`.
2. Open **Settings -> Apps -> Plugins** and install/update **RTL Reader**.
3. Open a PDF in the native document reader and tap **RTL Reader**.

ADB diagnostics:

```powershell
.\adb logcat -c
.\adb logcat -v raw | Select-String RTL_READER
```
