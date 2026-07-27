# Supernote RTL Reader

A Supernote plugin focused on right-to-left PDF reading and landscape two-page spreads, designed especially for Hebrew books.

## Stable baseline

v0.1.1 is the current hardware-validated stable baseline on Supernote Nomad. It includes the v0.0.9 reading engine plus the validated UI/settings pass and direction-aware footer.

The stable baseline covers:

- portrait and landscape reading;
- RTL/LTR navigation;
- Auto / Single / Spread modes;
- **Treat Cover Page Separately** parity;
- per-PDF settings and page persistence;
- boundary cases;
- direction-aware Prev/Next footer placement;
- root-free native-reader page handoff on Close.

## v0.2.x performance work — experimental

The v0.2.x development branch is focused on page-turn responsiveness while preserving v0.1.1 behavior.

### v0.2.0 renderer reuse

The first performance build changes the native render lifecycle:

- keep the active PDF file descriptor and Android `PdfRenderer` open across sequential page renders;
- reuse that renderer while the PDF path, file size, and modification time are unchanged;
- automatically reopen it when the document changes;
- serialize page access so only one `PdfRenderer.Page` is open at a time;
- log native timing for document-open/reuse, raster rendering, PNG compression, base64 encoding, and total render time.

Hardware timing on a 738-page, approximately 378 MB PDF confirmed renderer reuse works. After the first render, native document-open time drops from about 85 ms to essentially 0–1 ms. Across the captured run, median timings were approximately:

- document open/reuse: 1 ms;
- PDF rasterization: 138 ms;
- PNG encoding: 265 ms;
- Base64 encoding: 8 ms;
- total native render: 426 ms.

PNG encoding is therefore the dominant remaining native cost, accounting for roughly 62% of median render time. The same capture also showed repeated requests for several pages during rapid navigation, consistent with foreground/prefetch overlap.

Diagnostic marker:

```text
RTL_READER_NATIVE_RENDER page=... reused=... cacheHit=... openMs=... renderMs=... pngMs=... base64Ms=... totalMs=...
```

### v0.2.1 recent-render cache

v0.2.1 adds a small native LRU cache of the four most recent rendered PNG byte arrays. Because `PdfRenderer` access is serialized, a duplicate request arriving behind a just-completed render can now reuse the compressed page instead of repeating rasterization and PNG compression. A cache hit only repeats the much cheaper Base64 conversion.

The v0.2.1 hardware check should confirm two things:

- ordinary reading behavior and native-reader handoff remain unchanged;
- repeated requests now appear as `cacheHit=true` with `renderMs=0` and `pngMs=0`.

This deliberately preserves the existing image format and visual quality while reducing duplicate work before considering a larger native-display redesign that could remove PNG encoding from the page-turn path entirely.

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

GitHub Actions uploads the current performance test build as the `supernote-rtl-reader-v0.2.1` artifact.

## Install and diagnostics

1. Copy the `.snplg` to `MyStyle`.
2. Open **Settings -> Apps -> Plugins** and install/update **RTL Reader**.
3. Open a PDF in the native document reader and tap **RTL Reader**.

ADB diagnostics:

```powershell
.\adb logcat -c
.\adb logcat -v raw | Select-String RTL_READER
```
