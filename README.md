# Supernote RTL Reader

A Supernote plugin focused on right-to-left PDF reading and landscape two-page spreads, designed especially for Hebrew books.

## Stable baseline

v0.0.9 is the hardware-validated reading-engine baseline on Supernote Nomad. It passed the complete regression suite covering portrait and landscape reading, RTL/LTR navigation, cover parity, persistence, boundary cases, and root-free native-reader page handoff.

## v0.1.1 UI polish — hardware validated

v0.1.1 keeps the v0.0.9 reading engine intact while refining the reader controls. The complete UI pass, including the direction-aware footer, has been validated on the test Supernote Nomad.

- compact status bar showing direction, selected layout, effective Auto layout, and cover behavior;
- dedicated e-ink-friendly Settings panel;
- explicit RTL / LTR choices;
- explicit Auto / Single / Spread choices;
- exact **Treat Cover Page Separately** option with On / Off controls;
- clearer page/spread indicator with tap-to-jump hint;
- Prev/Next footer buttons follow the selected reading direction:
  - RTL: Next on the physical LEFT, Previous on the physical RIGHT;
  - LTR: Previous on the physical LEFT, Next on the physical RIGHT;
- footer positioning is forced to physical left-to-right layout so Android RTL UI inheritance cannot reverse the slots;
- center tap still hides/shows all chrome for distraction-free reading;
- no animations.

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

GitHub Actions uploads the current hardware-validated UI build as the `supernote-rtl-reader-v0.1.1` artifact.

## Install and diagnostics

1. Copy the `.snplg` to `MyStyle`.
2. Open **Settings -> Apps -> Plugins** and install/update **RTL Reader**.
3. Open a PDF in the native document reader and tap **RTL Reader**.

ADB diagnostics:

```powershell
.\adb logcat -c
.\adb logcat -v raw | Select-String RTL_READER
```
