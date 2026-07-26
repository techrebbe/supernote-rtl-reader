# Supernote RTL Reader

A Supernote plugin focused on right-to-left PDF reading and landscape two-page spreads, designed especially for Hebrew books.

## Proven hardware foundation

The core reader has been validated on a Supernote Nomad running the plugin beta firmware:

- the official SDK supplies the currently open PDF path and page index;
- Android `PdfRenderer` renders that PDF inside PluginHost without root;
- RTL swipes and edge taps work on-device;
- a bounded render cache improves ordinary sequential page turns;
- landscape two-page spreads and **Treat Cover Page Separately** work;
- per-PDF RTL Reader settings and position can be persisted independently of the source PDF.

Root is not required for the core reading path.

## v0.0.9 native-reader handoff test

Hardware investigation on the Nomad established that:

- Supernote stores the native document position in `CONFIG/config.data` as a Java-serialized `HashMap`;
- `currentPage` is a zero-based String;
- manually changing `currentPage` and restarting `DocumentActivity` reopens the PDF at that page;
- PluginHost and `com.supernote.document` are separate processes, but both run as `system` UID 1000 on the tested firmware;
- v0.0.8 proved that PluginHost itself can locate, deserialize, rewrite, and verify the native `config.data` without root;
- v0.0.8's remaining failure was specifically the use of the `am` shell command from a PluginHost child process.

On Close, v0.0.9 therefore attempts to:

1. flush RTL Reader's normal per-PDF preferences;
2. locate the native per-document config by PDF inode;
3. verify both the stored inode and file URI;
4. change only `currentPage` and verify the serialized write;
5. perform the ordinary PluginHost Close;
6. from a delayed PluginHost worker, locate the `com.supernote.document` PID;
7. signal only that process using Android's direct `Os.kill()` API;
8. start the private `DocumentActivity` directly using an explicit Android `Intent`, rather than invoking the `am` shell utility.

The handoff remains an experimental hardware test until this final process-restart path is confirmed on-device. Config access itself has already been confirmed to work as UID 1000 without `su`.

## View modes

The top `Auto` button cycles through:

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
- `-` / `+` move one page in Single mode or one spread in Spread mode.
- Tap the page/spread counter to jump to a PDF page.
- `Close` returns to Supernote's native reader; v0.0.9 experimentally attempts to synchronize that native page first.

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

GitHub Actions uploads it as the `supernote-rtl-reader-v0.0.9` artifact.

## Install and diagnostics

1. Copy the `.snplg` to `MyStyle`.
2. Open **Settings -> Apps -> Plugins** and install/update **RTL Reader**.
3. Open a PDF in the native document reader and tap **RTL Reader**.

ADB diagnostics:

```powershell
.\adb logcat -c
.\adb logcat -v raw | Select-String RTL_READER
```

Useful v0.0.9 handoff markers include:

- `RTL_READER_HANDOFF_CONFIG_WRITTEN`
- `RTL_READER_HANDOFF_PREPARED`
- `RTL_READER_HANDOFF_WORKER_START`
- `RTL_READER_HANDOFF_DOCUMENT_PIDS`
- `RTL_READER_HANDOFF_KILL_SENT`
- `RTL_READER_HANDOFF_KILL_CONFIRMED` / `...KILL_FAILED`
- `RTL_READER_HANDOFF_START_REQUESTED_DIRECT`
- `RTL_READER_HANDOFF_WORKER_FAILED`
- `RTL_READER_HANDOFF_SKIPPED`
- `RTL_READER_HANDOFF_FAILED`
