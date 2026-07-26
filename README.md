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

## v0.0.8 hardware test

v0.0.8 tests native-reader page handoff on Close.

Hardware investigation on the Nomad established that:

- Supernote stores the native document position in `CONFIG/config.data` as a Java-serialized `HashMap`;
- `currentPage` is a zero-based String;
- manually changing `currentPage` and restarting `DocumentActivity` reopens the PDF at that page;
- PluginHost and `com.supernote.document` are separate processes, but both run as `system` UID 1000 on the tested firmware.

On Close, v0.0.8 therefore attempts to:

1. flush RTL Reader's normal per-PDF preferences;
2. locate the native per-document config by PDF inode;
3. verify both the stored inode and file URI;
4. change only `currentPage` and verify the serialized write;
5. schedule a UID-1000 document-reader restart without invoking `su`;
6. perform the ordinary PluginHost Close regardless, so a failed experimental handoff cannot trap the user.

The native-reader handoff is still a hardware test until confirmed on-device. The reader itself remains usable if handoff preparation fails.

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
- `Close` returns to Supernote's native reader; v0.0.8 experimentally attempts to synchronize that native page first.

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

GitHub Actions uploads it as the `supernote-rtl-reader-v0.0.8` artifact.

## Install and diagnostics

1. Copy the `.snplg` to `MyStyle`.
2. Open **Settings -> Apps -> Plugins** and install/update **RTL Reader**.
3. Open a PDF in the native document reader and tap **RTL Reader**.

ADB diagnostics:

```powershell
.\adb logcat -c
.\adb logcat -v raw | Select-String RTL_READER
```

Useful v0.0.8 handoff markers include:

- `RTL_READER_HANDOFF_CONFIG_WRITTEN`
- `RTL_READER_HANDOFF_PREPARED`
- `RTL_READER_HANDOFF_WORKER_START`
- `RTL_READER_HANDOFF_FORCE_STOP_OK` / `...FAILED`
- `RTL_READER_HANDOFF_START_OK` / `...FAILED`
- `RTL_READER_HANDOFF_SKIPPED`
- `RTL_READER_HANDOFF_FAILED`
