# Supernote RTL Reader

A Supernote plugin focused on right-to-left PDF reading and landscape two-page spreads, designed especially for Hebrew books.

## Roadmap

The intended reader behavior is:

- right-to-left or left-to-right page progression per document;
- portrait single-page reading;
- landscape two-page spreads;
- Hebrew/RTL spread order (`left = later page`, `right = earlier page`);
- **Treat Cover Page Separately**, implemented as a virtual blank after the cover so later spreads stay aligned with the physical book;
- remembered reading settings and position per document.

## Proven hardware foundation

v0.0.1 was validated on a Supernote Nomad running the plugin beta firmware. The official SDK successfully supplied the currently open PDF path and page index, and a small Kotlin bridge rendered that exact page through Android `PdfRenderer` inside PluginHost.

That proof established that the reader can stay entirely within the supported plugin architecture for its core PDF rendering path; root was not required.

## v0.0.2 navigation build

This build turns the rendering proof into a basic single-page reader.

### Reading direction

The reader starts in **RTL** mode. Tap the `RTL` button at the top to switch between RTL and LTR.

In RTL mode:

- swipe **right** -> next PDF page;
- swipe **left** -> previous PDF page;
- tap the **right edge** -> next PDF page;
- tap the **left edge** -> previous PDF page.

LTR mode reverses those physical gestures while keeping PDF page numbers increasing normally.

### Reader controls

- Tap the center of the page to hide/show the reader controls.
- `-` and `+` move one PDF page backward/forward regardless of reading direction.
- Tap the page counter to enter a PDF page number and jump directly to it.
- `Close` returns to Supernote's native document reader.

The current build intentionally does not yet synchronize the new page position back into the native reader when closing.

### Hardware acceptance test

1. Open a PDF in native Supernote DOC and launch **RTL Reader**.
2. Confirm it starts on the same page.
3. In RTL mode, swipe right several times and verify the PDF page number increases.
4. Swipe left and verify it decreases.
5. Test both right/left edge taps.
6. Switch to LTR and verify the physical swipe/tap directions reverse.
7. Tap the page counter and jump to a known page.
8. Tap the center of the page and verify the controls hide/show.
9. Confirm `-` and `+` always decrement/increment the PDF page number, independent of RTL/LTR.

Once this passes, the next milestone is landscape two-page spreads plus **Treat Cover Page Separately**.

## Build

The build follows Ratta's official React Native 0.79.2 plugin template and overlays the reader code:

```bash
chmod +x build.sh
./build.sh
```

The resulting package is written to:

```text
out/*.snplg
```

GitHub Actions also uploads the package as the `supernote-rtl-reader-v0.0.2` artifact.

## Install and diagnostics

1. Download the `.snplg` build artifact.
2. Copy it to the Supernote `MyStyle` directory.
3. Open **Settings -> Apps -> Plugins** and install/update **RTL Reader**.
4. Open a PDF in the native document reader and tap **RTL Reader**.

For diagnostics over ADB:

```powershell
.\adb logcat -c
.\adb logcat -v raw | Select-String RTL_READER
```

Useful log markers include:

```text
RTL_READER_OPENED
RTL_READER_RENDERED
RTL_READER_NAV
RTL_READER_DIRECTION
RTL_READER_JUMP
```
