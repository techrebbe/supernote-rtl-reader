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

## v0.0.1 hardware proof

The first build is intentionally much smaller. It tests the one architectural dependency that everything else needs:

1. Open a PDF in Supernote's native DOC reader.
2. Navigate to any page.
3. Tap **RTL Reader** in the DOC toolbar.
4. The plugin asks the official Supernote SDK for the current file path and page index.
5. A small Kotlin native module opens that same PDF with Android `PdfRenderer`.
6. The current page is rendered into the full-screen plugin UI.

### Pass criteria

The page shown inside RTL Reader matches the PDF and page that were open in Supernote, at readable quality, without crashing PluginHost.

No RTL navigation, two-page layout, cover offset, zoom, or annotation support is included yet. Those come only after this rendering proof passes on real hardware.

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

GitHub Actions also uploads the package as the `supernote-rtl-reader-v0.0.1` artifact.

## Install and test

1. Download the `.snplg` build artifact.
2. Copy it to the Supernote `MyStyle` directory.
3. Open **Settings → Apps → Plugins** and install/update **RTL Reader**.
4. Open a PDF in the native document reader.
5. Navigate to a distinctive page.
6. Tap **RTL Reader**.

For diagnostics over ADB:

```powershell
.\adb logcat -c
.\adb logcat -v raw | Select-String RTL_READER
```

Expected success output includes a line similar to:

```text
RTL_READER_RENDERED file=/storage/emulated/0/.../book.pdf page=42 size=1404x1986
```

If the plugin UI reports that the PDF file is inaccessible, that specifically tells us the beta PluginHost cannot directly read the DOC file path. Since the test Nomad is rooted, the next fallback would be an Android-side privileged/file-descriptor bridge rather than changing the reader design.
