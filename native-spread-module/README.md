# Supernote Native Spread companion module

This LSPosed module supplies the rooted native-reader enhancement controlled by
Supernote RTL Reader. It keeps Supernote's own PDF renderer, links, highlights,
and `.mark` annotation data while adding:

- RTL page progression in portrait;
- automatic two-page RTL spreads in landscape;
- optional separate-cover parity;
- per-document opt-in through a hidden `.snspread` sidecar;
- a fail-closed read-only pilot mode.

## Compatibility and safety

The module intentionally refuses to operate unless all of these match the
hardware-tested environment:

- firmware fingerprint
  `Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys`;
- `SupernoteDocument` version code `102446`;
- document APK length `138486560` bytes;
- LSPosed scope limited to `com.supernote.document`;
- an enabled marker beside the current PDF.

The plugin-created marker always sets `editable=false`. In that mode v0.0.62
forces a full-page disabled handwriting region and blocks the native
annotation-commit callback. It displays existing `.mark` ink but does not allow
new native writing. Editable hooks remain restricted to the explicitly marked
disposable calibration workflow and are not exposed by the plugin UI.

Before the plugin reports this mode as active or creates a marker, it sends a
random challenge to the currently hooked `DocumentActivity`. The module answers
only after all hooks have registered and only when the challenge names the PDF
that is actually open. The response binds the nonce to the handshake protocol,
module version, document APK identity, and live document-process PID. An
installed-but-disabled, incorrectly scoped, or compatibility-rejected module
therefore fails closed.

v0.0.62 also clears the destroyed activity reference and recycles all
per-activity full-resolution page, ink, and digest bitmaps when the native
reader closes.

This is firmware-specific experimental software for a rooted device. Back up
documents and `.mark` files before testing a new firmware or module revision.

## Build

Requirements:

- JDK 17 with `javac` and `jar` on `PATH`;
- Android SDK platform and build-tools 35.0.0;
- Android NDK 27.0.12077973;
- an Android debug keystore.

`build.ps1` reads `ANDROID_SDK_ROOT` or `ANDROID_HOME`, and
`ANDROID_NDK_HOME` when set. Paths can also be passed explicitly:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
```

The signed APK is written to `build/artifact/`.

## Install

Install the APK, enable **Supernote Native Spread Probe** in LSPosed, scope it
only to `com.supernote.document`, and restart the document reader. Supernote
RTL Reader v0.4.7 or newer is required for the current read-only pilot control.

## Hardware validation

v0.0.61 passed on a rooted Supernote Nomad using both a disposable calibration
PDF and a protected copy of a 738-page annotated Hebrew PDF. The real-document
pass confirmed persistent two-page annotation display, outer-edge-only tap
navigation, side-preserving spread turns, and an unchanged `.mark` checksum.

v0.0.62 compiles and passes automated handshake and destroyed-activity cleanup
invariants. Its focused hardware regression is tracked in the root
`REGRESSION.md`.
