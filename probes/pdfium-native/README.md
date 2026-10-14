# Isolated PDFium diagnostic — T018P

This is **not** a production RTL Reader replacement or upgrade. Nothing here is
imported, registered or copied by its installer. Saved ink remains parked;
existing portrait/RTL spreads/Bluetooth/SDK Edit-Return remain unchanged.

The user approved a source-only prototype after the unrooted Nomad's valid
WebView109 failed the proposed current PDF.js Chrome125 browser prerequisite.
No system browser update, root, stock writer hook, native annotation/save route,
conversion or user sidecar is introduced.

## Engine authority and limits

Pin `bblanchon/pdfium-binaries` immutable release chromium/8100,
PDFium157.0.8100.0, published2026-10-12, publisher source/signing commit
`5b4d6b2ede1c1b0e17f5dc7b996c42d68d534ca8`. This third-party publisher is **not**
Google upstream. Three archive hashes/sizes, attestation and extracted engine
hashes are in `pdfium.lock.json`; all three hosted build attestations were
cryptographically verified against the pinned repository/workflow/source/signer.
This authenticates provenance, not absence of engine bugs or hardware fidelity.
Actual GN flags: V8=false/XFA=false; Android arm/arm64 minAPI23. All native
third-party notices ship in the diagnostic APK. Compiler headers now come from
fresh hash-verified archive extraction, never a mutable prior extracted tree.

Public C API only: render, Unicode/character boxes, original direct/named/same-page
link destinations and outline titles/ordering/hierarchy. Fit and nullable XYZ
are supported; other modes/actions explicitly reject. No execute-action or form
environment exists; URI/JavaScript/Launch/remote links cannot dispatch an intent.
All input is the embedded, immutable four-page generated disposable fixture,
SHA256 `7cf9de8fa7ed91f7746ac44f62aa63e0641f757f330cf7d83efec7584b213905`.
No personal file input, storage/network permission or native-reader access.

Serialized process-wide open/read/close FIFO and monotonic native session tokens
prevent stale ownership/close and destroyed-Activity reopen races. Generation
fences bind bitmap/text/links/page/dimensions; native rendering and hit rectangles
use PDFium's same page-to-device transform, crop clipping and bitmap bounds.
Generated/missing-box separators survive copy; cropped source text is excluded.
Four-million pixels/20k characters/1000 links/outlines and depth32 cap work.

## Evidence and unverified behavior

Actual Windows API characterization: **7 tests PASS**, all four rendered images
inspected, exact direct/named/null-XYZ targets, crop/rotation/inverse mapping,
hierarchical Unicode outlines, English phrase and real glyph hit observed.
First host run completed API/output but failed printing Hebrew to CP1252;
corrected ASCII summary run exited0. Neither run changed the fixture.

Both Android ARM ABIs compiled using NDK27/C++17 warnings-as-errors, actual
Android35/JDK17 Java→DEX and separate signed APK built. The first independent
source review found six P2 defects (no P0/P1); these were corrected together
with five focused regression tests and **16 actual-Java helper assertions**.
Correction review/exact clean-head package evidence is recorded in T018P,
not inferred from this README.

Android runtime, visual comfort/performance, RTL dual-page integration, real
Bluetooth and logical Hebrew copy order remain **UNVERIFIED**. The existing
fixture has visually shaped Hebrew, so it cannot establish general logical copy
fidelity. This diagnostic is single-page with button zoom/pan (no pinch).
Link back restores original page in Fit, not prior pan/zoom. Reopening starts
PAGE1. Final product integration must reuse existing original-document READ,
per-document preferences, RTL pairing/cover, key transport and SDK Edit/Return.

Package `com.techrebbe.rtl.pdfiumprobe`, `0.1.0-pdfium-exp1`, code1, min23/target35,
ARM32/64, separate label RTL PDFium Probe. Exact diagnostic debug certificate
`a5a8551131de84d41660a3cf22d224f320f7a2f05a380282f76f6fe731807c67`;
**not** production plug-in certificate `fac617…3b9c`. No keys are shipped/uploaded.
Early failed/pre-review builds are preserved but are not install candidates.

## Reproduction (offline after authenticated download)

Use Python3+Pillow, JDK17, Android35/build-tools35.0.0 and NDK27.0.12077973.
Set JAVA_HOME and an owned writable TEMP/TMP for tests/builds.

1. `fetch_engine.ps1 -OutputDirectory <fresh>` verifies hashes, hosted attestations
   and bounded regular archive entries before extraction; network is only fetch.
2. `python test_probe.py --engine <verified-root> --fixture <exact-fixture>`.
3. `python -m unittest discover -s probes/pdfium-native -p test_boundaries.py -v`.
4. From a clean archive of the exact reviewed commit, `build_probe.ps1` requires
   EngineRoot, Fixture, fresh OutputDirectory, PythonExecutable, local Keystore,
   exact ExpectedSignerSha256 and SourceCommit. It authenticates fresh native
   build inputs, compiles, normalizes/aligns/signs and writes `build-receipt.json`.
5. `verify_package.py --apk ... --engine <authenticated-engine> --aapt ...
   --receipt ... --expected-commit ...` checks the **complete** entry allowlist,
   source/normalizer hashes, whole signed APK and every payload hash, original
   engine/notices, zero permissions and exact package/version/ABI markers.

The local receipt binds executed build inputs/output; it is not an independent
attestation that an arbitrary APK was compiled from source. Two fresh exact-head
reproducible builds plus signer verification are required for the install
candidate. Preserve receipts/build evidence locally, not in repository assets.

No device command exists in the build. Earliest hardware gate is the bounded
T018P-H plan, fresh explicit approval, issue23 exclusive reservation and exact
identity/power/package preflight. Do not install by merely building this probe.
