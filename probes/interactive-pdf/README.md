# T018 desktop-only interactive original-PDF proof

This isolated prototype is **not installed, packaged, imported by App.js or
registered with the plug-in**. Production navigation, native Edit/Return, SDK
0.1.65 and saved-ink code are unchanged. No Nomad access is needed to run it.
Saved-ink work remains parked. Original PDFs/annotations are never inputs to the
fixture generator and must not be used in this proof.

## What this proves, and what it does not

The local PDF.js canvas, selectable text and link layers share the same original
page viewport, including CropBox and /Rotate. Outlines retain titles, hierarchy
and ordering. Direct/named destinations resolve against original zero-based page
indices, not Virtual Spread indices. Supported modes are Fit, XYZ and FitH;
unsupported modes/actions are explicit errors. XYZ null/zero zoom retains the
effective magnification and nullable coordinates retain the prior top-left.
Destination/history scroll anchors use the canvas and scroll viewport rectangles,
not body-relative offsetTop. Zoom rerenders from the source with a 16M backing-
pixel budget; this is a bounded prototype budget, not a Nomad performance promise.

The server adapts the actual existing original-page pairing functions and
pageTurnerKeys controller into browser modules rather than copying their logic.
Cover is paired in this proof. Keyboard simulation is opt-in and local-page-
focused; it is **not** evidence about physical Bluetooth delivery on Android.
The native ReaderKeyHost, permissions and Edit/Return are not integrated here.
Nothing writes PDF text highlights, native ink or any .mark file. Scans without
embedded text have no selection/OCR promise. Pointer selection on desktop does
not establish touch/pen selection or correct Hebrew copy order on the Nomad.

Embedded script/Launch/custom-scheme actions are disabled; only HTTP(S) external
links can ask for explicit confirmation. Browser checks dismiss that confirmation
without opening a website. A failed/stale render leaves the old surface inert;
request/navigation generations fence asynchronous work. No production state
serialization or replacement-document return contract is changed by this proof.

## Dependency and reproducibility

`pdfjs.lock.json` pins PDF.js 6.4.299, Apache-2.0 and the exact official npm
archive SHA-512 integrity. It is not a production dependency. Fetch the specified
archive into a new ignored task directory, verify the integrity **before**
extracting its `package/` tree, and reject escaping paths or symlink entries.
Do not run npm install scripts or commit vendor assets. The server rechecks the
archive integrity and extracted package name/version before serving anything.

The documented legacy engine floor is Chrome125. The Nomad's embedded WebView
version and feature support remain **UNVERIFIED**. A modern PC browser PASS is
not grounds to ship this engine on Android11/API30. Do not silently replace the
device's WebView or choose an unmaintained old PDF.js as a shortcut. API30's
current Android PdfRenderer bitmap surface is not the API35 text/link surface.

Sources: [PDF.js FAQ](https://github.com/mozilla/pdf.js/wiki/Frequently-Asked-Questions),
[document API](https://mozilla.github.io/pdf.js/api/draft/module-pdfjsLib-PDFDocumentProxy.html),
[page API](https://mozilla.github.io/pdf.js/api/draft/module-pdfjsLib-PDFPageProxy.html),
[Android PdfRenderer.Page](https://developer.android.com/reference/android/graphics/pdf/PdfRenderer.Page).

From the repository root, with reportlab/pypdf and a local Hebrew-capable font:

```text
python probes/interactive-pdf/make_fixture.py --output <fresh-task-dir>/interactive-original-fixture.pdf --font <local-font.ttf>
node --test probes/interactive-pdf/test_destinations.mjs
python probes/interactive-pdf/test_fixture.py
node probes/interactive-pdf/server.mjs <verified-package-dir> <fresh-fixture.pdf> 49731
```

The font path is read-only; no font binary is published. Generated PDF/manifest,
vendor assets and browser evidence remain ignored/local. The fixed fixture
manifest is diagnostic authority only, **not a required product PDF sidecar**.
The server binds only 127.0.0.1, serves the verified disposable PDF in memory,
whitelists source routes/vendor paths, and has no upload/write endpoint. Close
only this proof's owned browser session/server when checks finish.

## Desktop evidence — 2026-10-14

Disposable v2 SHA256 `7cf9de8fa7ed91f7746ac44f62aa63e0641f757f330cf7d83efec7584b213905`:
four pages, five page1 links (direct/named/same-page/external/script canary),
nested outline with Hebrew title, page2 CropBox20,30,590,750 and /Rotate90.
Poppler renders all four pages inspected. The fixture's shaped Hebrew extraction
appears in visual order, so **logical Hebrew copy-order correctness is UNKNOWN**;
do not present this fixture as a general Hebrew text-selection fidelity pass.
Earlier fixture and failed bootstrap evidence retained, not overwritten.

Observed in isolated Chrome155/PDF.js6.4.299: portrait direct link1→2 and return;
named link1→3 at XYZ44,738/zoom1.25 and return; same-page identity retained;
external confirmation dismissed; unsafe script canary disabled/not executed;
outline hierarchy/order and Hebrew-title destination→4; zoomed direct hit→2;
pointer-selected known English phrase; RTL landscape left2/right1 and named
target left4/right3 with active3, then portrait retains3; opt-in local PageDown
simulation advances3→4. Three concrete prototype defects were corrected:
duplicate exported binding, removed PDF.js rectangle helper, and body-relative
scroll anchor. A fourth real API mismatch, removed document-proxy destroy, is
fixed with loading-task-owned idempotent cleanup; real engine task destruction
and viewer pagehide inert/not-ready with zero warnings/errors were observed.
Actual engine page2 scale2 viewport1440x1140 maps source rect40,50,140,70 to
left40/top40/width40/height200. Fixture SHA unchanged before/after; no .mark.
Focused regressions cover these and nullable XYZ view semantics. First independent
review's two P2s (failure enables unusable zoom; manifest overwrite) corrected:
settled-surface guards retain explicit Fit recovery, and both fresh output leaves
are checked with exclusive manifest creation. Independent source confirmation
CLEAN/no critical-high blocker; zoom and loading-task cleanup CLOSED. Fixture
overwrite source corrected and six independent no-write authority checks PASS;
the reviewer did not run filesystem tests in its read-only environment. Owner
filesystem regressions PASS; do not claim an independent filesystem execution.

Owner checks: 11 focused Node tests plus5 Python fresh-output tests PASS (three
real temporary-file refusal/race cases, two mocked symlink metadata cases); combined
existing navigation/key-route/transport/Edit-return suite88 tests PASS; unchanged
native-renderer/Edit/v2/cross-layer invariant gates PASS. Initial missing Python/
PyYAML/default-temp host failures resolved through existing environment paths,
not production changes. No package rebuild or parked ink investigation performed.
Browser sessions and loopback servers stopped; evidence remains local/ignored.

This is not an integrated product/hardware/release PASS. Pending: real WebView
capability; supported engine choice if inadequate; production permission/source
transport, renderer lifecycle/limits, native-key focus/modal integration and
exact-page SDK Edit/Return; independently reviewed signed candidate; disposable
Nomad portrait then RTL/rotation/Bluetooth gates. The next device operation must
be separately approved/reserved and read-only; no root or installation is implied.
