# T018D — interactive engine choice after measured WebView incompatibility

Owner codex; agent/page-turner-bridge. Source-only comparison2026-10-14,
not a new engine implementation, dependency download/build or installation.
T018C is COMPLETE/released6161799646 from6161740390: unrooted3.30.45/API30,
valid Google WebView109.0.5414.117 below PDF.js6.4.299 legacy Chrome125 floor.
Desktop proof preserved; installed reader untouched. Wi-Fi10.0.40.9:5555 verified.

## Recommendation / decision boundary

Prefer an app-contained maintained native PDF engine over replacing the system
WebView. PDFium is the first candidate to assess, not a selected/shipped binary.
This avoids requiring the user to change shared device software; it still needs
a pinned Android build/ABI/provenance and our selection/hit-testing integration.
This is an engineering inference, not a demonstrated Nomad performance result.
Get the user's decision before expanding the implementation to a native-engine
integration or any system browser change. Do not resurrect the stock writer
inside custom viewports, conversion, root, or parked saved-ink work.

| Route | Benefit | Cost / unresolved risk |
|---|---|---|
| Bundled PDFium + our native page surface | No system browser change; public rendering/text/link/outline APIs; reuse our original-page navigation | Moderate-high adapter/build effort: reproducible current Android native binary, JNI lifetimes, bounded memory, selection UI and Unicode/crop fidelity; actual Android11/ABI support not yet verified |
| Bundled MuPDF + our native surface | Another app-contained engine candidate, rather than dependence on WebView109 | Native integration still needed; AGPL/commercial choice must be settled before adoption, no license purchase or assumption of whole-app license compatibility |
| Update system WebView, retain current PDF.js proof | Least viewer-source rework if a compatible provider can actually be installed | Shared device-package/signature/provider/Android compatibility and rollback unknown; separately approved task required; may affect other apps; not an assumed safe shortcut |

No finite delivery estimate or performance ranking is asserted before an actual
candidate build/fixture trial. No unmaintained old PDF.js workaround.

## Concrete evidence, not a stock-writer audit

PDFium exposes original-page loading/rendering and an explicit rendering matrix;
text APIs expose Unicode, character boxes and hit testing in PDF user space.
Links expose destinations/actions and original zero-based target pages; outlines
expose child/sibling/title navigation. XYZ APIs have nullable coordinate/zoom
flags; generic fit-view extraction is marked experimental, so pin/test that ABI
and reject unsupported/lossy semantics rather than guessing. Source APIs do not
provide our selection UI or prove correct Hebrew logical copy order.
[Rendering](https://pdfium.googlesource.com/pdfium/+/refs/heads/main/public/fpdfview.h),
[text](https://pdfium.googlesource.com/pdfium/+/refs/heads/main/public/fpdf_text.h),
[links/outlines](https://pdfium.googlesource.com/pdfium/+/refs/heads/main/public/fpdf_doc.h).

PDFium uses Chromium/GN/Ninja tooling and documents Android arm builds;
JS/V8 and XFA are enabled by default but can be disabled. A candidate must disable
both and expose no save/form/action-execution bridge. Current upstream LICENSE
contains BSD-style and Apache2 text; inventory actual linked third-party notices
and redistribution obligations, not just a wrapper's license.
[Build](https://pdfium.googlesource.com/pdfium/+/refs/heads/main/README.md),
[license](https://pdfium.googlesource.com/pdfium/+/refs/heads/main/LICENSE).
MuPDF's publisher offers AGPL and commercial licensing; that is a decision gate,
not legal clearance or approval to buy a license.
[MuPDF licensing](https://mupdf.readthedocs.io/en/latest/license.html).

## Reuse / smallest proposed implementation after decision

Current native/PdfRendererModule.kt.template uses Android PdfRenderer with a
read-only FD, source-bound session/cache and serialized page access; native
PdfPageView owns the bitmap surface. It is not an exposed interactive engine on
API30. Do not mix unrelated renderer and text matrices without proving agreement.

Retain per-document READ/source validation/preferences, logical Next/Previous,
RTL pairing/cover rules, original page identity, reader-owned Bluetooth transport,
modal/transition fences and supported SDK Edit/Return. Reuse the desktop fixture,
destination rejection cases and viewport/history lessons, not its WebView runtime.

First bounded native slice: one disposable source page rendered by the same
engine that provides its text/link coordinates, known direct/named destinations
and outline tree. Original PDF/annotations remain read-only; no required user
sidecar. Finite/pixel/text/outline bounds and document/generation/close guards;
fail explicit on unsupported actions/destinations. No writer/ink/save integration.
Then viewport focus, zoom/pan and both RTL halves share that exact page-to-view
transform. Reading coordinates do not silently change frozen native ink contracts.

Earliest safe hardware gate: pinned reproducible compatible native candidate,
focused source/ABI/lifecycle/fixture tests and independent narrow review, exact
signed package, fresh approved issue23 reservation; one disposable portrait
link/text/bookmark/zoom trial, then separate RTL/rotation/Bluetooth/Edit-return.
No speculative emulator prerequisite or broad rewrite. Original device check
is complete; no further device action is authorized by this comparison.
