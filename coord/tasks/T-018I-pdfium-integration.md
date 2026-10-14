# T018I — user-approved PDFium reader integration

User2026-10-14 explicitly requests integration of the tested engine while
preserving portrait, RTL landscape, Bluetooth and supported Edit/Return.
Owner codex, owned agent/page-turner-bridge, baseline969a471. Source/build/review
work authorized; new integrated device install/test still needs exact package
approval, fresh exclusive issue23 reservation and preflight. No device action
or timer resume in this source phase. Ink PARKED, original PDFs/marks unchanged.

Scoped implementation: native/Pdfium* reader/session/interaction templates and
read-only JNI adapter; shared tested probe helpers only where named default
behavior is preserved; overlay/interactivePdf* UI/controller; generated App patch
and build/native installer/package verification, focused tests, candidate identity
and these coordination notes. Canonical old App/PdfPageView, writer/save/native
ink contracts and frozen legacy digests stay intact unless a named expectation
change is necessary and independently reviewed. No blind digest repinning.

Implement one document/session owner and serial engine queue, immutable bounded
input/fingerprint, original-page indices, atomic page/viewport request, stale
generation rejection, aggregate raster accounting and deterministic owner close.
Reuse existing logical RTL/cover/page navigation, reader-owned Bluetooth host,
preferences/READ and SDK Edit/Return. Native page owns touches; no parent responder
also intercepts selection/link/pan. No conversion/required sidecar/root/WebView
update/stock writer/global key hook/new restart route. Keep former source/evidence.

Offline gates: real current pinned production ARM64 JNI+RN compile (the SDK
compactor retains ARM64 only; diagnostic ARM32 evidence stays preserved), generated App/source
boundary tests (portrait/pairs/cover/rotation/key/modal/Edit/Close), actual helper
tests for cancellation/replacement/pan/selection/geometry/memory, required native
core+mutations+invariants, exact independent review and reproducible verified
upgrade-compatible package with complete engine notices/payload receipts.
No production success inferred from the standalone diagnostic or mocked callbacks.

Earliest safe next device gate: one disposable original-PDF portrait direct link,
selection/copy-readback/bookmark/zoom trial on the exact reviewed package, then
normal Close/integrity/rollback and release. Separate RTL halves/rotation,
Bluetooth and exact-page Edit/Return gates follow under their own defined scopes.
Stop for identity/model/ownership mismatch, unsafe action, uncertain cleanup or
major decision. Prefer decisive device evidence once source/package gates clear,
not speculative emulator work. No PR finalization or merge without user decision.
