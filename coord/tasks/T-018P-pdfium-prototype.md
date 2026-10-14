# T018P — user-approved bounded PDFium prototype

Owner codex; agent/page-turner-bridge, base71f1ebfa8ab666983425702653fe1837cd19cdec.
User2026-10-14 approved app-contained native PDFium prototype after T018C
measured WebView109 below current PDF.js floor. No system/browser/root change.

Allowed authored paths: probes/pdfium-native source/pins/fetch+build tooling/
focused tests and notes; coord/STATE.md, T018/T018D/T018P and review/handoff notes.
Ignored local task tmp holds verified vendor archives, native headers/binaries,
generated diagnostics, disposable APK and unchanged generated PDF fixture.
Do not upload vendor/raw/PDF/annotation/credential data. Existing production
App/native/install/SDK/frozen pins and installed RTL Reader remain unchanged.

First implementation slice: select one pinned maintained no-V8/no-XFA PDFium
release with verifiable publisher hashes/provenance. Validate its actual public
C API on the existing four-page disposable fixture: source rendering, crop/rotate,
text boxes/Unicode, direct/named/same-page links, outlines and destination modes.
One source-to-view matrix is shared by drawing and hit testing; no stock writer,
save, annotation, conversion or required user sidecar. Unsupported actions/modes
explicitly rejected. Do not infer Hebrew copy fidelity from visual shaped text.

Keep a strict read-only/session-owned prototype adapter: bounded immutable input,
finite geometry and allocations, serialized engine access, original page indices,
generation/source binding and deterministic close. Build an isolated Android
diagnostic only after engine API proof; use embedded disposable fixture only,
no personal storage/device privilege, writer or global key hook. This is not a
replacement production architecture: final integration must reuse existing READ,
per-document settings, RTL/cover navigation, key transport and SDK Edit/Return.

Earliest safe hardware gate: exact reviewed prototype source, actual pinned
Android ABI/API build/export/provenance verification and signed diagnostic
package; fresh explicit install/test approval, exclusive issue23 reservation,
power/identity preflight. One disposable portrait link/text/outline/zoom question,
record before any following hardware trial. Do not create speculative emulator
prerequisites. No Nomad access/install is authorized by this source-only slice.

Stop/report if binaries cannot be authenticated, maintained Android support/
required semantics unavailable, major license/boundary decision needed or user
data could be exposed. Continue another concrete safe part if a subtask blocks;
no filler hardening. Saved ink PARKED, timers PAUSED, no merge/PR finalization.

## Source checkpoint2026-10-14 (correction review pending)

Pinned hosted publisher provenance authenticated for Windows/ARM32/ARM64.
Actual Windows API7 tests/all4 renders PASS, exact original direct/named/null-XYZ
targets, crop/rotation/Unicode outlines and glyph hit. Original fixture unchanged.
Android native bothABIs compile warnings-as-errors, actual Android35 Java/DEX and
permission-free separate diagnostic package/signature PASS before corrections.
Package com.techrebbe.rtl.pdfiumprobe/code1/0.1.0-pdfium-exp1, **not** production
reader upgrade; local diagnostic certificate a5a855…807c67 pinned, no key upload.

Independent initial review: six P2, no P0/P1, all accepted as a batch. Correct
fresh archive-derived headers, complete package/source/executable receipt, shared
process FIFO across Activity open/close, final UP displacement, generated/missing
box text separators without cropped source text, and crop/bitmap hit bounds.
Focused5 tests/actualJava16 assertions PASS. Reviewer runtime/hardware NOTRUN.
Next correction confirmation then exact committed clean-archive build/rebuild
and local hashes. T018P-H is prepared NOT AUTHORIZED; no speculative emulator.
Original PDFs/marks/installedRTL/current production source unchanged, device free.
