# T018P-H — proposed embedded-fixture interactive engine gate

Status PREPARED / NOT AUTHORIZED / NOT RUN. Timers stay PAUSED; saved ink PARKED.
No installation/device access under the source-only T018P approval. Obtain fresh
explicit user approval for separate diagnostic install/launch/UI/Close/uninstall
and an exclusive issue23 reservation before preflight; old reservation consumed.
Candidate must be exact reviewed commit, two reproducible clean-archive builds,
complete source/payload/signature receipt and focused tests. No current-reader
upgrade or downgrade, no SDK/native-reader navigation, root, firmware or pen.

## Defined question and sequence

Can the app-contained current PDFium engine on unrooted Nomad3.30.45 render its
embedded original PDF and align interactive text/links/outlines with its pixels?
One bounded session; record each phase before the next, no ad-hoc follow-ups.

1. Preflight exact serial SN078C10015092, approved device ownership, observed
   firmware/API/ABI, sufficient charged power, no competing task or system modal.
   Diagnostic package absent or a separately verified owned expected identity;
   unknown existing package/signature -> STOP. Verify current reader identity
   read-only; no personal document/file enumeration. Do not close an unknown
   active personal document. If a normal safe launcher state is unavailable,
   ask user, not force-stop stock reader or inject into it.
2. Install only `com.techrebbe.rtl.pdfiumprobe` exact approved SHA/certificate.
   Verify installed package/version/certificate. Launch own launcher activity.
   PASS1 = READY sourcePAGE1/four pages, known original heading/English phrase,
   no crash/STOP or mismatched source. UNKNOWN if screen evidence inconclusive.
3. FitPAGE1 direct internal link -> originalPAGE2; cropped/90-degree page pixels
   and link hit agree. Link back -> PAGE1 Fit. PASS2 = exact source targets and
   no invisible-margin link action. Wrong target/model -> FAIL and hard stop.
4. Named Chapter-three link and equivalent outline -> sourcePAGE3 /XYZ44,738,
   zoom1.25. Same-page/null zoom link after back retains effective zoom as
   specified. Preserve hierarchy/Unicode titles. Record rendered destination
   and zoom/target evidence, UNKNOWN rather than guessing from text alone.
5. Select known English phrase, copy via app UI; verify separators and no hidden
   crop text. Zoom+/Fit/pan and one authorized orientation round trip retain
   page identity/model alignment. Logical Hebrew copy fidelity remains UNKNOWN;
   this fixture cannot prove it. No real Bluetooth/pen gate in this diagnostic.
6. Close own probe normally; verify no probe activity/process retained beyond
   permitted Android process caching (no claim that caching is a leak). Uninstall
   only exact owned diagnostic after identity check; verify absence. Restore any
   test-owned orientation change; current reader identity unchanged. No original
   PDF/.mark was an input, so do not enumerate personal files for blanket hashes.
   Retain local raw evidence; summarized result only in REGRESSION/issue23.
   Release exclusive reservation even on FAIL/UNKNOWN.

Hard stops: collision, unknown task/window/document, package/source/signer drift,
crash/STOP, inconsistent model/page, unexpected storage/network request, unsafe
action dispatch, uncertain cleanup or power loss. No retry, rescue uninstall,
system setting change or another package without separate scope/decision.
If interrupted, report exact stage/evidence and only perform already-approved
owned cleanup after package identity remains verifiable. Never stop/restart the
stock Document task, touch native marks or substitute a personal document.

Success authorizes an integration proposal, not production release. Reuse
portrait/RTL layouts/Bluetooth/Edit-Return; do not duplicate those systems here.
