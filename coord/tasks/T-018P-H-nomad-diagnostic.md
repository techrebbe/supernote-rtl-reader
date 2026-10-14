# T018P-H — proposed embedded-fixture interactive engine gate

Status AUTHORIZED2026-10-14 / NOTPERFORMED (connection block). Timers PAUSED;
saved ink PARKED. User explicitly approved separate diagnostic install/test/remove
and publishing22 reviewed authored files/issue23 summary. Source-only prior
approval alone was insufficient; latest explicit approval is recorded below.
Fresh exclusive issue23 reservation is required before each resumed preflight.
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

## Approved attempt2026-10-14 — connection blocked

Reviewed sourcee87d1c4/reproducible APKc96222a7…da7742 unchanged. User explicitly
approved both pending scopes; verified source push34b1288 completed. Reservation
6172168409 posted after newest paginated issue23 read found prior release/no
active conflict. Host adb inventory restarted its local daemon, ZERO devices.
Reconnection/preflight command to saved10.0.40.9:5555 auto-review REJECTED before
execution as stale/unverified. Reviewer mentions10.0.40.1; current address of
neither endpoint verified by this session. Do not retry/contact another address
until current USB/user-provided authority, no scan or rejected-action workaround.

No target connection/shell or identity/power/window/package check; no install,
screen/input/page/rotation/root/original or .mark access. No device temp files;
no diagnostic cleanup needed. Hardware NOTPERFORMED, not engine FAIL. Reservation
6172168409 RELEASED6172235090; USB/debugging reconnect/current Wi-Fi question sent.
NEW reservation required for resume. No build/review/device observer left active;
ordinary host ADB daemon is not an observer. Software gates complete, no filler
rebuild/emulation. Exact candidate/evidence preserved; timers not resumed.

## USB resume2026-10-14 — bounded trial, FAIL/cleanup PASS

Fresh reservation6172548164 after user's USB-connected response. Exact serial/
fw3.30.45/API30/ARM64+32/ordinaryUID2000/77% charging/safe Inbox FileManager,
diagnostic absent PASS. Same candidatee87d1c4/exp1/code1/c96222a7…da7742 installed;
public installed APK byte-identical and exact signer verified before own launch.
Own PAGE1 render/English+Hebrew PASS; direct link->PAGE2/CropBox/intrinsic90deg
PASS, Link-back PAGE1 byte-identical59232480…e7385c. NamedXYZ1.25 FAIL: visible
render STOP with inert previous bitmap. Hardstop; no Fit retry or later phases.
Bookmark/same-page/selection/zoom/pan/rotation NOTPERFORMED, no general glyph/
hidden-link/physical flash/feel/Bluetooth claims. Cosmetic control mojibake noted.

Cleanup PASS: normal own Close -> prior Inbox, exact diagnostic path/hash checked,
own uninstall Success/absence verified, public PluginHostf60ce483…d2aad and
Documentdd77ff2c…6f986 hashes/serial/fw/UID/rotation1,2 unchanged. No original
PDF/.mark/privatepath/stock restart/root/firmware/pen or remote scratch files.
RELEASED6172821405. Raw shots/own APK/local outcomes preserved only in tmp.

Continue bounded offline correction: explicitUTF-8 compilation and finite6M
diagnostic ceiling plus half-max-heap/new+old bitmap accounting; preserve XYZ
meaning, fail on unsupported allocation, not silent downsampling. Observed
300dpi/612x792/XYZ1.25 arithmetic replay1913x2475=4734675 explains old4M stop;
no emitted exception trace, not a complete native-runtime/memory proof. New
exp2/code2 requires exact-source review/clean build/verification and separate
fresh package approval/reservation before device use. No retry on consumed trial.
