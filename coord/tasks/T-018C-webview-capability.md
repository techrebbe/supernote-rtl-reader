# T018C — earliest read-only engine compatibility gate

Owner codex; agent/page-turner-bridge. Proposed only, NOTPERFORMED.
Production baseline code59 unchanged; desktop proof in probes/interactive-pdf.
User may disconnect during offline work. Ask explicitly for connection and
approval when this gate is ready; do not infer device availability from old
reservations or operate concurrently with DayWeave/another workflow.

Question: does unrooted Nomad firmware3.30.45 expose an enabled, valid system
WebView provider at or above PDF.js6.4.299's documented legacy Chrome125 floor?
This determines whether to prepare a bounded interactive WebView candidate,
not whether links/selection/zoom are already functional on the Nomad.

Prerequisites: explicit user approval for this READ-ONLY metadata task; new
exclusive issue23 reservation; known USB or user-supplied/current Wi-Fi endpoint;
exact serialSN078C10015092/firmware/API identity; adequate power and stable transport.
No address scanning, root, private data bypass, or consumed reservation reuse.

Observe only: ordinary shell identity/build/API, `dumpsys webviewupdate` provider
selection/validity/version, then public package metadata for that exact provider
if needed. Do not guess the package name. Record summarized provider/version and
PASS/FAIL/UNKNOWN, retain raw output locally. A disabled/missing/unparseable or
old provider is FAIL/UNKNOWN, not authorization to install/update a browser.
No PDF access, screenshots, document/page/rotation input, package installation,
settings changes, scripts in another app, pen, firmware or native ink operation.

Stop immediately on wrong device/firmware, ownership conflict, transport failure
or ambiguous provider identity. Verify no mutation was issued; report/release the
reservation. Do not upgrade or restore root as a rescue action.

PASS establishes only a version-level candidate prerequisite. Actual embedded
feature behavior, source READ transport and bounds, local-only loading, memory,
touch selection, crop/rotation/hit testing and lifecycle require source review,
an exact signed upgrade-compatible integrated package and a later disposable-
PDF Nomad gate. Preserve native Edit/Return and the existing reader-owned
Bluetooth transport; do not equate browser keyboard simulation with Bluetooth.

If provider is below the floor, report the concrete incompatibility and compare
maintained native interactive engines/licensing against an explicitly approved
browser update. Do not silently pin an unmaintained older PDF.js or start another
stock-writer/ink investigation. Keep the working portrait/RTL/Bluetooth reader
available, originals unchanged and timers paused. No merge/PR finalization.
