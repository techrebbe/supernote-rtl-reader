# T018C — earliest read-only engine compatibility gate

Owner codex; agent/page-turner-bridge. COMPLETE2026-10-14: provider valid,
PDF.js6.4.299 documented browser-version prerequisite FAIL (109<125).
Production baseline code59 unchanged; desktop proof in probes/interactive-pdf.
User may disconnect during offline work. Ask explicitly for connection and
approval when this gate is ready; do not infer device availability from old
reservations or operate concurrently with DayWeave/another workflow.

## Completed bounded result

User confirmed USB/free and explicitly approved Wi-Fi setup + read-only check.
Fresh reservation6161740390; source6ca9a185055ab63801ecd09a65c2178b3b24a8a0.
Exact SN078C10015092/Chauvet.E103.2610091001.2545_release/API30/UID2000,
93% USB-charging. Observed wlan0 address10.0.40.9/24, not assumed from history.
Standard tcpip5555 only, connect that address and independently reverify the
same serial/firmware/API/ordinary shell. Wi-Fi ADB PASS; may disconnect USB.

Read-only service: current/preferred com.google.android.webview109.0.5414.117,
versionCode541411703, target33, valid/enabled all users, relro2/2, dirty=false.
No additional package query needed. Official PDF.js FAQ reconfirmed Chrome125+
legacy floor. Mark only proposed engine's version prerequisite FAIL; do not claim
the project/installed reader fails or that a functional PDF trial was performed.

Exact postflight serial/firmware/UID/provider unchanged. No document/PDF/.mark
access, screenshot/input/page/rotation, install, private path, root, firmware or
browser update. No remote temporary file, no deletion/cleanup needed. Wi-Fi
enabled as requested is the sole setup change; no compatibility-test mutation.
Local metadata: root tmp/t018c-nomad-20261014-metadata.json, not uploaded.
RELEASED6161799646 from6161740390. Next source-only decision: maintained native
interactive engine versus separately authorized compatible browser update;
preserve desktop proof, current reader/navigation/Edit/Return and parked ink.
Do not ship old unmaintained PDF.js or silently change firmware/WebView.
Source-only comparison/recommendation: T-018D-engine-decision.md; user decision
before native-engine implementation or any system browser update.

## Original gate / safety contract

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
