# T-001 Nomad test plan — NOT APPROVED, NOT RUN

Candidate: RTL Reader `0.4.24-edit-exp1` (code 43), marker `RTL_READER_OPEN v0.4.24-edit-exp1-native-reader-v2`, companion v0.0.140 unchanged. Exact commit and APK SHA-256 are filled in below only after the package is built from a clean checkout of that commit (this host cannot run gradle).
Commit: `______`  Package: `______`  SHA-256: `______`  bytes: `______`

## Preconditions (all required)
1. User approval of this plan; issue #23 reservation comment posted, released at the end.
2. Rollback: v0.4.23 package (code 42, 7,360,370 bytes, SHA-256 `ee2f0623c878ea830a6d7b8c693efd7d4144194779c41f01808bd468cfc5cc96`, REGRESSION.md) plus the current companion v0.0.140, both confirmed present on the host before touching the device. Rollback = copy the v0.4.23 `.snplg` back to `MyStyle` (the same path used to install; README) and restart PluginHost. No firmware, bootloader, system-partition, or companion changes.
3. Baseline capture (read-only): firmware fingerprint, installed plug-in version/code, companion version, `.mark`/PDF sha256 of the disposable files.
4. Disposable data only: 2 copies of a 12+ page PDF with large page numbers (`RTL_EDIT_A.pdf`, `RTL_EDIT_B.pdf`), pushed to a new path, no `.mark`; real documents never opened. Human does every pen/touch action; nothing injected.

## Order (stop at the first hard stop)
- **S0 install** candidate over v0.4.23; confirm marker in log and version code 43. Open RTL on A; observe read-only that no `.mark` appears.
- **E1 annotation visibility** (answers the open question; predicted NOT shown). Stock p5: 2 pen strokes, 1 highlight, partial erase; open RTL portrait single, landscape RTL spread (cover on/off); screenshot. PASS/NOT_RENDERED/PARTIAL per T-001.md. Neither result blocks E2.
- **E2a page identity** (finding 1): portrait and landscape, Edit left and right, 5 trials each; in 3 trials per orientation tap Edit immediately (<0.5 s) after a page turn and after rotation. PASS = button is inert until the render settles, and every accepted tap opens stock on exactly the labelled page (5/5, no exceptions). HARD STOP: stock opens on any page other than the button label.
- **E2b Edit/Return**: after Edit, page in stock (one trial back to the open-time page), relaunch RTL. PASS = RTL opens at the spread containing the stock page 5/5; RTL wrote no `.mark`. Also confirm the notice path: with Native Spread configured on B (read-only), Edit is refused with the message and nothing restarts.
- **E3 kill safety** (conservative first): per operation (pen stroke, eraser, lasso move, highlight) 3 trials at 10 s idle between last pen-up and Edit; only if 12/12 pass, repeat at 2 s (3 trials each), pen still touching the screen at kill time is deliberately NOT tested. PASS = the result is present in `.mark` (size/sha256 changed as expected) and on screen after restart. HARD STOP: any lost/corrupted stroke, any crash loop, PluginHost or Document failing to restart, or `.mark` size 0/shrinking unexpectedly -> roll back, no further trials, Edit stays blocked for real documents.
- **Rollback drill** at the end regardless of results: restore v0.4.23, confirm code 42 and that disposable docs still open. Delete disposable files only with user permission.

## Hard stops for the whole session
Device reboot loop, ADB loss mid-install, stock reader not restarting after Edit, any change to a non-disposable file, any unexplained `.mark` change while only RTL Reader is open.
