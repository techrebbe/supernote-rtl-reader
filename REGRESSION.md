# RTL Reader hardware regression

Device baseline: Supernote Nomad running firmware fingerprint
`Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys`
with SupernoteDocument `1.02.446`.

## Native Reader v2 v0.4.21 hardware checkpoint — FAIL CLOSED

- [x] The v0.4.21 recovery-retirement change restored an originally absent
  calibration `.mark`, retired its first durable recovery fence, removed the
  verified backup, and reopened the native reader without data loss.
- [x] A subsequent fresh activation exposed a separate shared-storage
  publication failure. PluginHost and `/data/media` observed the committed
  marker SHA-256
  `6d4b9f911efa7f704b5d6f3c39953055e764008e7826d8174e862cf2caac6333`,
  while DocumentActivity and the shell `/storage/emulated` view retained the
  prior pending marker SHA-256
  `ded1599dc88a39443b09b4a6420117454d379ad3fd42c3a89f4c868d6dd832e7`.
  The injected module rejected that stale pending schema and did not admit the
  document.
- [x] The cleanup retry also failed closed. Reusing the legacy marker pathname
  with `O_EXCL` but without `O_TRUNC` produced a recovery-journal prefix plus a
  retained pending-marker tail (SHA-256
  `e368fff7cd12c910683ae5f774b6184be4bfe636f1f4b081a34982545778d220`).
  Strict duplicate-key parsing rejected the mixed file; the verified backup
  remained, the live `.mark` remained absent, and the reader was not reopened
  by the recovery worker.
- [x] A disposable Nomad mount-namespace probe used never-before-seen paths and
  found identical 8,192-byte hashes through PluginHost, DocumentActivity,
  shell `/storage/emulated`, and root `/data/media` after both initial
  publication and a fixed-offset, same-inode update. The stable file retained
  inode `179295`; its hash changed coherently from
  `170dfe93c5a733e1d711c57bcfff7ca2c09ca541bad265985514fde5c73e3081`
  to `aaf78b2e2c8f3e8e89609a6f022ee60035a96bf0f2663f1755b9509d14bdadca`.
- [ ] v0.4.21 is not releasable. v0.4.22 must replace rename-over-existing
  authorization with a new-path, fixed-size journal, a durable OFF state, and
  exact Document-process acknowledgement for activation and revocation.

## Native Reader v2 v0.4.22 fixed-journal pre-hardware gate — LOCAL PASS

- [x] RTL Reader v0.4.22 (`versionCode=41`) and companion v0.0.140
  (`versionCode=140`) use handshake protocol 4 and protected-editable marker
  protocol 3. The companion is 274,971 bytes with SHA-256
  `dd40b89f4bbc6d161b90ea631efccac8c185e3ae8b2cc0cb13d5791f35464c48`
  and the upgrade-compatible signer certificate SHA-256 remains
  `a5a8551131de84d41660a3cf22d224f320f7a2f05a380282f76f6fe731807c67`.
- [x] Authority moved to a never-reused `.snspread-v3` path containing one
  fixed 32 KiB, two-slot journal. Initialization exclusively creates and sizes
  the inode once; later PENDING, COMMITTED, RECOVERY, and OFF transitions use
  fixed-offset writes and three fsync stages without rename, delete, truncate,
  resize, or recreation.
- [x] A nonzero malformed/torn slot rejects the complete journal. Header state
  is required to equal the exact payload activation state, and a valid OFF
  record is the only v3 authority that supersedes retained legacy `.snspread`
  evidence.
- [x] A torn inactive-slot publication is repairable only during explicit
  verified annotation restore, after DocumentActivity is stopped, and only
  when the same exact inode contains one valid generation plus one malformed
  slot. The malformed slot is replaced by a newer authenticated RECOVERY
  record using the same three-fsync sequence. Empty/valid journals, zero valid
  slots, two malformed slots, replacement/version drift, and every ordinary
  open remain fail closed.
- [x] Every reported transition requires the live Document process to
  acknowledge the exact journal path, generation, authenticated record digest,
  state, and activation token. Handshakes are generation-owned, single-flight,
  raw-path bound, main-thread registered, and expire on one absolute deadline.
  PluginHost re-reads the live journal after receiving the ACK and rejects a
  disappearance or generation/digest/state change during the observation-to-
  response interval.
- [x] Restore publishes RECOVERY before touching `.mark`, keeps the document
  process stopped during replacement, starts a fresh authority provider while
  RECOVERY remains fenced, and opens the fence only through an exact-ACKed OFF
  transition. Post-commit cleanup cannot roll restored bytes backward.
- [x] Valid protected legacy sessions migrate only after two exact authority
  checks, including immediately at v3 publication. Malformed legacy evidence
  stays fail closed, while reconciliation publishes durable v3 OFF authority
  before reassessment so legacy path evidence cannot silently regain control.
- [x] The Java/Kotlin journal golden vectors agree. The core suite passes
  85,407 assertions, including mutations at both ends of every wire field and
  authenticated region. All 231 executable/static authority mutations are
  rejected, and native/plugin invariants, provenance, and fail-closed package
  tests pass.
- [x] The full RTL Reader package compiles through the authenticated Supernote
  template and verifies at 7,360,211 bytes with SHA-256
  `2065a4935b9bb17c02157b1ce7d69c2e148e7848cebf75947619570ac6782bab`.
- [ ] Exact-head PR CI and Codex review are clean.
- [ ] The Nomad proves same-inode visibility and exact ACKs for enable,
  disable, restore, interrupted recovery, cold process reopen, and ordinary-PDF
  isolation. No hardware result is claimed by this local section.

## Native Reader v2 pre-hardware adversarial gate — PASS

- [x] 85,071 deterministic controller/geometry/transaction assertions pass.
- [x] 213 authority mutations are rejected, including exact firmware-declaration
  and native pen-callback ownership drift, stale admission evidence,
  contained-runtime publication, contact-safe containment, three-layer stock
  restoration, projection drain ordering, and descriptor-backed marker
  recovery.
- [x] Ordinary native/plugin invariants, packaging fail-closed tests, and trace
  helper fail-closed tests pass.
- [x] Companion v0.0.138 compiles and verifies with the upgrade-compatible
  signer; RTL Reader v0.4.19 compiles and packages with the hardened native
  module.
- [x] The current stable `origin/main` baseline at
  `81942105e60e1b5498a7fb790762a3b750371a2d` is integrated; all 189 Virtual
  Spread generator tests, contract fixtures, and native viewport tests pass.
- [x] Two clean v0.0.138 companion builds are byte-for-byte identical at
  258,587 bytes and SHA-256
  `aeaddb2e682e3b2a2eaf4c9abe531ea40fa7ead25dab1871c637892d048fce5f`.
  The exact locally generated v0.4.19 RTL Reader hardware-candidate package
  for this gate is 7,332,079 bytes and has SHA-256
  `4be70036a51ee91207933183a9130ebfb117b8e57221f27f4953cbb566dcd993`.
- [x] The final adversarial review findings are covered by deterministic gates:
  epoch-owned input/lifecycle authority, exact stock-reload receipts, no-clobber
  `.mark` publication/rollback interleavings, post-commit relaunch, exact
  installed-companion identity, protected two-stage release signing, bounded
  filesystem-free exact raw-path binding across the plug-in and native provider,
  generation-owned provider admission with absolute-deadline publication,
  plus
  generation-linearized terminal plug-in callbacks.
- [x] Delayed runtime retirement cannot remove component IDs leased by a new
  same-Activity session, and every unproven post-rename `.mark` failure blocks
  all native-reader relaunch paths while retaining displaced recovery evidence.
- [x] The protected no-checkout signer verifies the final signed APK's fixed
  258,587-byte length and SHA-256 before publishing it.
- [x] The first v0.0.137 Nomad admission attempt failed closed before any hook
  installation. An exact offline DEX audit of all 124 pinned symbols identified
  and corrected all three declaration mismatches together: the annotation map
  interface type, the link hit-test point type, and the native-event pressure
  owner. The v6 symbol contract now matches the captured firmware APK with zero
  mismatches, and future runtime admission reports every mismatch in one pass.
- [x] Companion v0.0.138 admitted the exact Nomad firmware, installed all 24 v2
  hooks, and left an ordinary PDF explicitly unadmitted. The first v0.4.17
  editable attempt verified the live annotation backup and then failed closed
  before marker publication because Android's emulated-storage FUSE mount
  rejects `O_DIRECTORY` with `EINVAL`. A device probe proved that the same mount
  accepts `O_NOFOLLOW` without `O_DIRECTORY`, preserves exact descriptor/path
  identity, and supports directory `fsync`; v0.4.18 uses only that narrowly
  validated fallback and retains the before/open/after inode checks.
- [x] The first v0.4.18 retry admitted the companion and verified the live
  annotation backup, then rejected pending-marker publication because Android
  emulated storage legitimately advanced the staged inode's `ctime` during
  atomic rename. Fail-closed rollback restored the original ABSENT `.mark`,
  removed the unpublished marker, and retained exact recovery evidence under
  token `6097c662-1947-4585-91e0-f6106560bceb`. A scoped Nomad probe proved the
  rename preserved device/inode/mode/links/size/mtime while advancing only
  `ctime`. v0.4.19 therefore anchors the post-publication check to the still-open
  staged descriptor's post-rename identity, then rechecks the descriptor-backed
  destination and final path exactly; four new mutation cases protect identity
  capture ordering and all three authority fences. An executable injected
  post-rename `fstat` failure additionally proves that the irreversible
  publication callback runs exactly once before the failure propagates.
- [x] The final exact-head review's two concurrency findings are reproduced and
  guarded. Mode loading now derives settings, configuration state, and recovery
  assessment from one descriptor-backed marker snapshot and revalidates that
  exact authority after the asynchronous companion handshake before resolving.
  Committed-marker publication is tracked separately from verified activation:
  a post-rename verification failure suppresses unsafe rollback but still
  rejects activation instead of being converted into success. Executable race
  models and two new static mutations cover both boundaries.
- [x] The subsequent exact-head review's two additional concurrency findings
  are also reproduced and guarded. Prepared background composition now acquires
  the hook's physical-stylus publication lock before disabling or reprogramming
  DrawPath; a DOWN that wins that lock defers composition until both stylus
  streams reach terminal release. Mode-load publication now rereads and exactly
  compares the document-bound recovery result, including no-follow descriptor
  identities for both manifest and snapshot, then rederives and compares the
  full recovery authority before resolving. Large `.mark` snapshots are hashed
  through pinned descriptors without retaining their payloads in the plug-in
  heap. Both physical DOWN streams and the final worker-to-main publication
  retain their shared generation/lock authority. Two executable interleaving
  models and seventeen new static mutations cover these boundaries.
- [x] Recovery restore and reconciliation now enter through the same
  process-shared configuration-generation authority as ordinary mode changes.
  They exclude overlapping loads/configuration while mutation is active and
  advance the generation again on exact completion, so a load checked before
  or during recovery cannot publish stale marker, settings, or backup authority
  afterward. Recovery carries an exact owner-generation token, so a stale retry
  cannot release a replacement owner, and annotation restore retains generation
  authority across `.mark` publication and recovery-evidence retirement. The
  executable interleaving model and twelve independent static mutations cover
  recovery admission, owner retry, irreversible publication, both terminal
  fences, and Promise-safe configuration rejection.
- [x] Pending-marker reconciliation now holds the cross-process publication
  lock before configuration-generation authority and parses one exact
  descriptor-backed marker snapshot. All restore/delete branches compare that
  same identity at their pathname mutation, so a stale PluginHost cannot
  overwrite or clear a newer process's marker. A two-process executable race
  model covers both precheck and compare-and-swap replacements; five additional
  static mutations guard the lock, descriptor snapshot, exact comparison,
  compare-and-delete, and compare-and-swap boundaries.
- [ ] Exact-head independent review is clean.
- [ ] Nomad hardware gate passes. No hardware result is claimed by this
  automated section.

v0.0.9 established the hardware-validated reading-engine baseline. v0.1.1 subsequently validated the polished UI and direction-aware footer. v0.4.2 is the current merged hardware-validated direct-render and direction-aware native bitmap-prefetch baseline.

## v0.0.9 full regression — PASS

### 1. Portrait single-page RTL — PASS

- [x] Open a PDF natively on a known page and launch RTL Reader.
- [x] Portrait / Auto shows one page.
- [x] Right swipe advances one PDF page.
- [x] Left swipe goes back one PDF page.
- [x] Right-edge tap advances one PDF page.
- [x] Left-edge tap goes back one PDF page.
- [x] Center tap hides/shows chrome.
- [x] Page counter jump opens the requested physical PDF page.
- [x] Close reopens native reader on the RTL Reader page.

### 2. Landscape Auto spread, RTL — PASS

- [x] Rotate to landscape while View = Auto; display changes to a two-page spread.
- [x] Earlier/lower page is on the RIGHT; later/higher page is on the LEFT.
- [x] Right swipe / right-edge tap advances exactly one spread.
- [x] Left swipe / left-edge tap goes back exactly one spread.
- [x] Footer labels match the two visible physical PDF pages.
- [x] Rotate back to portrait; the focused PDF page is retained.
- [x] Close from landscape/spread mode reopens native reader at the focused RTL Reader page.

### 3. Treat Cover Page Separately — PASS

With RTL + Spread + `Cover: On`:

- [x] First spread is `Blank | Cover 1`.
- [x] Next spread is `Page 3 | Page 2`.
- [x] Next spread is `Page 5 | Page 4`.
- [x] Turning `Cover: Off` returns to ordinary pairing (`Page 2 | Page 1`, then `Page 4 | Page 3`, etc.).
- [x] The setting persists after Close/reopen for this PDF.

### 4. LTR sanity check — PASS

- [x] Switch direction to LTR.
- [x] Single-page swipe/tap directions reverse correctly.
- [x] Spread order becomes earlier page LEFT, later page RIGHT.
- [x] With `Cover: On`, first spread is `Cover | Blank`.
- [x] Direction persists after Close/reopen for this PDF.

### 5. Native/RTL position and per-document persistence — PASS

- [x] Leave PDF A at a distinctive RTL Reader page and Close; native reader reopens at that page.
- [x] Launch RTL Reader again; it opens at the synchronized position.
- [x] Open PDF B natively and launch RTL Reader; PDF B does not inherit PDF A's saved page/settings unexpectedly.
- [x] Change PDF B settings, Close, then reopen PDF A; PDF A's own settings are restored.
- [x] Move the native reader manually to a different page, then launch RTL Reader; the externally changed native position wins rather than stale saved RTL position.

### 6. Beginning/end boundary cases — PASS

- [x] At the first spread, Previous does nothing and does not alter the footer/focused page.
- [x] At the final spread with `Cover: Off`, Next does nothing immediately; there is no extra invisible page-step where the spread stays visually unchanged.
- [x] At the final spread with `Cover: On`, Next does nothing after the true last spread/page.
- [x] Closing from the final spread hands off the page that RTL Reader actually considers focused.
- [x] Jump to PDF page 1 and to the final PDF page works without crash or blank unintended pages.

## v0.1.1 UI validation — PASS

- [x] Settings panel fits and works in portrait and landscape.
- [x] RTL/LTR, Auto/Single/Spread, and Cover On/Off selected states are clear.
- [x] Auto still switches between portrait Single and landscape Spread.
- [x] Center tap still hides/shows chrome.
- [x] RTL footer is physically `Next | page | Prev` left-to-right.
- [x] LTR footer is physically `Prev | page | Next` left-to-right.
- [x] Close/native page handoff remains working.

## v0.2.0 renderer-reuse validation — PASS

- [x] Ordinary navigation remains working.
- [x] Portrait and landscape reading remain working.
- [x] Rapid page turns do not expose an obvious regression.
- [x] Existing UI remains correct.
- [x] Close/native-reader handoff remains working.
- [x] Native logs confirm renderer reuse: after the initial open, `reused=true` and `openMs` is normally 0–1 ms.

## v0.2.1 recent-render-cache spot check — PASS

- [x] Normal portrait and landscape reading still looks identical to v0.1.1/v0.2.0.
- [x] Rapid sequential turns do not crash, blank, show stale pages, or show pages out of order.
- [x] Close/native-reader handoff lands on the focused page.
- [x] Native logs continue to show renderer reuse (`reused=true`) after the initial open.
- [x] Repeated requests show `cacheHit=true` with `renderMs=0` and `pngMs=0`; captured cache-hit median total was about 16 ms versus about 419 ms for cache misses.

Hardware timing capture for v0.2.1 contained 107 native render requests: 14 cache hits (about 13.1%). Cache-hit median total time was 16 ms; cache-miss median was 419 ms. Cache hits therefore avoided roughly 403 ms of native work per hit in this test while preserving the same PNG output path.

## v0.3.0 direct-native-render validation — PASS

- [x] Native direct-render path launches and produces completed page renders.
- [x] `PdfRenderer` reuse remains active after the initial open (`reused=true`, normally `openMs=0–1`).
- [x] Foreground direct renders report `pngMs=0` and `base64Ms=0` throughout the capture.
- [x] Steady-state completed renders are typically about 140–145 ms total, versus the v0.2.1 uncached median of about 419 ms (roughly 3× faster native foreground rendering).
- [x] Normal portrait and landscape pages display correctly with no stale/blank/out-of-order completed pages.
- [x] Landscape Auto/Spread preserves RTL/LTR visual page order.
- [x] Treat Cover Page Separately still produces the correct virtual-blank parity.
- [x] Jump still lands on the requested PDF page.
- [x] Close/native-reader handoff still lands on the focused page.

The v0.3.0 hardware run confirms that the intended architectural bottleneck has been removed: foreground renders no longer perform PNG compression or Base64 transport, steady-state direct renders cluster around 140–145 ms, and the existing visual, navigation, parity, jump, and native-reader handoff behavior remains correct on the test Nomad.

## v0.4.2 direction-aware native bitmap prefetch — PASS

- [x] Native bitmap prefetch produces cache hits for normal Single-mode forward turns.
- [x] The visible page bitmap is returned to the four-entry native LRU when it leaves the screen.
- [x] One-step Single-mode reversals reuse the page just returned from the visible view.
- [x] Normal and one-step-reversal spreads reuse both pages from cache.
- [x] Foreground-priority and stale-request guards remain active during bursts.
- [x] No stale, blank, or out-of-order pages were observed.
- [x] Close/native-reader handoff still lands on the focused page.
- [x] Existing navigation, spread order, Cover parity, and page-jump behavior remain correct.

Final v0.4.2 timing capture:

- 43 completed Single-mode interactions had a median of about 50 ms;
- the captured Single-mode range was 43–51 ms;
- normal and one-step-reversal spreads generally completed in about 47–67 ms;
- cache-hit native work was normally about 0–4 ms;
- `RTL_READER_NATIVE_VIEW_VISIBLE_CACHED` appeared consistently as pages/spreads left the screen.

Very rapid spread bursts can still take roughly 200–350 ms when navigation outruns the time required to rasterize two new pages. The final completed pages remain ordered and correct, and speculative background work no longer creates a long queue ahead of the latest foreground request. This is accepted as the current Android `PdfRenderer` two-page throughput limit.

## v0.4.3 source consolidation and landscape cold start — IN PROGRESS

- [x] Canonical native renderer source replaces the layered v0.4.2 Kotlin patch pipeline.
- [x] Build-time invariants protect exact render-key reuse, file replacement, foreground priority, stale cancellation, and generated-source equality.
- [x] Initial native request waits for measured page-area dimensions.
- [ ] Launch while already in landscape displays the initial spread without navigation.
- [ ] Launch while already in portrait displays the initial page normally.
- [ ] Rotation after launch remains correct.
- [ ] Page jump, Cover parity, RTL/LTR ordering, and Close handoff remain correct.

The measured-layout candidate still reproduced a blank initial landscape spread. The r2 candidate adds native `onSizeChanged()` and `onAttachedToWindow()` redraw hooks so a bitmap completed before final native view sizing is drawn when the view receives a valid frame. Diagnostic marker: `RTL_READER_NATIVE_VIEW_SIZE_REDRAW`.

## v0.4.5 native-reader pilot control - PASS

- [x] Compatible Native Spread v0.0.60 is detected on the Nomad.
- [x] `RTL read-only` can be enabled for an ordinary PDF from Settings.
- [x] Close returns to the same native page and opens the correct RTL spread.
- [x] Portrait swipes and edge taps follow RTL direction.
- [x] Landscape cover parity and spread navigation match plug-in settings.
- [x] Native writing is blocked visibly and no `.mark` file is created.
- [x] Returning to Settings and choosing `Off` restores the unmodified native reader, including writing.
- [x] An unmarked PDF remains completely unaffected.

The first v0.4.4 pilot exposed a safety gap in Native Spread v0.0.59: the
activity-level stylus guard did not see Supernote's low-latency pen path, so a
stroke could still be committed. Native Spread v0.0.60 fixes this below the
activity layer by forcing every `HandWriteClient.sendDisableAreaInfo` request
to a full-page disabled rectangle and blocking `HandWritePresenter.receiveTrials`
as a persistence fail-safe. The disposable failure `.mark` was preserved for
analysis and removed from the device before the successful v0.0.60 retest.

## v0.4.6 protected real-document pilot - PASS

- [x] Native Spread v0.0.61 is detected as the minimum compatible module.
- [x] A protected copy of an existing 738-page Hebrew PDF opens with its copied
  `.mark` file intact.
- [x] Saved ink on pages 141 and 143 remains visible when the opposite page is
  active.
- [x] Center taps activate a spread page without turning the spread.
- [x] Outer-left and outer-right edge taps turn exactly one RTL spread.
- [x] Swipes continue to turn one RTL spread without requiring page activation.
- [x] The active left/right side is preserved across forward and backward turns.
- [x] No stale, blank, misplaced, or out-of-order annotation overlay was seen.
- [x] The protected `.mark` SHA-256 remained
  `c2155e51a686a3ba7066c8ef7d859c19053019e85d23d1414fa1a69dc9de2c21`.

v0.0.61 removes read-only mode's former editable-only committed-ink gate,
renders canonical saved ink for both visible pages, suppresses non-edge native
tap turns, and preserves the active spread side. The v0.0.60 hardware writer
and annotation-commit blocks remain unchanged.

## v0.4.7 / Native Spread v0.0.62 review hardening - PASS

- [x] Package compatibility floor is raised to Native Spread v0.0.62.
- [x] Marker creation requires a nonce-based response from the actively hooked
  `DocumentActivity` for the exact currently open PDF.
- [x] The response verifies protocol, module version, document APK length, and
  live document-process PID.
- [x] An installed module without an active handshake is reported as inactive.
- [x] `DocumentActivity.onDestroy()` clears `activeActivity`, all per-activity
  geometry/touch/config maps, and recycles page, committed-ink, full-ink, and
  digest bitmap caches.
- [x] Native Spread safety invariants pass.
- [x] Native PDF renderer invariants pass.
- [x] Native Spread v0.0.62 compiles, signs, and verifies successfully.
- [x] RTL Reader v0.4.7 compiles and packages successfully.
- [x] On-device live handshake succeeds for the protected pilot copy.
- [x] Disabling the LSPosed module and restarting the document process makes the
  RTL read-only control unavailable; the handshake times out with no response.
- [x] Re-enabling the module and restarting the document process restores the
  live handshake and RTL read-only spread without reinstalling either package.
- [x] Repeated native-reader close/reopen logs complete resource release without
  stale document state or regressions.
- [x] Existing read-only navigation, annotation display, and unchanged `.mark`
  checksum smoke tests still pass.

The protected-pilot hardware run exercised the complete safety sequence. With
Native Spread v0.0.62 enabled, RTL Reader received a protocol-1 response from
the live `com.supernote.document` process for the exact protected PDF. After
the LSPosed module was disabled and the process restarted, the response timed
out and **RTL read-only** was grayed out. Re-enabling the module and restarting
restored the handshake and spread. Removing the paused document task invoked
`DocumentActivity.onDestroy()` and logged
`activity_resources_released active_cleared=true`. The protected `.mark`
SHA-256 remained
`c2155e51a686a3ba7066c8ef7d859c19053019e85d23d1414fa1a69dc9de2c21`
throughout.

### Codex P1 configured-state follow-up - PASS

- [x] Marker configuration is tracked separately from live hook availability.
- [x] Read-only and externally configured editable markers remain distinct while
  the live handshake is unavailable.
- [x] The settings UI shows a configured read-only marker instead of falsely
  showing **Off** while the hooks are unavailable.
- [x] Switching to LTR removes a configured read-only marker even when the live
  handshake is unavailable.
- [x] Build invariants cover configured/runtime state separation.
- [x] With the module disabled, the configured read-only choice remains visible
  and **Off** removes its marker.
- [x] With the module disabled, switching to LTR removes its marker; re-enabling
  the module does not silently restore read-only mode.

The v0.4.7-r1 hardware run first confirmed that a configured read-only marker
remains visibly selected while the LSPosed hooks are unavailable. Selecting
**Off** deleted the marker without a live handshake. The marker was then
recreated through a valid handshake, the module was disabled again, and
switching the plug-in to LTR deleted it automatically. After the module was
re-enabled and the document process restarted, the protected PDF remained in
ordinary native landscape view rather than silently restoring RTL spread mode.
The protected `.mark` SHA-256 remained unchanged throughout.

## v0.4.11 settled native ink composition

- [x] Native Spread v0.0.81 compiles and the packaged, handshake, and plug-in
  compatibility versions all report 81.
- [x] Automated invariants require additive composition for ordinary pen
  commits and keep active-slot clearing behind the replacement-operation guard.
- [x] Pen selection enters additive mode; eraser and lasso selection enter
  replacement mode; undo and redo use the updated canonical `.mark` page rather
  than Supernote's sometimes incomplete transient replacement bitmap.
- [x] Draw multiple separate strokes on one active page. Each earlier stroke
  remains visible after the next stroke settles. Confirmed on the Nomad with
  Native Spread v0.0.116: two new strokes extended the canonical page from four
  to five to six trails without hiding any earlier trail.
- [x] Turn away and back. All added strokes remain present in the same positions.
  Confirmed by loading page 1 and page 2 in portrait and then restoring the
  landscape spread; the active page retained all six trails throughout.
- [ ] Erase part of one stroke. The erased pixels remain absent while the other
  strokes remain visible, including after a page turn.
- [ ] Lasso-move one stroke and confirm no old pixels remain at its source.

## v0.4.12 native spread appearance and inactive-page editing

- [x] Native Spread v0.0.116 compiles and the packaged, handshake, and plug-in
  compatibility versions all report 116.
- [x] Native Spread v0.0.84: rotate an open spread to portrait and confirm the
  current page immediately uses the normal native-reader portrait size without
  turning away and back.
- [x] Appearance choices are stored per PDF and marker updates retain the
  existing transactional backup protections.
- [ ] Set **Active-page header: Off** and confirm the persistent red ACTIVE or
  READ ONLY banner disappears, remains hidden after reopening the document,
  and returns when the setting is switched On. Safety/error overlays remain
  available in either state.
- [x] Start an annotation trace while an editable document is open. Confirm
  `events.jsonl`, `session.properties`, and the initial `.mark` snapshot appear
  under `Download/SupernoteNativeSpreadTrace` without changing visible ink.
  Confirmed in session
  `20260809-223717-633-p17868-SupernoteNativeSpreadCalibration.pdf`.
- [ ] Record one portrait control stroke and the equivalent landscape-spread
  stroke. Each trace correlates pen contact, reader page, mark page,
  `receiveTrials`, `saveTrails`, trail fingerprints, and the resulting `.mark`
  SHA-256 under one transaction/session timeline.
- [x] Record checkpoints after settling and after returning to the page. The
  collected ZIP contains both screenshots, only content-changed `.mark`
  snapshots, and `module-logcat.txt`. The completed bundle contained 433 events,
  three pen transactions, 48 annotation boundaries, six changed `.mark`
  snapshots, no parse errors, and no potential failures. Its ZIP SHA-256 is
  `DFC30AE0033B907ABD25612EBFEB1B5798552BEC585FDC1A3A244B17305D4306`.
- [ ] Stop tracing and repeat ordinary writing with no active session. No trace
  files grow and annotation behavior remains unchanged.
- [x] On the active spread page, stroke-erase one saved line. The line disappears
  as soon as the eraser settles, without changing page focus; the trace records
  the canonical save before `active_eraser_canonical_reload`.
- [x] Activate the other page and return. The erased line remains absent and all
  unrelated trails on both pages remain visible.
- [x] Automated invariants cover the divider and sizing controls, visible-page
  clipping, and the full-page annotation transform.
- [ ] **Fit page + Divider On** matches the v0.0.81 layout and annotation
  behavior.
- [ ] **Fit page + Divider Off** removes the dark line and uses the full two
  halves without moving or resizing existing ink incorrectly.
- [x] **Native fill + Divider Off** uses Supernote's automatic non-white page
  trim independently for both pages, fills the full landscape height without
  stretching, and extends behind the native toolbar and page-number bar.
- [x] A pen stroke drawn directly on the inactive right page is appended only
  after its page-local write succeeds; all earlier ink remains visible and the
  new stroke survives a spread turn away and back.
- [x] The symmetric inactive-left-page stroke follows the same sequence,
  preserves all prior trails, and survives a spread turn away and back.
- [x] Erasing a saved line on the inactive page removes the intersecting line,
  preserves the other page-local trails, and remains correct after turning
  away and back. On the Nomad, the far-left wavy line was removed while the
  other three visible trails remained. The page-local transaction reported
  `erased=1`, the one stale native save logged
  `pen_activation_stale_save_bypassed`, and the same result reloaded
  after leaving and returning to the spread.
- [x] Immediately after an inactive-page write, Undo removes the new stroke and
  Redo restores it without changing unrelated trails. Confirmed on the Nomad
  with Native Spread v0.0.90 using the native top-toolbar controls.
- [ ] Immediately after an inactive-page erase, Undo restores the erased trail
  and Redo removes it again without changing unrelated trails.
- [x] Immediately after an active-page erase, native top-toolbar Undo restores
  exactly the erased section and Redo removes it again without changing any
  unrelated trail. Confirmed on the Nomad with Native Spread v0.0.95; the
  redone erasure remained correct after leaving and returning to the spread.
- [x] The stale inactive-eraser save guard exists only while the deferred target
  `loadPage()` call is on the stack. Source invariants reject the former timed
  window, so later active pen and page-switch saves cannot consume the guard.
- [ ] On hardware, immediately write or erase on the newly active page after an
  inactive-page erase, then switch halves. Confirm those ordinary saves persist
  while the one stale activation save is still suppressed.
- [x] Trace `.mark` snapshots are debounced and serialized off the UI thread;
  annotation boundaries do not hash the file synchronously.
- [x] Trail details and all-trail fingerprints are computed from immutable
  captures on the trace worker rather than on annotation hook threads.
- [x] Annotation boundaries report a `.mark` hash only when the live file
  identity matches the completed snapshot; changed files report `pending`.
- [x] Ordered trail fingerprints include rotation, redraw dimensions, and
  coordinate extents in addition to points and pen metadata.
- [x] Trace captures and fingerprints include every integer/value identity
  attribute used by the production inactive-page trail matcher.
- [x] Trace captures and fingerprints include recognition, refresh,
  before/after-shift rectangles, and contour point geometry.
- [x] Native Fill active settled ink is clipped to the active page's visible
  half-screen slot before composition.
- [x] Static invariant: plug-in Native Fill mirrors native content trimming and
  asymmetric margin anchoring; trim metadata survives native bitmap caching
  and prefetch.
- [x] Static invariant: non-white content detection runs only for Native Fill;
  Fit foreground and prefetch renders skip it.
- [x] Static invariant: a configured marker is authoritative for cover parity
  as well as divider, header, and page-sizing state during initialization.
- [x] Static invariant: failed trace startup stops observers and cancels pending
  work. A pre-publication attempt is cleaned up; after `active.txt` is durable,
  that exact pointer remains guarded by `incomplete.txt` and
  `publication-failed.txt`.
- [x] Static invariant: `last.txt` is published only during successful trace
  finalization by atomically renaming `active.txt`; failed startup preserves the
  previous completed-session pointer and no separate success event can disagree
  with that single commit.
- [x] Static invariant: every desktop trace-helper action recognizes an
  `active.txt` whose recorded PID is no longer the live document process.
  `Status` retains that pointer across invocations; `Stop` removes it only after
  retaining its identity and partial directory without promoting it.
- [x] Nomad helper simulation: after recovering an `active.txt` tied to dead PID
  `999999`, `Stop` must report that exact incomplete session and refuse to pull
  the preceding completed session. `last.txt` remained unchanged, the partial
  directory was retained for diagnosis, and the disposable test was removed.
- [x] Static invariant: final `.mark` capture is retried after unstable hashes
  or copies; only a stable result can publish `last.txt`. Exhausted retries
  publish `incomplete.txt`, and the helper checks it before accepting or pulling
  a completed session.
- [x] Static invariant: snapshot publication captures the live source identity
  again after hashing the copied snapshot and rejects a concurrent rewrite.
- [x] Static invariant: missing-file and unchanged-hash final snapshot paths
  recheck the live source identity before reporting success.
- [x] Static invariant: successful final-snapshot events are emitted only after
  final source verification and in-memory acceptance; rejected candidates can
  publish only instability events.
- [x] Static invariant: hook-thread event capture queues immutable records to a
  per-session serialized writer; only that writer opens `events.jsonl`, and
  finalization drains it before publishing a session pointer.
- [x] Static invariant: completion removes `active.txt` only through the atomic
  rename to `last.txt`; incomplete/publication failure retains exact active,
  incomplete, and publication-failed guards, all checked before `last.txt`.
- [x] Static invariant: completed publication rejects an undeletable stale
  `incomplete.txt` and preserves an explicit publication-failure session.
- [x] Nomad helper simulation: `Stop` reported a disposable `incomplete.txt`
  session by name, refused the preceding `last.txt`, retained its partial
  directory, and left the prior completed pointer unchanged. The disposable
  marker and directory were then removed.
- [x] The trace collection script waits for asynchronous finalization and
  verifies the completed session pointer before pulling the bundle.
- [x] Local failure-injection regression: malformed active/incomplete/failure
  pointers for every helper action, padded active bytes, multiline `last.txt`,
  unreadable/nonregular nodes, missing/ambiguous owner metadata, `pidof`
  failure, and ADB transport failure all retain state and cannot broadcast,
  mutate, pull, or fall back to an older completed trace.
- [x] Static invariant: checkpoint screenshots stage outside the remote session
  directory; Checkpoint revalidates active identity on both sides, and Stop
  revalidates completion before and after every remote pull.
- [x] Ordered trail fingerprints cover all trails while detailed trace items
  remain capped at 256.
- [x] Native Spread v0.0.116 active/inactive composition trace: two new active
  page-2 strokes persisted additively (`4 -> 5 -> 6` trails), then one direct
  inactive-page-1 stroke persisted additively (`3 -> 4` trails). Every prior
  trail on both pages remained visible through portrait page loads and the final
  landscape spread. Canonical file and current-memory fingerprints matched in
  portrait. Their expected landscape difference was entirely the native 4/3
  display transform: `1404x1872`/thickness `900` canonical trails became
  `1872x2496`/thickness `1200` in memory, with matching trail counts and scaled
  geometry rather than missing or substituted ink.
- [ ] Tapping native Undo/Redo or the bottom page-number bar on the inactive
  half does not activate that page before the native control handles the tap.
- [ ] After an inactive-page erase activates its page, a following active-page
  erase keeps every unrelated trail visible without requiring a page reload.
- [ ] In the plug-in reader, Native fill reaches the physical top and bottom of
  landscape while the header/footer visibly overlay the PDF instead of
  reserving document space.
- [ ] In Native fill, pen, eraser, lasso, highlights, and embedded links remain
  aligned with the PDF on both active sides. Pen alignment and persistence on
  the active page passed with Native Spread v0.0.85; the remaining tools still
  need a focused smoke test with the new trim transform.
- [ ] Return to Fit page and confirm all existing annotations return to their
  original whole-page positions.

## v0.4.14 transactional single-active-page candidate

Automated and build evidence:

- [x] Work starts from stable `main` at `4e4d3ed`; the v0.0.117 inactive-page
  merge experiment is preserved on `agent/v116-inactive-erase-regression` at
  `818db1f` and is not in this branch's ancestry.
- [x] Native PDF renderer invariants pass.
- [x] Native Spread safety invariants pass and require exact transaction/input
  guard publication -> thread-scoped source save -> writer disable -> target
  native load ordering. Concurrent pen contact, UI/history actions, and all
  other lifecycle saves remain blocked from publication through commit.
- [x] Static invariants require the inactive-page pen coordinate to be rejected
  in an Xposed `beforeHookedMethod`, before Supernote's native callback can add
  it to the source page's DrawPath.
- [x] Static invariants reject any live pen-activation route to the experimental
  trail capture, normalization, manual `.mark` merge, or synthetic history path.
- [x] Static invariants require reader-page and presenter-mark-page identity to
  match the exact target before geometry commits.
- [x] Static invariants require trigger-contact save and receive callbacks to be
  blocked until pen-up, and require timeout/completion work to match the exact
  transaction token.
- [x] Static invariants serialize contact-start latching, activation startup,
  and final guard removal under the same ownership lock, including contacts
  that begin in a gutter/cropped margin or race a queued transfer/commit.
- [x] Static invariants require the native pen-position callback and its queued
  activation/interception helpers to use a UI-published immutable
  document/page-geometry snapshot. Config parsing, file identity capture,
  `stat`, and other filesystem work are rejected from the low-latency path.
- [x] Static invariants keep a stroke that begins on the active page owned by
  that page and discard any points that cross into the inactive half.
- [x] Static invariants require source-page rollback to use bounded,
  exact-transaction retries. A reload exception or convergence timeout cannot
  leave UI/history/save guards published forever: after the final attempt, the
  native writer must be disabled and pen geometry invalidated before the
  transaction guard is released.
- [x] Static invariants require an editable RTL spread turn rejected by a
  temporary pen/geometry/transaction guard to be retained and replayed against
  its exact document and source page rather than reported as handled and lost.
- [x] Static invariants require the pen-lift completion path to republish ready
  target-page geometry before releasing a held activation transaction.
- [x] Static invariants reject synchronous logging, JSON serialization, and UI
  context capture in the native pen-position hook/interceptor. Contact-boundary
  trace data and coalesced block-state logs are enqueued to serialized workers.
- [x] Static invariants require a partial transaction-start failure to retain
  ownership through source rollback and suppress the legacy target-page
  activation fallback.
- [x] Static invariants require an explicit side-selection tap rejected during
  transient geometry publication to be retained and replayed against its exact
  document/source/target context.
- [x] Static invariants require active-page ink coordinates crossing into the
  other page, divider, or unmapped/cropped margins to remain blocked while the
  terminal pen-up callback is preserved.
- [x] Static invariants require a native-chrome-origin stylus contact to remain
  blocked from DrawPath through pen-up, even if it drags into the page.
- [x] Static invariants reject synchronous per-motion logging from the blocked
  UI-input hook and require coalesced boundary diagnostics on the background
  logger.
- [x] Static invariants require deferred spread turns to bind and revalidate the
  cover-parity value used to calculate their target.
- [x] Static invariants require every deferred activation to be cancelled when
  the latest validated document configuration explicitly disables editing or
  Native Spread.
- [x] A verified v0.4.12 `protected-editable-pilot` session is authorized only
  for one-time marker migration or backup retirement. Load-time migration
  retains the existing live `.mark` and recovery snapshot, publishes the
  transactional marker atomically with rollback, and verifies the new marker
  against the same backup before reporting editable mode.
- [x] Static invariants require protocol-2 editable activation to publish a
  non-authorizing `pending` marker before the final live-`.mark` check. Only the
  atomic `committed` marker publication authorizes writing, and committed
  markers cannot retain pending-only rollback fields.
- [x] Static invariants require a failed new activation to archive and verify a
  token-bound copy of its manifest and snapshot before restoring the previous
  marker or freeing the canonical backup slot. Partial archive stages are
  resumable; ambiguous or mismatched evidence remains non-mutating and
  fail-closed.
- [x] Static invariants require read-only and Off transitions to journal their
  intent and exact previous-marker identity before retiring recovery data, then
  revalidate that pending transaction before publishing the final state.
- [x] Static invariants serialize configuration, retirement, restore, and
  process-death reconciliation under one lock and require an exclusive restore
  claim before `.mark` replacement.
- [x] Native Spread v0.0.119 compiles, is v2/v3 signed, and reports matching
  manifest, handshake, and plug-in minimum version 119. The tested APK is
  164,524 bytes with SHA-256
  `d001ddea28d93873413372f9a284e3b801d2ee043df645fd0a42b551e595e44f`.
- [x] Static invariants require both firmware-specific eraser hooks before the
  native readiness gate is published. The regular vector eraser wrapper is
  restricted to pen type 16, color 255, and exact `932 x 1243` half-page
  geometry; it temporarily supplies canonical `1872 x 2496` dimensions, calls
  the original exactly once, restores both fields, and preserves its result.
- [x] Deep-review hardening is compiled as Native Spread v0.0.120 and requires
  RTL Reader v0.4.14. Hook readiness uses atomic attempted/installed state and
  non-null original functions; ambiguous hook results cannot be installed a
  second time. The v2/v3-signed local APK is 168,622 bytes with SHA-256
  `4e03659bbd5d01861fd41982c1913689728f81da4e03e21f3261d7a6b0e3982e`.
- [x] Native Spread v0.0.123 compiles, is v2/v3 signed, and reports matching
  manifest and runtime handshake version 123. The installed APK is 185,004
  bytes with SHA-256
  `fe39832044eef51851c9aa4b3815e856959a0df3fc0609f5ba6d987f83b0761f`.
- [x] A real Nomad interrupted-trace cycle atomically archived the exact
  abandoned `active.txt` file under its session-specific recovery directory,
  retained the partial trace, did not publish stale `last.txt`, and removed
  only the verified empty recovery guard. A subsequent normal trace completed,
  pulled, and produced a verified ZIP. After Stop, v0.0.123 restored the normal
  `RTL SPREAD: ACTIVE RIGHT page 1` header instead of leaving a stale
  `SPREAD TRACE: recording` banner.
- [x] The v0.0.123 lasso failure was captured without changing the canonical
  `.mark`: the moved preview remained correct until dismissal, where the stale
  generic pen-contact timer rejected `areaSelectionTransition`. Native Spread
  v0.0.124 gives the accepted selection its own immutable writer transaction,
  bypasses generic handwriting contact/fallback admission for lasso UI pen
  gestures, revalidates exact document/page/component identity at transition
  and rewrite, and retires authority only after the final rewrite callback.
  Document-identity resets and persisted-config reloads now also retire the
  exact lasso authority so an interrupted transaction cannot block later page
  activation.
- [x] Native Spread v0.0.124 compiles, is v2/v3 signed, and reports matching
  manifest and runtime handshake version 124. The local APK is 185,007 bytes
  with SHA-256
  `b02646ab4515d2e32c1df282fc75ae6197165328c98a575fe7ab271beff9b63c`.
- [x] The focused v0.0.124 hardware trace proved that moved ink now survives a
  delayed pen dismissal. It also isolated three follow-up defects: Supernote's
  180-pixel lasso padding shifted the finalized ink up and left and reduced its
  size; the native thinning pass made the floating ink disappear during the
  drag; and a moved selection finalized at `areaSelectionTransition` without
  reaching `reWriteTrails`, leaving its immutable authority active.
- [x] Native Spread v0.0.125 maps the centered bitmap content rather than the
  padded interaction frame, retains the original canonical selection bounds,
  supplies an unthinned move bitmap, and retires a successful move transaction
  from the transition callback. The checker structurally protects all four
  behaviors. The APK compiles, is v2/v3 signed, reports version 125, is 185,005
  bytes, and has SHA-256
  `683f4d3f869b23da7852dc3d4d9b6136690803c40bded796cea0a218ca1499b4`.
- [ ] On v0.0.125, select a short line, drag it to a different calibration box,
  wait at least 20 seconds, and dismiss the selection with the pen. The ink must
  remain visible throughout the drag, keep its original size, settle exactly at
  the preview location, and leave page activation/navigation usable afterward.
- [x] Canonical reloads after pen, eraser, Undo, and Redo require the exact root
  `saveTrails()` hook to have been admitted, counted, and completed without a
  throwable. The final writer proof and `loadHandWrite()` are linearized in
  lifecycle-safe OWNER-then-PAGE lock order.
- [x] Fresh-process startup and sequential document switching are distinguished:
  only an earlier exact reset/presentation proof activates the late-receive
  quarantine. Delayed orientation refreshes retain and revalidate exact
  document, generation, presenter, and view-model identity.
- [x] Restore-worker ownership and the post-restore handoff skip use separate
  atomic states; the skip is published before worker ownership is released.
- [x] A clean Windows plugin build embeds and verifies `app.npk`. CI and local
  publication require one package, exact `/icon.png` and `/app.npk` metadata,
  the exact ReactPackage, reviewed native classes, and the runtime marker.
  Failure-injection tests reject missing/corrupt native payloads and softened
  packager paths. A digest-advanced mutation audit rejected all eight targeted
  authority, lock, hook, workflow, and package-verifier regressions.

### Native Spread v0.0.126 ordinary-reader containment audit

- [x] Every Java hook that can suppress a firmware call, alter arguments,
  change page/selection geometry, or enter the writer lifecycle requires an
  exact verified activity/document control claim.
- [x] Ordinary activity startup and teardown do not enter Native Spread's
  owner write lock, JNI eraser gate, or spread editing-state restoration.
- [x] Missing, stale, or not-yet-bound presenter, view-model, handwriting view,
  native callback, and native-note identities delegate to firmware when no
  current/pending activity owns a control claim.
- [x] Text selection, highlight creation, highlight overlay, digest rendering,
  pen input, touch input, lasso, Undo/Redo, page turns, and embedded-link hooks
  are inert without a claim.
- [x] A verified transition to Off removes the claim before disabling the JNI
  gate and asking the firmware to restore its writable/selection areas.
- [x] Native C++ inspection confirms that the only detours are the two
  firmware-specific eraser functions. With the Java gate false, they pass
  unchanged arguments to the original exactly once and preserve its result.
- [x] Both invariant suites and trace-helper regressions pass. Fourteen
  digest-advanced adversarial mutations of claim, lifecycle, resolver,
  highlighter, setImage, JNI, and publication guards were all rejected.
- [x] The locally signed APK reports v0.0.126 / versionCode 126, verifies under
  APK Signature Schemes v2 and v3, is 185,007 bytes, and has SHA-256
  `c91d55613ceabb6b72c3c5240494373255e97eb1d55e92dd4748750465752b0f`.
- [ ] With the module installed and LSPosed enabled, cold-open an ordinary PDF
  with no `.snspread.properties` authority and verify native highlighter,
  underline, pen, eraser, lasso, Undo/Redo, links, taps, and swipes.
- [ ] Reboot and repeat highlighter creation/persistence before opening any
  Native Spread document.
- [ ] Open an enabled RTL editable document and verify spread navigation and
  native tools, then switch it Off and immediately repeat the ordinary native
  highlighter test without uninstalling or disabling LSPosed.

Nomad hardware gate (in progress):

- [ ] Finger-tap each inactive half. Existing annotations on both pages remain
  unchanged; native focus and the ACTIVE banner move to the requested page.
- [ ] Hover over the inactive page, wait for activation, then write. The first
  real stroke uses normal native behavior and persists after away/back.
- [ ] Draw several normal and quick connected strokes on the active page. Pen
  samples remain smooth, no stroke is dropped, and the settled native ink
  matches the gesture after away/back.
- [ ] Touch the inactive page with the pen before activation can complete. The
  trigger gesture creates no partial or wrong-page ink; after lifting, the
  target is active and the next stroke persists normally.
- [ ] Repeat the direct-contact test in both directions and confirm no source
  page annotation count or visible ink changes.
- [ ] Begin a stroke on the active page and drag across the divider. It remains
  an active-page stroke, does not switch focus, and leaves no ink on the other
  page.
- [ ] On each active side, validate pen, stroke eraser, lasso move, top-toolbar
  Undo/Redo, highlighting, and an embedded link through native controls.
  Regular stroke erasure on active left page 2 passed with v0.0.119: the
  accepted eraser contact published `active_eraser`, reloaded the canonical
  page, remained visibly erased after Active Left -> Active Right -> Active
  Left, and survived a cold document-reader restart. The post-erasure and
  cold-reopen `.mark` SHA-256 both equal
  `9a61d949f6437a0f55986ba85b5797ba2e01743e46402607faefe351fcd211dd`.
  The trace recorded zero potential failures. The first eraser contact after
  process restart was intentionally discarded by the pre-existing
  document-context receive quarantine; a subsequent fresh contact retired the
  quarantine and persisted normally. The opposite side and remaining tools are
  still open. A v0.0.121 lasso trace isolated one remaining defect: the lasso
  polygon reached the ordinary active-pen settled-ink save/reload path, which
  resurrected the selected source trail beneath Supernote's floating selection.
  v0.0.125 leaves that refresh under the native selection buffer, carries exact
  selection authority through the real lasso transition/rewrite boundary,
  accounts for Supernote's padded lasso frame, and completes moved selections
  at their actual transition boundary. Static invariants and compilation pass;
  the select-drag-pen-dismiss round trip remains the only required stylus
  validation for this correction.
- [ ] Advance and reverse spreads with taps and swipes. Every turn saves the
  source, lands on the expected RTL spread, and leaves writing enabled only for
  the focused page.
- [ ] Rotate landscape -> portrait -> landscape and turn away/back. Canonical
  annotations on both pages remain complete and correctly aligned.
- [ ] Force an activation timeout or identity mismatch in a disposable test.
  Writing visibly fails closed and no `.mark` merge fallback runs.

## v0.4.10 protected native editing pilot

Safety and setup:

- [x] v0.4.10-r1 identifies Native Spread v0.0.75 through the live handshake.
- [x] The recovery manifest's full PDF SHA-256 remains valid after Supernote
  changes the PDF modification time during a native-reader restart.
- [x] **RTL editable** requires a separate confirmation and reports a verified
  recovery snapshot before it becomes selected.
- [x] An existing `.mark` snapshot matches the pre-test byte length and SHA-256.
- [x] Leaving a protected editable session retires that session's recovery
  baseline; a later **Back up & enable** cannot reuse it after an unprotected
  interval.
- [x] Recovery re-enumerates every native document PID and aborts before
  touching `.mark` unless all original or replacement processes have exited.
- [x] Restore resolves only after the worker's verified outcome and shows a
  visible failure message if an asynchronous recovery step fails.
- [x] Backup retirement stages the snapshot first, rolls it back if manifest
  removal fails, and recovers or cleans interrupted retirement state on load.
- [x] The companion hashes protected PDF and snapshot bytes off the activity
  main thread and keeps native editing disabled until verification completes.
- [x] Successful asynchronous verification refreshes an already visible
  landscape spread so native handwriting is re-enabled immediately.
- [x] Backup-creation failure removes a newly copied orphan snapshot when no
  manifest exists.
- [x] Successful restore uses the same staged, rollback-capable cleanup as
  backup retirement before reporting completion.
- [x] Cover controls and synchronization are blocked while a native-mode
  transition is pending; a Cover change holds the same lock until its own
  marker update completes.
- [x] A successful Off or read-only transition clears the retired recovery
  snapshot status and Restore action from the settings UI.
- [x] Cover cannot change while a configured marker's live hooks are
  unavailable, preventing UI/sidecar parity drift.
- [x] The protected-verification cache includes device/inode and nanosecond
  change time, so a metadata-preserving PDF replacement invalidates prior
  authorization and reruns full-file attestation.
- [x] Native Spread v0.0.79 applies the same strong identity to the marker,
  recovery manifest, and recovery snapshot; replacing or rewriting any sidecar
  invalidates the cached editable authorization and forces re-attestation.
- [x] Switching to LTR commits the direction only after native RTL shutdown and
  recovery-baseline retirement succeed; failure retains the RTL UI state.
- [x] First-time editable activation revalidates the live `.mark` presence,
  length, and SHA-256 immediately before marker creation. A native flush during
  backup creation retires and retries the snapshot, including the original
  absent-file case, and repeated instability fails closed without a marker.
- [ ] A document with no `.mark` records and can restore the original absent state.
- [ ] Removing or modifying a backup file makes editable mode fail closed.
- [ ] Read-only mode and **Off** retain their v0.4.7-r1 behavior.

Protected duplicate editing:

- [x] Native writing persists on the active left page through a cold restart.
- [x] Saved ink remains visible on the inactive page without deleting prior
  annotations and after spread turns. The v0.0.75 hardware trace preserved the
  seven existing `.mark` trails, appended the new trail as the eighth, and
  reloaded all eight after leaving and returning to the spread.
- [x] Stroke erasing on the inactive page removes only intersecting saved ink.
  On a fresh v0.0.78 disposable document, two separated page-5 strokes were
  shown beside a clean active page 4. The process-7 eraser transaction reported
  `erased=1`, retained one trail, left page 4 unchanged, and the selective erase
  remained correct after turning away from and back to the spread.
- [x] A failed inactive-page `.mark` transaction cannot silently complete the
  page switch and discard its retained ink/eraser buffers. The v0.0.79 invariant
  requires failure detection before `loadPage`, explicit activation cancellation,
  and a visible save-failure state.
- [x] Native Spread v0.0.80 compares every path point plus pressure, angle, draw
  flags, timestamps, color, thickness, and related pen attributes before treating
  an inactive-page stroke as already persisted. Endpoint-only collisions cannot
  silently discard a retraced line or colocated dot.
- [x] The packaged Native Spread version, runtime handshake version, and plug-in
  compatibility floor are required to match, preventing a valid module upgrade
  from being rejected as an older incompatible build.
- [x] The settings panel is viewport-bounded and its body scrolls, keeping the
  expanded editable-mode confirmation and recovery controls reachable in
  landscape.
- [x] Eraser changes persist after a normal page-change save and cold restart,
  and do not alter the protected recovery snapshot.
- [x] Lasso selection/movement preserves size and position through a spread
  turn and cold restart in canonical page coordinates.
- [ ] Text highlight/underline selection and final annotations remain aligned.
- [ ] Embedded document links, swipes, and outer-edge taps retain RTL behavior.
- [ ] Portrait RTL navigation and landscape active-page switching remain correct.

Recovery and portability:

- [x] **Restore snapshot** reopens the native reader with the exact original
  `.mark` SHA-256 (or removes the pilot-created `.mark` when none existed).
- [x] Completed recovery files are removed so a later pilot takes a fresh baseline.
- [x] InkBridge's existing Supernote page export sees the pilot-created,
  lasso-moved handwriting as ordinary schema-v2 elements.
- [ ] InkBridge page reconciliation emits a tombstone for a stroke erased after
  a prior portable baseline was captured.
- [ ] No stale/blank/out-of-order spread, crash, or native handoff regression occurs.

The protected 738-page pilot recovery test restored the live `.mark` from
147,752 edited bytes to the original 89,801-byte snapshot. Its final SHA-256
was exactly
`c2155e51a686a3ba7066c8ef7d859c19053019e85d23d1414fa1a69dc9de2c21`,
the document activity reopened normally, and all `.snspread*` recovery and
marker sidecars were removed. The pre-restore edited `.mark` and verified
recovery snapshot were retained as local test evidence for the InkBridge
portability check.

For that check, the edited snapshot was staged temporarily and page 145 was
exported through InkBridge's installed **Export Page Test** action. The
schema-v2 payload contained the moved X as two native strokes with 84 samples,
stable Supernote UUIDs, normalized page geometry, pressure, thickness, pen
type, and pen color. The original `.mark` was then restored again with the
same verified SHA-256 and the temporary device copies were removed. A separate
write-baseline-erase-reconcile cycle is still needed to validate a deletion
tombstone; a final page snapshot alone correctly contains only the surviving
strokes.

The final reviewed v0.4.10 / Native Spread v0.0.68 smoke test repeated the
first-time protected activation on the same pilot. The plug-in created and
verified the 89,801-byte baseline while immediate Close and hardware-Back
attempts were blocked, then opened the native spread with protected editing
active. A new native stroke changed the live `.mark` to 91,009 bytes; its erase
was committed through the normal Supernote annotation path. **Restore
snapshot** then replaced the edited file with the original baseline, reproduced
the exact SHA-256 above, reopened page 145, and removed every `.snspread*`
sidecar. No temporary inspector or rotation override was left running.

One non-destructive visual difference remains: the low-latency live pen preview
in a half-page landscape spread initially appears thicker than the settled
stroke after Supernote commits and redraws it. The saved `.mark` retains the
canonical Supernote thickness and remains portable through InkBridge; matching
the transient preview to the half-page scale is tracked as post-v0.4.10 polish.

### Native Spread v0.0.130 native-control and lasso-persistence regression

Automated pre-device checks:

- [x] Visible native chrome is published from current global view rectangles,
  including separate popup-window roots, and is refreshed on layout changes
  and synchronously at stylus DOWN.
- [x] A chrome-origin stylus contact receives one exact gesture token; the
  Activity and low-latency native callbacks bypass handwriting ownership,
  activation, remapping, trace mutation, and save/reload until its matching
  UP/CANCEL.
- [x] A document-origin contact is never reclassified when it crosses visible
  chrome, and hiding or moving a toolbar invalidates its former rectangle on
  the next DOWN.
- [x] A verified visible-chrome DOWN is passed to firmware regardless of page
  or writer authority; only malformed, mismatched, or raced gesture streams
  are blocked. Native-first callbacks cannot reclassify an already-started
  document contact.
- [x] A canonical lasso move invokes Supernote's region rewrite, global-layout
  flag, bitmap refresh, and writer clear before restoring the spread mark
  origin or completing the exact lasso authority.
- [x] Java compilation, native PDF invariants, Native Spread safety invariants,
  trace-helper failure tests, and whitespace validation pass.

Focused Nomad checks:

- [ ] Select Pen, regular Eraser, Highlighter, and Lasso with the stylus; each
  native control arms exactly as it does with a finger and creates no ink mark.
- [ ] Move the native toolbar, repeat stylus selection, then hide it and verify
  its former rectangle accepts ordinary document ink.
- [ ] Start a document stroke and cross into the visible toolbar; it remains a
  document gesture and does not activate a control.
- [ ] Select and move a lassoed stroke, dismiss the floating selection, turn
  away and back, and cold-reopen the document. The moved ink remains visible,
  singular, correctly sized, and at the released location.
- [ ] Undo and redo the lasso move affect only that selection; companion-page
  ink remains unchanged.
- [ ] Ordinary non-Native-Spread highlighting still works, and Close returns
  the native reader to the correct active page.

### Native Spread v0.0.131 text-selection contact regression

Automated pre-device checks:

- [x] Active-page text-selection DOWN is classified before Activity and native
  handwriting ownership, and the exact contact remains firmware-owned through
  UP/CANCEL.
- [x] Native text-selection hardware is configured for the active page and is
  never disabled by model change, stylus DOWN, or `handWriteSelectText` state 0.
- [x] Text-selection contacts cannot publish ordinary pen ownership, start page
  activation, or be reclassified as native chrome while crossing a toolbar.
- [x] Native-only and Activity-routed terminal states retire the selection
  token, and activity/global lifecycle reset clears all selection state.
- [x] v0.0.131 compiles, verifies under APK Signature Schemes v2/v3, reports
  matching manifest/runtime version 131, is 185,006 bytes, and has SHA-256
  `89f2188fa04e5cb3e9e24d0aa90ec8a1d66b774565949cd1717413943d7a2237`.

Focused Nomad checks:

- [ ] Select Highlighter with the pen, highlight active-left text, and confirm
  the live preview, final selection/menu, and persisted highlight are aligned.
- [ ] Confirm the selection logs native `handWriteSelectText` states without
  `pen_contact_activity_touch_latched` for the same gesture.
- [ ] Close the selection, activate the right page immediately, and confirm no
  `page activation waiting for pen/page state` banner appears.
- [ ] Highlight active-right text, turn away/back, and confirm both pages retain
  their annotations; repeat once outside Native Spread.

Initial v0.0.131 hardware result:

- [x] The failed active-left highlight no longer entered ordinary handwriting
  ownership and no longer left page activation permanently waiting.
- [x] The exact contact classified and retired cleanly, but Supernote emitted no
  `handWriteSelectText` state because its native `isAllowTurnPage` prerequisite
  remained true; the firmware gesture listener handled the contact instead.

### Native Spread v0.0.132 native text-selection gate regression

Automated pre-device checks:

- [x] Activity DOWN applies the native `isAllowTurnPage=false` gate only after
  exact active-page selection ownership is published/adopted and before the
  unmodified event reaches Supernote.
- [x] Exact Activity UP/CANCEL restores the prior native page-turn value only
  after the firmware dispatch completes, then retires the selection token.
- [x] A native terminal cannot prematurely remove an Activity-owned selection;
  a bounded main-thread fallback restores and retires it only if Activity UP is
  missing.
- [x] Activity/global lifecycle cleanup restores any applied gate instead of
  discarding the token, and structural invariants enforce these orderings.
- [x] v0.0.132 compiles, verifies under APK Signature Schemes v2/v3, reports
  matching manifest/runtime version 132, is 185,004 bytes, and has SHA-256
  `ac200814f85ae091b1cf83438d62e3e6a983ac28f0cda675963329a45b7b5bc8`.

Focused Nomad checks:

- [x] Pen-select Highlighter, draw across active-left text, and confirm native
  `handWriteSelectText` states plus an aligned live/final highlight.
- [x] Confirm `text_selection_activity_gate_applied` precedes native selection
  and `text_selection_activity_gate_restored` follows its terminal dispatch.
- [x] Immediately activate the right page with a finger and confirm navigation
  is not stuck or suppressed.
- [x] Highlight active-right text, turn away/back, and confirm both pages retain
  their annotations.
- [ ] Repeat text selection and choose **Underline** from Supernote's result
  menu; confirm alignment and persistence on both active sides.

### Native Spread v0.0.135 early digital-down text-selection regression

Automated pre-device checks:

- [x] The Activity `ACTION_DOWN` classifier is authoritative and may adopt only
  the exact otherwise-unowned physical digital-down emitted immediately before
  that same text-selection gesture.
- [x] The native-first classifier remains unable to adopt an already-down pen,
  and competing handwriting, activation, lasso, page, or chrome ownership
  rejects the selection fail closed.
- [x] A rejected Activity selection returns the blocking route before ordinary
  handwriting publication, while `onDigital(1)` rechecks text-selection
  ownership under the same lock before publishing physical-contact state.
- [x] Structural invariants enforce the classifier roles, atomic adoption,
  rejection ordering, and digital-down recheck. Native PDF invariants, Native
  Spread invariants, packaging failure tests, trace-helper tests, compilation,
  signing verification, and whitespace validation pass.
- [x] The locally signed APK reports v0.0.135 / versionCode 135, is 201,389
  bytes, and has SHA-256
  `d8ae6261d281e56851cf8af68548f91658041c7df4d244e3ee0cef8c69809b32`.

Focused Nomad checks:

- [x] Draw and settle ordinary ink on active left, then pen-select Supernote's
  text-selection tool without creating stray ink or retaining handwriting
  ownership.
- [x] Underline active-left text. The trace records
  `text_selection_preclassified_digital_down_adopted`, followed by gate apply,
  Activity classification, gate restore, and exact contact retirement.
- [x] Activate the right page immediately, pen-select the same native tool, and
  apply Highlight with correct live/final alignment and no stuck page state.
- [x] Both active sides retired their selection and result-menu contacts. No
  `pen_contact_receive_expired` event occurred, and the finalized trace reports
  zero potential failures with four changed `.mark` snapshots.
- [x] Trace archive SHA-256:
  `20b5462b58b46f4923d43c119867c8951b4bfe8dba174098a546831c569a7cb1`.

### Native Spread v0.0.134 recognized-straight-line transaction

Automated pre-device checks:

- [x] Exact `straightLine` / two-point recognition begins an authority token
  while the original receive contact, active writer, page, document, layout,
  and native split offset are still current.
- [x] The recognized-line `receiveTrials` branch defers the ordinary canonical
  save/reload instead of replacing Supernote's live editor coordinate frame.
- [x] `onEditLineMode` maps the native split-local editor geometry into the
  active physical page slot and rejects invalid, missing, unclassified, or
  stale transaction authority before Supernote can show its native editor.
- [x] `onEditLineTransition` revalidates exact authority, maps final physical
  endpoints back to Supernote's native split-local frame, lets the native
  commit succeed, and only then performs the canonical save/reload.
- [x] A recognized-line editor or commit in editable spread mode cannot fall
  through to native coordinates when its exact transaction is absent; the
  structural checker rejects both editor and commit fail-open regressions.
- [x] Activity release, global editing reset, and a later ordinary receive
  retire abandoned line authority; raw edit-line touch rewriting is forbidden.
- [x] Native Spread safety invariants and the full native build pass. The
  locally signed APK reports v0.0.134 / versionCode 134, verifies under APK
  Signature Schemes v2/v3, is 185,004 bytes, and has SHA-256
  `d27686f73729ae51f33a809ccdf32ba328b343a822a5dcde144c5f7778e783c7`.

Focused Nomad checks:

- [x] On active-right Box G, draw a short horizontal line and hold its endpoint
  for about 1.5 seconds. Confirm the live editor remains horizontal/aligned and
  does not jump into a large diagonal before or after pen lift.
- [x] Turn away/back and cold-restart the document reader; confirm the line
  remains horizontal, correctly placed, and singular.
- [x] Repeat the held-line test on active left, then draw ordinary unheld lines
  on both pages to confirm their existing path is unchanged.
- [x] Repeat one highlight and the pending Underline selection to confirm the
  v0.0.132 text-selection path remains aligned and persistent.

Focused v0.0.135 hardware result:

- [x] Seven recognized-line transactions across the right and left active
  pages entered the remapped native editor, deferred canonical reload until
  native commit, and logged `recognized_line_commit_persisted`.
- [x] The first right-page line showed only a small native straightening snap;
  no line became the former large diagonal or left its intended area. Later
  right-page lines and every left-page line remained visually stable.
- [x] A cold document-process reopen preserved every tested line in its
  original position without duplication. Trace archive SHA-256:
  `d857f14b7f41c5d482e027f2e7e26110f2f9090562c922b815837c1f4752fc96`.
## Native Virtual Spread v0.0.8 architecture validation — PASS

Hardware validation was completed on 2026-08-21 on a Supernote Nomad running
firmware fingerprint
`Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys`
and SupernoteDocument `1.02.446`, using the native
`com.supernote.document` reader. The legacy dual-page Native Spread compositor
was disabled and absent from the document process.

- [x] Native landscape displayed `blank | cover`, `3 | 2`, `5 | 4`, and
  `7 | 6` as real fixed PDF spread pages.
- [x] Native beginning/end boundaries, RTL turns, and portrait half focus were
  correct, including internal links to both halves plus Back/Original Back.
- [x] Mixed rotations and extreme source page dimensions navigated without the
  former page-turn failure.
- [x] Portrait-to-landscape and landscape-to-portrait refresh completed without
  a page turn while retaining the focused source half.
- [x] Pen input on both halves, erasing, lasso movement, undo/redo, text
  highlighting, and portrait writing all persisted through document round trips.
- [x] An ordinary PDF without a valid sidecar retained unmodified native LTR
  behavior and emitted no virtual-spread events.

The complete fixture list, visible observations, logs, and before/after `.mark`
hash evidence are recorded in `virtual_spread/HARDWARE_VALIDATION.md`. Later
v0.0.9-v0.0.15 changes harden manifest authority, revision invalidation,
publication transactions, internal-link mapping validation, and asynchronous
full-file verification. v0.0.13 also rejects reversed link rectangles and
dereferences indirect PDF destinations. v0.0.14 generates from a stable source
snapshot, verifies source bytes independently of filesystem timestamps, binds
the complete ordered link collection to the hashed PDF, and recovers an
interrupted two-file publication through a transaction marker. v0.0.15 binds
direction, cover parity, source/output page counts, spread geometry, and gutter
to a second authority marker inside the hashed PDF, preventing stale sidecars
from swapping layouts with equal page counts. It also makes Windows publication
durable with write-through marker, backup, publication, rollback, and retirement
renames; POSIX continues to synchronize affected directories. Older generated
pairs fail closed and must be regenerated. The 19 generator regressions include
metadata-preserving source changes, exact cross-language layout vectors,
write-through flag invariants, plus both partial and fully committed
crash-recovery states. CI also runs the complete Java companion-module suite,
including ten layout/link authority assertions.
A ninth review pass added an OS-owned per-pair publication lock so a concurrent
generator cannot recover another process's live transaction, enforces the
runtime's 8 MiB sidecar limit before publication, and makes CI compile, D8,
package, sign, and verify the actual companion APK on Ubuntu. Deterministic
regressions hold a live lock/marker while a second generator is rejected and
inject an oversized staged manifest before any final file can change.
A tenth review pass made publication ownership exclusively output-PDF keyed and
restricted generation to the runtime's only discoverable sibling sidecar,
`<output>.json`. One regression proves syntactic aliases of the same output use
the same transaction artifacts and OS lock; another proves an alternate
manifest path is rejected before a lock is created or the existing PDF, runtime
sidecar, or alternate file can change. The generator suite now contains 21
tests.
An eleventh review pass rejects an output path containing a symlink, junction,
or other filesystem alias before publication ownership is acquired. This keeps
the generator's sidecar location identical to the lexical PDF path later probed
by the Android runtime. A deterministic alias-path regression and a static
guard-before-lock invariant raise the generator suite to 22 tests.
A twelfth review pass keeps the lexical output and sibling manifest paths through
the locked generation/recovery pipeline and repeats alias validation after the
output-keyed OS lock is acquired. It also requires every existing publication
target, transaction marker, and backup to be a regular file before rename or
removal, so `--force` cannot displace a directory or special entry. Regressions
simulate an alias appearing between the initial check and locked build, and
preserve both output- and manifest-directory fixtures byte-for-byte. The suite
also prevents a concurrently introduced backup directory from becoming a rename
destination and rechecks file existence after interrupted-publication recovery.
A thirteenth review pass protects the deterministic lock itself with no-follow,
regular-file, and open-descriptor identity checks, and validates staged plus
canonical publication hashes before retiring rollback state. It also moves all
sidecar reads and hashes off native reader callbacks: UI paths compare strong PDF
and sidecar identities while the background verifier proves stable content.
Three fault and alias regressions raise the suite to 29 generator tests.
A fourteenth review pass binds every PDF, sidecar, full-file hash, and embedded
authority read to one captured descriptor pair. The verifier rejects a mismatch
between callback identity and opened handle, rechecks both handles after all
reads, and proves that each handle still names the visible pathname before
publishing a cache entry. Publication marker v2 records the previous PDF and
manifest hashes; recovery authenticates backups before restoring them and leaves
tampered evidence in place. The generator also carries a live lock-identity guard
through recovery and publication and rechecks it before each shared namespace
mutation. A POSIX lock-replacement regression and a tampered-backup regression
raise the generator suite to 31 tests; the complete Java companion suite and
signed APK build also pass locally. A fifteenth review pass closes the remaining
check-then-mutate race for cooperating publishers: POSIX generators acquire one
stable output-directory lock before the per-output lock and retain both until the
complete transaction ends. Replacing the per-output lock pathname therefore
cannot admit a second generator between an ownership check and its mutation;
Windows retains its nonreplaceable open-file lock. A deterministic Linux
regression recreates the per-output lock during an active transaction and proves
that a second publisher is still rejected, raising the generator suite to 32
tests.
A sixteenth review pass binds the complete POSIX publication namespace to the
already-open output-directory descriptor. Staged PDF and manifest creation,
writes, verification reads, hashes, size/type checks, transaction marker and
backup operations, publication, rollback, and cleanup no longer resolve the
replaceable parent pathname. The source snapshot uses one already-open temporary
stream outside that namespace. Two deterministic Linux regressions exchange the
parent directory precisely between validation and a final replace or staged JSON
open. In both cases the replacement tree remains byte-for-byte unchanged while
the original locked directory receives the descriptor-relative operation. The
generator suite now contains 34 tests and passes completely on Linux; Windows
passes the same suite with its five platform-specific POSIX cases skipped. A
seventeenth review pass binds the 8 MiB runtime manifest ceiling, staged-file
identity, and SHA-256 to one open descriptor. The same identity, size ceiling,
and digest are revalidated before marker establishment, immediately before the
sidecar move, and after canonical publication; interrupted-publication recovery
also refuses to commit an oversized sidecar. Two deterministic races replace the
already-checked staged manifest immediately before transaction preparation with
either an oversized regular file or a byte-identical file on a different inode.
Both prove that the previous PDF/sidecar pair remains untouched. The generator
suite now contains 36 tests and passes completely on both Windows and Linux,
with only the five POSIX-only cases skipped on Windows.
An eighteenth review pass symmetrically binds the staged PDF's identity, size,
and SHA-256 to the manifest and transaction. Descriptor-bound evidence is
captured before strict PDF verification, revalidated afterward, and carried
unchanged through marker creation, the sidecar move, the PDF move, and final
canonical verification. Two deterministic races replace the already-checked
staged PDF immediately before transaction preparation with either different
bytes or byte-identical content on another inode. Both fail before the existing
PDF/sidecar pair changes. The generator suite now contains 38 tests and passes
completely on both Windows and Linux, with only the five POSIX-only cases skipped
on Windows.
A nineteenth review pass makes invalid-marker recovery handle the generator's
own validation errors as well as malformed JSON and I/O failures. An obsolete v1
marker is discarded only when neither backup exists, allowing recovery from a
crash after marker durability but before canonical mutation. If either backup
exists, recovery still fails closed and preserves all evidence. Two regressions
cover both branches, raising the generator suite to 40 tests on Windows and
Linux.
A twentieth review pass validates and recovers the usable v1 marker fields when
no backup exists. Only an unambiguous pre-mutation state discards its obsolete
marker: previously existing artifacts must remain present without matching the
staged digest, and previously absent artifacts must remain absent. Partial or
complete new publication and every ambiguous state remain fail-closed with all
evidence preserved. Unknown or malformed markers are discarded only when both
canonical artifacts and both backups are absent. Three regressions cover a
sidecar-only partial publication, a complete new pair, and an unknown marker with
a canonical artifact, raising the generator suite to 43 tests on Windows and
Linux.
A twenty-first review pass rejects duplicate JSON keys while parsing publication
markers and requires the exact field set for each recognized transaction schema.
Structurally ambiguous markers bypass the evidence-free invalid-marker discard
path and remain fail-closed even when no backup exists. Two regressions preserve
the marker and canonical pair for a duplicate legacy field and an unknown legacy
field, raising the generator suite to 45 tests on Windows and Linux.
A twenty-second review pass preserves supported internal destination modes and
transforms `/XYZ`, horizontal-fit, vertical-fit, and `/FitR` coordinates through
the target source-to-spread affine transform. Unsupported modes and partial
coordinates that cannot survive rotation now fail closed instead of silently
degrading to `/Fit`. Two regressions cover all eight supported destination modes
and one unsupported mode, raising the generator suite to 47 tests on Windows and
Linux.
A twenty-third review pass accepts destination modes only as PDF name objects
and coordinates only as PDF numeric/null objects. Null `/XYZ`, horizontal-fit,
and vertical-fit coordinates survive only when the source and target transforms
preserve the relevant generated-spread axis; otherwise generation fails closed
rather than retaining a coordinate from the wrong half or page geometry. Three
regression groups cover matching transforms, differing transforms across all six
partial destination forms, string-typed modes, and numeric strings, raising the
generator suite to 50 tests on Windows and Linux.
A twenty-fourth review pass preserves multiline link activation geometry by
transforming every coordinate in a valid `/QuadPoints` array while retaining
quadrilateral order. Empty, non-array, incomplete, null, nonnumeric, nonfinite,
or overflowed quadrilateral geometry fails closed rather than widening the link
to its bounding `/Rect`. Positive and malformed regressions raise the generator
suite to 52 tests on Windows and Linux.
A twenty-fifth review pass makes generator/runtime direction support explicit:
LTR is rejected before publication because the companion runtime intentionally
accepts only RTL manifests. Rebuilt links now retain every standardized integer
annotation `/F` bit, while malformed, negative, or unknown flag values fail
closed instead of turning a hidden or NoView link into an ordinary active link.
Link `/Rect` arrays likewise require exactly four finite PDF number objects in
increasing coordinate order, preventing numeric-string coercion, non-finite
geometry, and repaired reversed hit regions. Three new regression groups plus
the revised direction test raise the generator suite to 55 tests on Windows and
Linux.
A twenty-sixth review pass closes the complete supported-link annotation
surface rather than continuing a field-by-field whitelist. Visible `/Border`
and `/BS` styling, color, and `/H` activation highlight modes are validated,
scaled through the source-to-spread transform, and retained. URI actions now
require a PDF text-string operand and preserve a Boolean `/IsMap`. Chained
`/Next` actions and unimplemented appearance, optional-content, additional-
action, previous-action, structural-parent, or unknown entries fail closed
instead of being partially reconstructed. Positive border/highlight and URI
fixtures plus malformed and unsupported semantic matrices add five regression
groups, raising the generator suite to 60 tests on Windows and Linux.
A twenty-seventh review pass rejects every deterministic marker, backup,
retirement, and lock filename as a source path before recovery or lock
acquisition, so transaction cleanup cannot delete or overwrite an unusually
named input PDF. The generator also detects a source catalog `/Outlines` tree
and fails before publication rather than silently removing native table-of-
contents navigation; destination remapping remains an explicit future
capability. The runtime documentation now accurately distinguishes its
identity-only callback fast path from descriptor-bound sidecar and PDF hashing
on a background cache miss. Two deterministic regression groups cover all
nine reserved source names and outline rejection, raising the generator suite
to 62 tests on Windows and Linux.
A twenty-eighth review pass extends the document-catalog preflight to reject a
source `/OpenAction` before staging or publication, preventing the generated
PDF from silently losing its persisted opening destination, zoom, or action.
A serialized destination-array fixture verifies that the source and an existing
published PDF/manifest pair remain byte-for-byte unchanged, raising the
generator suite to 63 tests on Windows and Linux.
A twenty-ninth review pass replaces the field-by-field document-catalog guard
with an explicit complete supported surface. The generator preserves validated
`/PageMode` and `/PageLayout`, regenerates structural `/Type` and `/Pages`, and
rejects `/OCProperties` plus every other unsupported or unknown catalog entry
before staging or publication. A real default-off optional-content-group
fixture covers the reported visibility-loss case; positive view-setting
preservation and generic viewer-preference rejection prevent another catalog
field from being silently dropped. The generator suite now contains 66 tests
on Windows and Linux.
A thirtieth review pass applies the complete supported-surface design to each
source page dictionary. Content, resources, geometry, rotation, and supported
links remain explicit inputs; ReportLab's empty transition placeholder is
accepted as inert; persisted durations, meaningful transitions, additional
actions, user-unit scaling, and every other unsupported or unknown page entry
fail closed before staging or publication. Real `/Dur`, `/Trans`, `/AA`, and
`/UserUnit` fixtures verify all reported and generic paths while preserving the
source and previous publication pair, raising the generator suite to 68 tests
on Windows and Linux.
A thirty-first review pass requires `/Rotate` to be an actual PDF integer and
an exact multiple of 90 before normalization, rejecting string, fractional, and
non-quarter-turn values without publication changes. Document information now
bypasses pypdf's string-coercing `add_metadata()` helper: validated text,
byte-string, name, Boolean, integer, real, and null primitives are copied with
their PDF types intact; standardized text and `/Trapped` entries are constrained;
arrays, dictionaries, streams, and other unsupported values fail closed. Typed
`/Trapped`, custom number/Boolean, malformed rotation, unsupported metadata,
numeric-title, and string-typed-`/Trapped` fixtures raise the generator suite to
72 tests on Windows and Linux.

A thirty-second review pass preserves `/XYZ` magnification after target-page
fitting by dividing every non-null zoom operand by the target affine scale.
Only finite, nondegenerate, orthogonal uniform transforms are representable;
non-uniform or skewed transforms fail closed. The same pass detects duplicate
annotation `/NM` identifiers after two source pages are paired onto one output
page and fails before publication instead of emitting ambiguous link identities.
Explicit scale, transform, and paired-page collision regressions bring the
generator suite to 76 tests. All 76 pass on Windows (with five platform skips)
and Linux; both native invariant suites, 47 navigation assertions, 10 link-
authority assertions, 8,752 exhaustive navigation assertions, hook scope, and
the signed v0.0.15 APK build also pass.

A thirty-third review pass restricts persisted `/PageLayout` values to
`/SinglePage` and `/OneColumn`. All four `/TwoPage*` and `/TwoColumn*` layouts
now fail closed before staging or publication because retaining them after
composition would place two complete virtual spreads—up to four source pages—
beside one another and change the source layout semantics. Subtests cover every
incompatible name while preserving the source and an existing output pair,
bringing the generator suite to 77 tests on Windows and Linux.

A thirty-fourth review pass validates every transformed destination coordinate
again immediately before constructing its PDF number object. Finite source
operands combined with extreme but finite affine coefficients can no longer
publish infinity or NaN through `/XYZ`, `/FitH`, `/FitBH`, `/FitV`, or `/FitBV`.
Direct overflow subtests exercise the shared guard through all three calculation
paths and bring the generator suite to 78 tests on Windows and Linux.

A thirty-fifth review pass applies the same fail-closed representability rule to
all transformed link-border geometry. Every radius contribution, border width,
border-style width, and dash measurement must remain finite after scaling, and a
positive source measurement may not collapse to zero. The `/XYZ` destination
path now likewise rejects a positive explicit zoom that underflows to zero while
preserving a literal zero as PDF's intentional "retain current zoom" value;
negative zoom operands fail closed. Direct overflow and underflow regressions
cover `/Border` radii/width/dashes, `/BS` width/dashes, and `/XYZ` zoom, bringing
the generator suite to 80 tests on Windows and Linux. These semantic guards do
not change the v0.0.15 hardware-smoke pair, which regenerates byte-identically.

A thirty-sixth review pass requires strict positive area immediately after every
shared rectangle transform and again at the Android float boundary. A valid
source link or `/FitR` rectangle whose endpoints collapse under scale and slot
translation can no longer be published as an unclickable zero-width or zero-
height region. The regression exercises the translated double-precision collapse,
the runtime defense, and the shared `/FitR` path, bringing the generator suite to
81 tests on Windows and Linux. The hardware-smoke pair remains byte-identical.

A thirty-seventh review pass closes the same invariant at every remaining
geometry boundary. The Android manifest parser and runtime link matcher now
reject exact zero-width or zero-height rectangles rather than publishing an
unmatchable target. Each transformed `/QuadPoints` group must retain strict
positive horizontal and vertical extent independently of its larger `/Rect`, so
slot translation cannot collapse a valid source quadrilateral into a line. The
generator also validates effective source page boxes before normalization and
rejects any derived page placement whose finite affine arithmetic collapses or
overflows. Deterministic regressions exercise both exact Android zero-area forms,
degenerate observed and persisted link targets, the translated quadrilateral
counterexample, and an extreme finite page box that previously produced a
zero-width placement. The generator remains at 81 tests on Windows and Linux;
the focused companion suite now passes 51 assertions, alongside 10 link-authority
and 8,752 exhaustive-navigation assertions. These fail-closed guards do not
alter the valid v0.0.15 hardware-smoke pair.

## v0.0.15 focused hardware smoke - PASS

A fresh pair was generated from `VS-Link-Target-Sides-source.pdf` with the
v0.0.15 generator and opened on the Nomad with companion module v0.0.15
(`versionCode=15`). The runtime accepted all four virtual spreads and activated
the exact regenerated manifest revision. The focused 2026-08-25 smoke pass
confirmed:

- initial landscape cold-open displayed `blank | page 1` without a page turn;
- rightward RTL turns displayed `3 | 2`, `5 | 4`, and `7 | 6` in order;
- an additional rightward turn at the end was an exact visual no-op, and the
  reverse turn returned to `5 | 4`;
- portrait focus immediately displayed full-size page 4 and later page 2, while
  both rotations back to landscape immediately restored the complete spread;
- internal links from page 2 opened the exact page 7 left half and page 6 right
  half, and native Back restored page 2 after each link;
- a native pen stroke written on portrait page 2 survived a page 3 round trip
  and appeared in the correct position on the right half of the landscape
  `3 | 2` spread; and
- the same source PDF opened without a sidecar remained an ordinary native
  single-page document and retained native LTR turns in portrait.

This closes the v0.0.15 release gate without repeating the already completed
v0.0.8 annotation campaign.

## Review pass 38 and v0.0.16 automated gate - PASS

The thirty-eighth review pass closes three remaining malformed-input and link-
view gaps. Effective `/MediaBox` and `/CropBox` coordinates must now be genuine
finite PDF number objects even when inherited through the page tree, preventing
pypdf's rectangle accessor from coercing numeric strings. Every source and
transformed `/QuadPoints` quadrilateral must contain at least one non-collinear
triple, so a diagonal line with positive horizontal and vertical bounding extent
cannot masquerade as a link activation region.

Source `/Fit` links are now encoded as `/FitR` around the original target source
page's placed rectangle rather than fitting the complete composite spread.
Viewport- and content-dependent `/FitB`, `/FitH`, `/FitBH`, `/FitV`, and `/FitBV`
forms fail closed because their original semantics cannot be represented safely
after two pages are composed. Link-authority v2 authenticates a `targetView`
field for every internal link. The companion uses that authenticated value to
restore the complete spread after a `/Fit` traversal in landscape while leaving
explicit `/XYZ` and `/FitR` views untouched; absent, non-string, or unknown view
values reject the whole manifest.

All 82 generator tests pass on Windows (with five platform-specific skips) and
Linux. Both native invariant suites pass. The companion passes 55 navigation
assertions, 10 cross-language link-authority assertions, 8,752 exhaustive
navigation assertions, hook-scope validation, and a signed/verified v0.0.16
(`versionCode=16`) APK build.

## Review pass 39 target-view ambiguity guard - PASS

The final exact-head draft review found that two link records could be
indistinguishable within the runtime's native-coordinate tolerance while
disagreeing on their authenticated target-view policy. The matcher now treats a
`resetLandscapeFit` disagreement exactly like conflicting source or target
halves and returns no match. A paired positive regression proves that duplicate
records with the same target-view policy remain deterministic. The focused
companion suite therefore increased from 53 to 55 assertions without changing
the valid unique-link path exercised on hardware.

## v0.0.16 focused hardware smoke - PASS

On 2026-08-25, `VS-v16-Fit-Smoke.pdf` and its sidecar were regenerated from
`VS-Link-Target-Sides-source.pdf` with the v0.0.16 generator. The pair contained
four source `/Fit` links rewritten as target-source-page `/FitR` destinations,
and every internal sidecar record authenticated
`targetView=fit-source-page`. The Nomad accepted and activated revision
`9fa9a9b875c0cc29a217c159693cf269b82ec0406372e0139a4ec10f3806ab29`.
The output PDF SHA-256 was
`09527f32803161d5d0b664cd68ce0f7409c8e3f2e86e25229847f2c23f0484ef`.

Hardware confirmed:

- in portrait, links from source page 2 opened page 6 and page 7 at normal
  native Fit-page size, and native Back restored the exact page-2 source half
  after each traversal;
- rotating page 2 to landscape immediately restored the complete `3 | 2`
  spread without a page turn;
- both landscape links opened the complete `7 | 6` spread with the intended
  right or left target half, and both native Back traversals restored `3 | 2`;
- neither landscape link produced visible zoom, flicker, stale content, or an
  incorrect page while the authenticated `internal_link_fit_reset` refresh ran;
- one forward and reverse native page-bar turn retained RTL ordering; and
- the same seven-page source opened as `VS-v16-Ordinary.pdf` without a sidecar
  remained the native single-page landscape reader and retained native LTR
  left/right swipe behavior.

After the visual pass, the review-pass-39 ambiguity guard was built as the exact
v0.0.16 APK (SHA-256
`73d0e1024c58993a3b8ec7646f75739b2f0886cd7273ef80fbe0b1fb8e57e679`),
installed on the same Nomad, and accepted and activated the same authenticated
fixture. That guard is reached only when multiple tolerance-equivalent link
records conflict; the tested fixture has one unique record per link, so the
completed visual evidence remains directly applicable.

## Review pass 40 native-open snapshot binding - AUTOMATED PASS

The exact-head draft review identified that pathname-level PDF and sidecar
verification did not prove that Supernote's already-open MuPDF object represented
those same bytes. A same-path replacement could therefore publish a valid new
manifest while the native reader still displayed the old object.

v0.0.17 adds a source-authority marker to the descriptor-verified PDF tail and
stores the authenticated source, layout, and link authorities in the parsed
manifest. Before activation, the runtime reflects the actual
`DocumentViewModel.mupdf -> DocumentMupdf.pdfMupdf -> PDFMupdf.document` object,
reads all three custom Info values with MuPDF `getMetaData()`, and requires an
exact match. The decision is cached only for that native `Document` object plus
manifest revision, so a newly opened native object is always revalidated.

Automated validation passes:

- 82 generator tests on Windows, with five expected filesystem skips;
- the same 82 tests on Linux with no skips;
- 60 focused navigation assertions;
- 12 cross-language PDF-authority assertions;
- 8,752 exhaustive navigation assertions;
- both native invariant suites and hook-scope validation; and
- signed APK verification for v0.0.17 (`versionCode=17`) using v2/v3 schemes.

Focused hardware validation of native metadata lookup and same-path replacement
fail-closed behavior remains pending.

## Review pass 41 transformed-link and manifest typing - AUTOMATED PASS

The exact-head draft review identified four additional semantic-preservation
boundaries. v0.0.18 now rejects URI `/IsMap true`, because a viewer would append
coordinates from the transformed spread rather than the source page. Link
`/Rect` and `/QuadPoints` geometry must remain wholly inside the effective source
CropBox so hidden source interactions cannot become visible after composition.
When both `/Border` and `/BS` are absent, the generator materializes PDF's
implicit `[0 0 1]` border with the transformed width. Finally, the Android
manifest parser accepts only actual JSON Integer or in-range Long tokens for
every consumed page count and page index; strings and floating-point values no
longer coerce or truncate into valid mappings.

Automated validation passes:

- 85 generator tests on Windows, with five expected filesystem skips;
- the same 85 tests on Linux with no skips;
- 68 focused navigation and manifest-typing assertions;
- 12 cross-language PDF-authority assertions;
- 8,752 exhaustive navigation assertions;
- both native invariant suites and hook-scope validation; and
- signed APK verification for v0.0.18 (`versionCode=18`) using v2/v3 schemes
  (SHA-256 `08576673386430ba8ce38c35c314e5a1d04ce2bfd517bbbe422da69675eec92c`).

Focused hardware validation of native metadata lookup and same-path replacement
fail-closed behavior remains pending.

## Review pass 42 exact output-size typing - AUTOMATED PASS

The exact-head v0.0.18 review found that Android `JSONObject.optLong()` could
still coerce a numeric string or truncate a fractional `output.size` value to
the actual PDF length. v0.0.19 reads the raw token and accepts only a
nonnegative JSON Integer or Long. Strings, Doubles (including integral-valued
ones), negative values, and missing values fail closed before identity checks.
The hook-scope invariant now bans both `optInt()` and `optLong()` from manifest
validation.

Automated validation passes 85 generator tests on Windows and Linux, 76 focused
navigation/manifest assertions, 12 cross-language authority assertions, 8,752
exhaustive assertions, both invariant suites, hook-scope validation, and the
signed/verified v0.0.19 (`versionCode=19`) APK build (SHA-256
`03852fe6c37a7cd99f0735f0f504702ee87368293e082bf045d73796d811c507`).
Focused hardware validation of native metadata lookup and same-path replacement
remains pending.

## Review pass 43 exact geometry typing - AUTOMATED PASS

The exact-head v0.0.19 review found that Android `JSONObject.optDouble()` could
still coerce numeric strings in `output.spreadSize`, `output.gutter`, or a link
`rect`. v0.0.20 reads every geometry token raw and accepts only finite JSON
`Number` values. Strings, booleans, nulls, NaN, and either infinity fail closed
before layout/link authority recomputation. The hook-scope invariant now bans
`optDouble()` and `getDouble()` together with the integer coercion APIs.

Automated validation passes 85 generator tests on Windows and Linux, 85 focused
navigation/manifest assertions, 12 cross-language authority assertions, 8,752
exhaustive assertions, both invariant suites, hook-scope validation, and the
signed/verified v0.0.20 (`versionCode=20`) APK build (SHA-256
`9740d4593ed2b2fb6598b0349adce43d1aa7bba5f879ca76320323a6e6bc0085`).
Focused hardware validation of native metadata lookup and same-path replacement
remains pending.

## Review pass 44 unambiguous manifest and page boxes - AUTOMATED PASS

The exact-head v0.0.20 review found two remaining ambiguous-input boundaries.
Android's `JSONObject` silently keeps one value when an object repeats a name, so
v0.0.21 first scans the complete manifest with a bounded strict JSON parser and
rejects duplicate names at every nested object, including escape-equivalent
spellings. The generator now also requires each effective source CropBox to be
fully contained within its MediaBox in both the raw PDF operands and pypdf's
resolved rectangle view. Any protruding left, bottom, right, or top edge fails
closed before an output PDF or manifest can be published.

Local automated validation passes 86 generator tests on Windows (five expected
filesystem skips), 93 focused navigation/manifest assertions, 12 cross-language
authority assertions, 8,752 exhaustive assertions, both invariant suites, hook-
scope validation, and the signed/verified v0.0.21 (`versionCode=21`) APK build
(SHA-256
`60acd2fb4f10cebb6be57613a331c179eb3e30dfef0e3e64b9f4ca297d8f38ba`).
The exact-head CI gate independently runs the generator suite on Linux. Focused
hardware validation of native metadata lookup and same-path replacement remains
pending.

## Review pass 45 strict sidecar UTF-8 - AUTOMATED PASS

The exact-head v0.0.21 review found that Java's ordinary UTF-8 `String`
constructor replaces malformed byte sequences with U+FFFD before JSON parsing.
v0.0.22 now decodes the raw sidecar bytes with a `CharsetDecoder` whose malformed
and unmappable actions are both `REPORT`. Invalid bytes therefore produce a
stable cached rejection before the duplicate-key scanner or Android
`JSONObject` can accept a normalized representation. A legitimately encoded
U+FFFD remains valid and is preserved exactly.

Local automated validation passes 86 generator tests on Windows (five expected
filesystem skips), 99 focused navigation/manifest assertions including malformed
continuation, overlong, truncated, surrogate, and valid-replacement-character
UTF-8 cases, 12 cross-language authority assertions, 8,752 exhaustive assertions,
both invariant suites, hook-scope validation, and the signed/verified v0.0.22
(`versionCode=22`) APK build (SHA-256
`71cda2d144cf7c732fbb239f209bf8388bec24cd6e4b1bd8d4b48cd43c1ea01d`).
The exact-head CI gate independently runs the generator suite on Linux. Focused
hardware validation of native metadata lookup and same-path replacement remains
pending.

## Review pass 46 portrait link viewport and bounded cache - AUTOMATED PASS

The independent full-diff review of v0.0.22 found two process-lifetime edge
cases. A portrait internal link with an authenticated explicit `/XYZ` or `/FitR`
destination could have Supernote's native viewport overwritten by the module's
ordinary half-edge focus. v0.0.23 preserves that native destination view and
binds every delayed portrait-focus retry to the page-load generation, so an old
retry cannot move a newer link target. The process-wide manifest cache is now a
synchronized four-entry access-order LRU rather than an unbounded map.

Local automated validation passes 86 generator tests on Windows (five expected
filesystem skips), 112 focused navigation/manifest/cache assertions, 12
cross-language authority assertions, 8,752 exhaustive navigation assertions,
both invariant suites, hook-scope validation, and the signed/verified v0.0.23
(`versionCode=23`) APK build (SHA-256
`59457392533e6428e5c943eaa2f0c600afe67591041af6595c263e9bd917a9df`).
The exact-head CI gate independently runs the generator suite on Linux. Focused
hardware validation of same-path replacement and preserved portrait explicit
link viewports remains pending.

## Review pass 47 FitR containment and latest-only verification - AUTOMATED PASS

The second independent full-branch review found three remaining hardening
issues. Explicit `/FitR` destinations are now required to be positive rectangles
fully contained by the target source page's effective CropBox, preventing a
crafted viewport from exposing the neighboring page in a composed spread. The
manifest verifier now has a one-entry pending queue: a newer document invalidates
older work, queued stale jobs are removed, and active full-PDF hashing checks for
supersession between chunks. Hardware evidence now records the exact Nomad
firmware fingerprint and SupernoteDocument version rather than only the device
model and date.

Local automated validation passes 87 generator tests on Windows (five expected
filesystem skips), 112 focused navigation/manifest/cache assertions, 12
cross-language authority assertions, 8,752 exhaustive navigation assertions,
both invariant suites, hook-scope validation, and the signed/verified v0.0.23
(`versionCode=23`) APK build (SHA-256
`bd51d1397c7057fa0fd2957ea476cba43417b66a98f2e9b99edf1d56f4010c0c`).
The exact-head CI gate independently runs the generator suite on Linux. Focused
hardware validation of same-path replacement and preserved portrait explicit
link viewports remains pending.

## Review pass 48 destination and border edge semantics - AUTOMATED PASS

The next independent full-branch review identified two neighboring-page or
visual-semantics boundaries. Every non-null `/XYZ` left or top coordinate must
now lie within the target source page's effective CropBox before it is
transformed into a composed spread. An underlined link border (`/BS /S /U`) is
preserved only when the source-to-spread transform leaves the source bottom
edge as the output bottom edge; quarter-turn and half-turn page rotations fail
closed rather than drawing the underline on a different edge.

Local automated validation passes 89 generator tests on Windows (five expected
filesystem skips), 112 focused navigation/manifest/cache assertions, 12
cross-language authority assertions, 8,752 exhaustive navigation assertions,
both native invariant suites, hook-scope validation, and the signed/verified
v0.0.23 (`versionCode=23`) APK build (SHA-256
`6f03e4b4e96053d8d794cc165a135cd09bde4b5a0c5ed922d7375eb7ebfdeca9`).
The exact-head CI gate independently runs the generator suite on Linux. Focused
hardware validation of same-path replacement and preserved portrait explicit
link viewports remains pending.

## Review pass 49 bounded XYZ viewport and Original Back chain - AUTOMATED PASS

The following full-branch review found two remaining navigation boundaries.
An explicit `/XYZ` anchor could lie inside the target CropBox while the retained
portrait viewport still extended into the neighboring composed page. The
generator now requires an explicit horizontal anchor and positive zoom, derives
the portrait viewport width in spread coordinates, and publishes the link only
when the complete viewport remains inside the authenticated target half.
Retained/zero zoom and unknown horizontal anchors fail closed. Native direct
Original Back after multiple link jumps now validates the newest recorded
destination against the currently open page before restoring the oldest source
half; a mismatched in-process history mirror is cleared and cannot fall back to
ambiguous manifest inference.

Local automated validation passes 91 generator tests on Windows (five expected
filesystem skips), 116 focused navigation/manifest/cache assertions, 12
cross-language authority assertions, 8,752 exhaustive navigation assertions,
both native invariant suites, hook-scope validation, and the signed/verified
v0.0.23 (`versionCode=23`) APK build (SHA-256
`64ff19234647d324335a42b7e2e231bd2f62365c416499099226aff1d7ce8223`).
The exact-head CI gate independently runs the generator suite on Linux. Focused
hardware validation of same-path replacement and preserved portrait explicit
link viewports remains pending.

## Review pass 50 fitted viewport and document-switch cancellation - AUTOMATED PASS

The next independent full-branch review found two remaining fail-closed
boundaries. An explicit `/FitR` rectangle could lie inside one composed half
while PDF aspect fitting expanded the actual portrait viewport into the other
half. The generator now computes that fitted viewport from the authenticated
spread aspect and rejects any neighboring-half exposure. The background
manifest verifier now observes the active canonical document before cache and
sidecar-existence fast paths. Switching to a cached spread, an ordinary PDF, a
missing sidecar, or no document cancels old active and queued verification;
delayed callbacks from a stale native view model cannot reclaim ownership.

Local automated validation passes 92 generator tests on Windows (five expected
filesystem skips), 116 focused navigation/manifest/cache assertions, 12
cross-language authority assertions, 8,752 exhaustive navigation assertions,
both native invariant suites, hook-scope validation, and the signed/verified
v0.0.23 (`versionCode=23`) APK build (SHA-256
`76d37364a059c957cbe19b1ac38886cc1b77db97efc24941b223fdf40a177492`).
The exact-head CI gate independently runs the generator suite on Linux. Focused
hardware validation of same-path replacement and preserved portrait explicit
link viewports remains pending.

## Review pass 51 pending turns, recovery evidence, and Nomad aspect - AUTOMATED PASS

The next independent full-branch review found three accepted fail-closed
boundaries. A cold or replaced spread could receive a native LTR turn while its
manifest was still being verified; the lookup now returns an explicit pending
state and consumes turns until the verified RTL manifest is activated. Recovery
now restores an authenticated backup over a canonical target only when that
target is absent or still matches the transaction's staged digest. An unrelated
or concurrently replaced target remains untouched with the marker and backup
evidence preserved. Finally, both generator and companion require the output
geometry to retain the Nomad's 4:3 landscape aspect, while still allowing
proportionally scaled coordinate systems.

The review also suggested applying the explicit `/FitR` viewport guard to source
`/Fit`. That suggestion was not adopted: source `/Fit` carries no explicit
viewport, and this branch already authenticates `targetView=fit-source-page` so
the companion restores Supernote's native Fit-page view after traversal. The
dedicated v0.0.16 Nomad pass verified that behavior in portrait and landscape on
both target halves with no zoom, flicker, stale content, or wrong page. A new
deterministic regression preserves this intentional distinction; explicit
source `/FitR` remains subject to the fitted-viewport containment guard.

Local automated validation passes 95 generator tests on Windows (five expected
filesystem skips), 119 focused navigation/manifest/cache assertions, 12
cross-language authority assertions, 8,752 exhaustive navigation assertions,
both native invariant suites, hook-scope validation, and the signed/verified
v0.0.23 (`versionCode=23`) APK build (SHA-256
`d8a98b94cfd3ec4a4fcbc4e997aab8c199cb83058e3c91bfa054196d222e69fa`).
Focused hardware validation of same-path replacement and preserved portrait
explicit link viewports remains pending.

## Review pass 52 native mismatch, retained link view, and APK payload - AUTOMATED PASS

The next independent full-branch review found three additional fail-closed and
lifecycle boundaries. A fully verified replacement pair now continues consuming
page turns when Supernote still holds an older, authority-mismatched MuPDF
document at the same path; reopening the document is required before navigation
can activate. An authenticated explicit `/XYZ` or `/FitR` destination now retains
its native portrait viewport across repeated page-loaded, orientation, and native
screen-reload callbacks for the same page, while an actual page/half transition
clears that state. Finally, APK assembly checks the exit status of both JAR
operations and verifies that `classes.dex`, `assets/xposed_init`, and the LSPosed
scope entry are present before alignment and signing.

Local automated validation passes 95 generator tests on Windows (five expected
filesystem skips), 120 focused navigation/manifest/cache assertions, 12
cross-language authority assertions, 8,752 exhaustive navigation assertions,
both native invariant suites, hook-scope validation, and the signed/verified
v0.0.23 (`versionCode=23`) APK build (SHA-256
`c8c05613416966a3f6d1b9b2e65ee38c647ecb6e57c70b6799247850f2862341`).
Focused hardware validation of same-path replacement and preserved portrait
explicit link viewports remains pending.

## Review pass 53 retry authority, rejected manifests, and recovery paths - AUTOMATED PASS

The following whole-branch review found four further boundaries. Portrait
`screenChange` callbacks and already queued focus retries now recheck the
authenticated explicit-link viewport before changing the visible half. A
generated PDF whose sidecar verification was rejected continues consuming
native turns when its retained MuPDF document contains virtual-spread authority
metadata; an unavailable metadata probe also fails closed, while an ordinary
PDF with no such metadata remains native. Manifest activation now requires a
positive native page count that exactly matches the authenticated output. On
Windows, interrupted-publication recovery compares persisted paths using the
filesystem's case and separator semantics without accepting dot-segment aliases.

Local automated validation passes 96 generator tests on Windows (five expected
filesystem skips), 120 focused navigation/manifest/cache assertions, 12
cross-language authority assertions, 8,752 exhaustive navigation assertions,
both native invariant suites, hook-scope validation, and the signed/verified
v0.0.23 (`versionCode=23`) APK build (SHA-256
`792226ff3048ad4fb24244e50b8b5efb4c91113b65cde5aaa31f027a835f5115`).
Focused hardware validation remains pending.

## Review pass 54 deferred links and publication-state retention - AUTOMATED PASS

The next whole-branch review identified four remaining authority windows.
Generated PDFs whose sidecar is missing or whose native metadata cannot be
inspected now fail closed, while an ordinary native PDF is allowed through only
after its open MuPDF document explicitly proves that no virtual-spread authority
is present. Native link taps made during cold manifest verification are consumed,
queued once, and replayed only after the same document and source page acquire
verified authority; rejected, failed, stale, cross-page, and cross-document
requests are discarded. Forced replacement now requires explicit cover parity,
spread width, spread height, and gutter values, preventing implicit defaults from
resetting persisted layout. Recovery also removes deterministic `.retired`
artifacts left by a crash, including the case where the active path was already
removed. Review pass 58 supersedes that cleanup behavior: because a bare
`.retired` filename is not authenticated transaction evidence, current recovery
preserves and rejects it for manual inspection instead of deleting it.

Local automated validation passes 98 generator tests on Windows (five expected
filesystem skips), 124 focused navigation/manifest/cache assertions, 12
cross-language authority assertions, 8,752 exhaustive navigation assertions,
both native invariant suites, hook-scope validation, and the signed/verified
v0.0.23 (`versionCode=23`) APK build (SHA-256
`1dcfee90040039914b7ac7ff173f56536e262d8de81d3ee89eb465657d2abc38`).
Focused hardware validation remains pending.

## Review pass 55 navigation snapshot binding and POSIX recovery - AUTOMATED PASS

The next independent review found five related authority and crash-consistency
windows. Native Back and Original Back now return no destination while manifest
or native-snapshot authority is unresolved, and authenticated virtual-spread
links with missing, malformed, unmatched, or ambiguous runtime geometry are
consumed rather than navigating without a trusted half mapping. A link tapped
during verification is bound to the exact PDF and sidecar filesystem identities
being verified; same-path replacement or any verification snapshot change
discards the queued invocation before native replay.

Publication markers are now fully written and fsynced under a staged name on
POSIX as well as Windows before the final marker path becomes visible. Recovery
also recognizes the precise POSIX link-before-unlink crash state for an original
being moved to its backup, requiring the canonical and backup names to share one
inode and both to match the marker's authenticated old digest before rollback.

Local automated validation passes 100 generator tests on Windows (six expected
filesystem/platform skips), 125 focused navigation/manifest/cache assertions,
12 cross-language authority assertions, 8,752 exhaustive navigation assertions,
both native invariant suites, hook-scope validation, and the signed/verified
v0.0.23 (`versionCode=23`) APK build (SHA-256
`772b25ff8a163e148ae896f9bebb2990014d3986596d76417fa2d51a8c57ea5e`).
Focused hardware validation of this exact build remains pending.

## Review pass 56 native-link compatibility and atomic no-replace - AUTOMATED PASS

A focused follow-up review found two regressions in pass 55. The shared
`showLinkJumpView` callback now bypasses the companion when it is serving a
native annotation or digest menu rather than a link. Authenticated external URI
links also remain in Supernote's native handler; only internal page links require
an authenticated target-half match. A link queued during manifest verification
retains its exact external/internal routing classification as well as its exact
PDF/sidecar snapshot, and is discarded if either changes before replay.

Unguarded POSIX no-replace publication now uses the kernel's atomic hard-link
operation instead of a check followed by overwrite-capable `os.replace`. A
deterministic cross-platform emulation test proves that an incumbent destination
cannot be displaced even when a stale existence check claims it is absent.

Local automated validation passes 102 generator tests on Windows (seven expected
filesystem/platform or privilege skips), 130 focused navigation/manifest/cache
assertions, 12 cross-language authority assertions, 8,752 exhaustive navigation
assertions, both native invariant suites, hook-scope validation, and the
signed/verified v0.0.23 (`versionCode=23`) APK build (SHA-256
`098208ae1a7f875e2a3c2b0c39561af5f90dd2a48b50cb217bee2d414558ce4b`).
Focused hardware validation of this exact build remains pending.

## Review pass 57 capability epoch and reader-state lifecycle - AUTOMATED PASS

The required Ultra whole-branch review found five release-boundary defects before
push. Manifest schema v2 now makes newly generated pairs incompatible with old
companions that predate native-open snapshot binding. The companion clears every
manifest-bound page, half, pending-link, history, viewport, queued-link, and
native-snapshot value when a reused view model changes documents; its delayed-
callback generation is incremented rather than reset, closing the prior ABA
window. Deferred external links initialize the current verified spread
immediately after native replay, while internal links continue to wait for their
native page-load callback. The generator preserves the source PDF language-
version header and verifies it after staging rather than silently emitting
`%PDF-1.3`.

Deterministic regressions pin schema v2, source-header preservation, all four
queued-link initialization outcomes, complete document-state invalidation, and
monotonic generations. Local automated validation passes 103 generator tests on
Windows (seven expected platform/filesystem or privilege skips), 134 focused
navigation/manifest/cache assertions, 12 cross-language authority assertions,
8,752 exhaustive navigation assertions, both native invariant suites,
hook-scope validation, and the signed/verified v0.0.24 (`versionCode=24`) APK
build (SHA-256
`de8ec66a858573a17fcdf8b2f8edbf3fd22c029f9850033e2f9900b31f942a4d`).
Focused hardware validation of this exact build remains pending.

## Review pass 58 publication namespace and atomic hook activation - LOCAL PASS

The follow-up Ultra whole-branch review accepted four release-boundary defects.
The generator now publishes the sidecar with the exact output-derived filename
case even when Windows accepts a case-equivalent caller spelling. Publication
stages use deterministic, reserved names so a process death cannot create an
unbounded set of random orphan files. A stage without authenticated transaction
evidence is preserved and rejected; after a valid marker exists, recovery
removes a stage only when its SHA-256 matches that transaction. Pre-existing
`.retired` paths are likewise preserved and rejected rather than being deleted
based solely on their names.

The companion now treats its activity, view-model, page-bar, link-target, and
link-history hooks as one required capability set. Virtual-spread behavior is
enabled only after all five install successfully; a failure leaves any already
installed callback native pass-through for the process. Deterministic tests pin
the output-derived case spelling and physical Windows directory entry, every
reserved retirement path, orphaned and authenticated stage recovery, mismatch
preservation, and the process-wide readiness gate.

Local automated validation passes 109 generator tests on Windows (seven
expected platform/filesystem or privilege skips), 134 focused
navigation/manifest/cache assertions, 12 cross-language authority assertions,
8,752 exhaustive navigation assertions, both native invariant suites,
hook-scope validation, and the signed/verified v0.0.24 (`versionCode=24`) APK
build (SHA-256
`3e2e9df0435beef69b2d6b9b677bb864363d21010e487a91499d590cbf40e7d2`).
The updated full-branch local review and focused hardware validation remain
pending; PR #16 stays draft.

## Review pass 59 filesystem-aware publication separation - LOCAL PASS

The next Ultra whole-branch review found that a source and output whose names
differed only by case could pass Python's case-sensitive `Path`-set check on
Windows even though both names addressed the same filesystem entry. A forced
publication could consequently replace the source PDF and then discard its
backup. All three publication layers now share one filesystem-aware distinctness
guard. It compares host-normalized paths and existing-file identity, rejecting
case aliases and hard-link aliases before publication. The CLI also reports the
actual output-derived sidecar spelling rather than a case-equivalent caller
spelling.

Deterministic regressions exercise the dangerous case-only collision on the real
Windows filesystem, an existing hard-link alias, emulated host case semantics,
and CLI sidecar reporting. Both aliases leave the source bytes intact. A static
invariant pins the common guard at every repeated publication boundary and bans
the former case-sensitive `Path`-set checks.

Local automated validation passes 114 generator tests on Windows (seven
expected platform/filesystem or privilege skips), 134 focused
navigation/manifest/cache assertions, 12 cross-language authority assertions,
8,752 exhaustive navigation assertions, both native invariant suites,
hook-scope validation, and the signed/verified v0.0.24 (`versionCode=24`) APK
build (SHA-256
`65a62b821b45d95b48ba9cb1b9ac6e9c7971330c59c62336ecbdd5ca630804b2`).
A clean follow-up full-branch review and focused hardware validation remain
release gates; PR #16 stays draft.

## Review pass 60 publication and deferred-link race closure - LOCAL PASS

The next independent Ultra review identified six final concurrency boundaries.
Generator staging now keeps each exclusively created inode open through every
write and binds its identity before Windows must release the handle for an atomic
move. A replaced staging pathname is preserved, and cleanup no longer masks the
more precise boundary error already in flight. The exact authorized state of the
output and sidecar is captured before expensive generation, rechecked before the
transaction, and carried through publication. Both final moves and every backup
restore are kernel-level no-replace operations, so a file that appears late is
never overwritten by either normal publication or rollback.

The Android verifier now gives every task a unique monotonic owner rather than
using a reusable filesystem snapshot token as task identity, closing an A-to-B-
to-A cancellation race. A link deferred during cold verification is also bound
to that unique verifier generation, the exact native MuPDF document object, and
its three embedded authorities. Same-path replacement can therefore never replay
a stale native `SuperNoteLink` against a different open document.

Deterministic regressions cover a POSIX staging-name hard-link substitution, a
no-force target appearing during generation, a late final target, a late target
during backup restoration, verifier-generation ABA, and native-document mismatch
during deferred-link replay. Local automated validation passes 118 generator
tests on Windows (eight expected platform/filesystem or privilege skips), 135
focused navigation/manifest/cache assertions, 12 cross-language authority
assertions, 8,752 exhaustive navigation assertions, both native invariant suites,
hook-scope validation, and the signed/verified v0.0.24 (`versionCode=24`) APK
build (SHA-256
`4c0983bdd2df031f3481509e0f00015a3e1c9cfb284da4fceccee8b2944fdc4c`).
A fresh exact-head Ultra review and focused hardware validation remain release
gates; PR #16 stays draft.

## Review pass 61 recovery identity, captured layout state, and strict URI authority - LOCAL PASS

The fresh exact-head Ultra review found three remaining authority races. Recovery
now captures the verified filesystem identity of a newly published canonical
target and supplies that identity to guarded removal. A matching hash is no
longer sufficient to delete a pathname that may have been concurrently replaced.
Forced-regeneration layout policy now derives replacement state from the same
captured output/sidecar snapshots later authorized for publication, rather than
from earlier existence observations. Finally, Android's link-authority encoder
rejects unpaired UTF-16 surrogates before UTF-8 hashing, matching the generator's
strict Unicode contract instead of silently hashing replacement characters.

Deterministic regressions cover a recovery-time same-content pathname
replacement, a target that appears between the initial observation and captured
publication state, and malformed high-surrogate, low-surrogate, and record
strings in the Android authority encoder. Local automated validation passes 120
generator tests on Windows (eight expected platform/filesystem or privilege
skips), 135 focused navigation/manifest/cache assertions, 15 cross-language
authority assertions, 8,752 exhaustive navigation assertions, both native
invariant suites, hook-scope validation, and the signed/verified v0.0.24
(`versionCode=24`) APK build (SHA-256
`120819858eb7ab8a897e032b543aed63687b5b50ecff9b39b32288c6f4464b0b`).
A clean follow-up exact-head Ultra review and focused hardware validation remain
release gates; PR #16 stays draft.

## Review pass 62 authenticated cleanup, strict geometry, and verifier ownership - LOCAL PASS

The follow-up exact-head Ultra review identified six remaining fail-closed
boundaries. Publication cleanup now authenticates the complete marker, stage,
and backup set before deleting anything and carries each captured filesystem
identity through an unguessable retirement name. A stage, backup, marker, or
retirement entry replaced during cleanup is preserved rather than deleted.
POSIX source identity now includes ctime, closing an in-place same-size mutation
that restores mtime; only the ctime transition caused by the generator's own
hard-link/unlink namespace move is accepted.

The Android hook now verifies that a deferred link belongs to the exact verifier
generation before reading or clearing it, so a stale activation cannot consume
a newer queued link. Generator spread dimensions are bounded to PDF's
3-to-14,400-unit page range. Link `/QuadPoints` must contain four distinct
vertices forming one strict convex quadrilateral in PDF Z order; duplicate,
concave, and self-intersecting regions fail closed before publication.

Deterministic regressions cover replaced stages, backups, markers, and retirement
entries; unauthorized backup state; POSIX ctime mutation; stale verifier
generation; page-size limits; and malformed quadrilaterals. Local automated
validation passes 127 generator tests on Windows (eight expected
platform/filesystem or privilege skips), 138 focused navigation/manifest/cache
assertions, 15 cross-language authority assertions, 8,752 exhaustive navigation
assertions, both native invariant suites, hook-scope validation, and the
signed/verified v0.0.24 (`versionCode=24`) APK build (SHA-256
`3c67cab40653367cf83b4ef2ece8c21b01ce0247d80d40e796c558a518e876c2`).
A fresh clean exact-head Ultra review and focused hardware validation remain
release gates; PR #16 stays draft.

## Review pass 63 atomic publication and cross-layer geometry - LOCAL PASS

The exact-head Ultra review found six additional release-boundary defects. POSIX
publication now uses `renameat2(RENAME_NOREPLACE)` rather than a hard-link plus
path-only unlink, so a non-cooperating writer cannot have its replacement source
entry deleted. The post-rename identity is retained for every subsequent check,
and recovery accepts only the authenticated ctime transition on the surviving
link from a legacy link-before-unlink crash state.

Publication-marker bytes are now read, hashed, and parsed through one
descriptor-bound snapshot. Committed recovery captures both canonical
identities and revalidates the complete pair immediately before every retirement
of stage, backup, or marker evidence. A same-content pathname replacement thus
fails closed while retaining the prior backups and transaction marker. The
Android companion independently enforces the generator's exact 3-to-14,400-unit
PDF page-dimension limits. The POSIX parent-exchange regression also now asserts
the intended post-syscall fail-closed result while proving the descriptor-bound
mutation remains confined to the originally locked directory.

Deterministic regressions cover descriptor-swapped marker parsing, a recreated
source after atomic rename, committed-pair replacement before cleanup, the
legacy hard-link crash state, and runtime page-size boundaries. Local validation
passes 130 generator tests on Windows (10 expected platform/filesystem or
privilege skips) and the same 130 on Linux (two Windows-specific skips), 141
focused navigation/manifest/cache assertions, 15 cross-language authority
assertions, 8,752 exhaustive navigation assertions, both native invariant
suites, hook-scope validation, and the signed/verified v0.0.24
(`versionCode=24`) APK build (SHA-256
`febb7b00de9ad41def5c83c41653d1473d5b1f51b44b2a64ea205516694e20a3`).
A fresh clean exact-head Ultra review and focused hardware validation remain
release gates; PR #16 stays draft.

## Review pass 64 source restoration and stale-action cancellation - SUPERSEDED

The next exact-head Ultra review found three remaining cross-callback races.
After a POSIX no-replace move, publication now verifies the moved inode and, if
a non-cooperating writer substituted the checked source immediately before the
syscall, atomically restores that foreign entry to its original source name
before failing closed. It can no longer leave an unauthenticated replacement
under a canonical output, backup, marker, or retirement name.

The following exact-head review showed that the restoration step could not
distinguish that source-side race from a destination replacement after the
move. Review pass 65 therefore supersedes only this restoration mechanism; the
stale/superseded lookup protections below remain current.

Android manifest lookups from an obsolete native view model, or whose verifier
ownership was superseded between observation and scheduling, are explicitly
blocked rather than falling through to native LTR navigation. A fresh manual
turn also clears any link invocation queued by an older cold-verification tap,
so the delayed activation callback cannot replay that link over newer user
navigation.

Deterministic regressions cover the source substitution immediately before
`RENAME_NOREPLACE`, enforce fail-closed stale/superseded lookup returns, and pin
queued-link cancellation ahead of manual turn routing. Local validation passes
131 generator tests on Windows (11 expected platform/filesystem or privilege
skips) and the same 131 on Linux (two Windows-specific skips), 141 focused
navigation/manifest/cache assertions, 15 cross-language authority assertions,
8,752 exhaustive navigation assertions, both native invariant suites,
hook-scope validation, and the signed/verified v0.0.24 (`versionCode=24`) APK
build (SHA-256
`77c5e3bf2b22d25e5277182e8d4c0c4e7f2cc4d9f89e2e7a9b083beb2c4739b8`).
A fresh clean exact-head Ultra review and focused hardware validation remain
release gates; PR #16 stays draft.

## Review pass 65 ambiguous-target preservation and action supersession - LOCAL PASS

The next exact-head Ultra review found that reversing a mismatched POSIX move
could relocate a non-cooperating writer's newly created destination. Because a
post-move mismatch cannot distinguish a source replacement before the move from
a destination replacement afterward, publication now preserves the ambiguous
destination in place, leaves any existing transaction evidence intact, and
fails closed. It never performs a destructive reverse move based on that
ambiguity.

The same review found two remaining queued-link ordering gaps. Every nonzero
manual turn now clears any older cold-verification link before manifest lookup,
including turns that must then remain blocked. A newly verified internal or
external link also clears an older queued invocation before capture or native
passthrough. A delayed verifier therefore cannot replay an older tap over either
newer form of user intent.

Deterministic POSIX regressions cover both a source substitution immediately
before `RENAME_NOREPLACE` and a destination replacement immediately afterward;
both preserve the ambiguous destination and fail closed. Structural Android
regressions pin queued-link cancellation before every pending/blocked turn
return and before both verified-link branches. Local validation passes 132
generator tests on Windows (12 expected platform/filesystem or privilege skips)
and the same 132 on Linux (two Windows-specific skips), 141 focused
navigation/manifest/cache assertions, 15 cross-language authority assertions,
8,752 exhaustive navigation assertions, both native invariant suites,
hook-scope validation, syntax checks, and the signed/verified v0.0.24
(`versionCode=24`) APK build (SHA-256
`1702b0054afe2a7cf918f76be4fb77513e8ab0178f38d3012274d03ef0474971`).
A fresh clean exact-head Ultra review and focused hardware validation remain
release gates; PR #16 stays draft.

## Review pass 66 exact link semantics and blocked-action supersession - LOCAL PASS

The next exact-head Ultra review found four remaining link-authority gaps. URI
actions now require an absolute URI; relative references depend on a catalog
base URI that the generated representation does not carry, so copying them
unchanged could resolve against a different output directory. A link carrying
the annotation `/NoRotate` flag on a rotated source page also fails closed. The
generator bakes source rotation into an unrotated spread, where preserving that
flag would change the annotation's display semantics.

On Android, an uninspectable current link and Back or Original Back while
manifest authority is blocked now each clear any invocation left queued by an
older cold-verification callback before returning. A delayed verifier therefore
cannot replay stale navigation over either newer user action.

Deterministic regressions cover relative URI rejection, rotated-page
`/NoRotate` rejection, and the ordering of both queued-link cancellation paths.
Local validation passes 134 generator tests on Windows (12 expected
platform/filesystem or privilege skips) and the same 134 on Linux (two
Windows-specific skips), 141 focused navigation/manifest/cache assertions, 15
cross-language authority assertions, 8,752 exhaustive navigation assertions,
both native invariant suites, hook-scope validation, syntax checks, and the
signed/verified v0.0.24 (`versionCode=24`) APK build (SHA-256
`7cd1087c6ad44b6bd9dd359303191d0621a9810233a61e04ab3d7236cc05b1fa`).
A fresh clean exact-head Ultra review and focused hardware validation remain
release gates; PR #16 stays draft.

## Review pass 67 identity-bound retirement and stable rejection - LOCAL PASS

The full-branch Ultra review found three remaining release-boundary defects.
Publication cleanup no longer performs a pathname-only unlink after moving an
authenticated stage, backup, or marker to its unguessable retirement name.
Instead it opens and revalidates the exact retired inode, empties that inode
through its descriptor, fsyncs it, and retains an inert zero-length tombstone.
A non-cooperating writer's late pathname replacement is therefore preserved.
An interrupted POSIX hard-link backup is retained without truncation while it
still aliases a live canonical inode, so cleanup cannot corrupt the restored
PDF through a shared inode; a later run treats that nonempty alias as
fail-closed recovery evidence.

Review pass 69 supersedes this descriptor-truncation implementation after a
later review proved that a new hard-link alias could still be created between
the link-count check and the mutation.

The generator now rejects a link carrying `/NoZoom` whenever the source page is
scaled into its virtual half; copying transformed annotation geometry while
retaining that flag would change its visible semantics. On Android, an
unchanged sidecar outside the 8 MiB ceiling is stored as a stable negative cache
entry. An ordinary PDF with such an unrelated sidecar returns to native behavior
after that deterministic rejection, while an authoritative generated PDF stays
blocked without repeatedly scheduling the same verifier.

Deterministic regressions cover pre-open and POSIX post-open retirement
replacement, inert retirement tombstones, legacy hard-link recovery, scaled
`/NoZoom` rejection, and ordering of the oversized-sidecar negative-cache path.
Local validation passes 138 generator tests on Windows (13 expected
platform/filesystem or privilege skips) and the same 138 on Linux (two
Windows-specific skips), 141 focused navigation/manifest/cache assertions, 15
cross-language authority assertions, 8,752 exhaustive navigation assertions,
both native invariant suites, hook-scope validation, syntax checks, and the
signed/verified v0.0.24 (`versionCode=24`) APK build (SHA-256
`fea075f10b10701d73c8b7bf5c3998bb243fa31b1b89f27f47c745bc24c347c4`).
A fresh clean exact-head Ultra review and focused hardware validation remain
release gates; PR #16 stays draft.

## Review pass 68 exclusive lock initialization and deterministic rejection - LOCAL PASS

The next full-branch Ultra review found four remaining fail-closed gaps. A
publication-lock pathname is now initialized only when the generator created an
unaliased inode with exclusive-create. A pre-existing empty lock and a lock that
hard-links another file are rejected without changing either inode. The
generator's spread width, height, and gutter boundary also rejects Python
Booleans and every non-finite or nonnumeric value before staging, so it cannot
publish a JSON Boolean that Android correctly refuses as geometry.

On Android, stable JSON/canonical-string parse failures now become bounded
negative cache entries only after exact PDF/sidecar descriptor, pathname, and
digest authority has been rechecked. A malformed unchanged sidecar therefore
does not repeatedly trigger a full-PDF hash, and a replaced snapshot cannot
inherit the rejection. A verified virtual-spread turn is also consumed while
the activity is temporarily unbound or the orientation is unavailable, rather
than entering Supernote's native LTR offset path with stale lifecycle state.

Deterministic regressions cover Boolean geometry, an empty hard-linked lock,
an existing empty lock, stable malformed-manifest negative caching, activity-
null turn blocking, and unknown-orientation turn blocking. Local validation
passes 141 generator tests on Windows (13 expected platform/filesystem or
privilege skips) and the same 141 on Linux (two Windows-specific skips), 141
focused navigation/manifest/cache assertions, 15 cross-language authority
assertions, 8,752 exhaustive navigation assertions, both native invariant
suites, hook-scope validation, syntax checks, and the signed/verified v0.0.24
(`versionCode=24`) APK build (SHA-256
`e189fc6b8a489e1fd98988fd00b5137233e56dab206216a508e00bd88796c4f1`).
A fresh clean exact-head Ultra review and focused hardware validation remain
release gates; PR #16 stays draft.

## Review pass 69 immutable retirement and cold Back supersession - LOCAL PASS

The fresh exact-head Ultra review found two remaining races. Publication
cleanup could observe one link to an authenticated retired inode and then
truncate it after a non-cooperating writer created another hard-link alias. The
cleanup path now never truncates or unlinks authenticated retirement bytes. It
moves the exact inode without replacement from its unguessable `.retired...`
name into an inert unguessable `.retained...` namespace, preserving every late
alias byte-for-byte and failing closed on either source or destination
substitution. Retained bytes are deliberately kept until the containing
versioned cache directory can be safely garbage-collected.

The same review found a narrow cold-verification interval in which an accepted
manifest had entered the verifier cache but had not yet activated on the main
thread. Back or Original Back during that interval could miss the manifest-null
queue-clear branch and allow an older queued link to replay later. Every
concrete history-return action now clears the older queued link immediately
after resolving the view model and before any manifest lookup.

Deterministic regressions create a hard-link alias after the first retirement
move and prove both names retain the original bytes, replace the retired path
before the retention move and prove the unrelated replacement survives, pin
the inert retention namespace, and require history queue cancellation before
manifest lookup. Local validation passes 141 generator tests on Windows (12
expected platform/filesystem or privilege skips) and the same 141 on Linux
(two Windows-specific skips), 141 focused navigation/manifest/cache assertions,
15 cross-language authority assertions, 8,752 exhaustive navigation
assertions, both native invariant suites, hook-scope validation, syntax checks,
and the signed/verified v0.0.24 (`versionCode=24`) APK build (SHA-256
`c0eeb6b83f7b7fef7b7366a0eb46bb35205fa50c0d672f2c6f40bf6cf59536b5`).
A fresh clean exact-head Ultra review and focused hardware validation remain
release gates; PR #16 stays draft.

## Review pass 70 settled-pair and deferred-link generations - LOCAL PASS

The next exact-head Ultra review found two remaining cross-layer races. Recovery
could restore and authenticate the PDF, then restore the sidecar, yet retire all
transaction evidence without rechecking a non-cooperating writer's intervening
replacement of the first path. Every committed, rolled-back, and discarded
cleanup now carries the exact settled PDF/sidecar existence, identity, and hash
state and revalidates the complete pair before each retirement. A changed path
therefore remains in place and the marker or other remaining evidence is
preserved for fail-closed recovery.

A native page-load callback that arrived while cold manifest verification was
pending also returned before advancing the token used by a queued link. Moving
away from and back to the original page could consequently replay the older tap.
Every native page-load callback now advances a monotonic generation before
manifest lookup; a queued link captures that generation and must match it at
replay.

Deterministic regressions replace the settled output after both rollback and
legacy-discard state capture and prove cleanup preserves the marker, and reject
a queued link after any intervening page load even when the final page number is
unchanged. Local validation passes 143 generator tests on Windows (12 expected
platform/filesystem or privilege skips) and the same 143 on Linux (two
Windows-specific skips), 142 focused navigation/manifest/cache assertions, 15
cross-language authority assertions, 8,752 exhaustive navigation assertions,
both native invariant suites, hook-scope validation, and the signed/verified
v0.0.24 (`versionCode=24`) APK build (SHA-256
`7d3bd74eea3d74176777e4db6a29cb41f8f84d6dd35ee1ae0cd3cb9a3dd9ee6d`).
A fresh clean exact-head Ultra review and focused hardware validation remain
release gates; PR #16 stays draft.

## Review pass 71 source commit and stable APK identity - LOCAL PASS

The fresh exact-head Ultra review found two release-path defects. The generator
previously rehashed the canonical source immediately before calling the pair
publisher, leaving publication itself free to commit an older snapshot after a
concurrent source replacement. Source validation now belongs to the publication
transaction: it runs before transaction evidence is created and again after the
new canonical PDF and sidecar are authenticated but before rollback evidence is
retired. A failure at that commit boundary disables committed-pair recovery, so
the previous pair is restored (or a first-published pair is removed) and the
changed source is preserved.

GitHub-hosted runners also generated a new Android debug certificate for every
run while uploading each APK. CI now restores a stable keystore from the
encrypted `VIRTUAL_SPREAD_APK_KEYSTORE_BASE64` repository secret. If that secret
is unavailable, an ephemeral signer is still sufficient for build verification,
but the non-upgradeable APK is deliberately not uploaded. Deterministic invariant
checks pin that upload gate and the build's selected-keystore argument.

The source-race regression atomically replaces the source immediately after the
new output reaches its canonical path and proves publication raises, the changed
source survives, and the complete earlier PDF/sidecar pair is restored without a
marker or backup remnant. Local validation passes 144 generator tests on Windows
(12 expected platform/filesystem or privilege skips) and the same 144 on Linux
(two Windows-specific skips), 142 focused navigation/manifest/cache assertions,
15 cross-language authority assertions, 8,752 exhaustive navigation assertions,
both native invariant suites, hook-scope validation, workflow YAML parsing, and
the signed/verified v0.0.24 (`versionCode=24`) APK build. The APK uses the existing
upgrade-compatible certificate and has SHA-256
`0922b0bdd53732c6c07b26576c4795d01cdc0ffe16ff95c67a41c3fa23edf7f2`.
A fresh exact-head Ultra review and focused hardware validation remain release
gates; PR #16 stays draft.

## Review pass 72 protected signer and crash-safe source commit - LOCAL PASS

The next exact-head Ultra review found two release blockers in pass 71. The
stable Android signer is no longer referenced by any pull-request-controlled
job. Pull requests build and verify with a two-day ephemeral certificate. Only
a successful trusted `main` push enters the `virtual-spread-release` GitHub
environment and publishes an upgrade-compatible APK. That environment accepts
deployments only from `main`; it now contains the sole encrypted signer secret,
and the repository-wide duplicate was removed.

A matching newly published PDF and sidecar are also no longer sufficient for
crash recovery to infer commit. Source-validated publication starts
rollback-only. After both canonical files are authenticated, the generator
rehashes the original source and no-replace publishes a fsynced source-commit
record bound to the publication-marker hash, both new pair hashes, and the exact
source path, identity, timestamps, size, and SHA-256. Recovery commits only when
that record is structurally exact and the persisted source snapshot still
matches; a crash before the record or a changed source restores the previous
pair. Committed cleanup keeps the source-commit record until after marker
retirement, and an orphaned final record can retire itself only after
reauthenticating both canonical files.

Deterministic regressions cover a complete pair without commit evidence, an
unchanged validated source, source replacement after durable commit evidence,
marker-binding mutation, interrupted committed cleanup, mismatched orphaned
pair bytes, all deterministic source-commit staging/reserved paths, and exact
cleanup identities. Local validation passes 150 generator tests on Windows (12
expected platform/filesystem or privilege skips) and the same 150 on Linux (two
Windows-specific skips), 142 focused navigation assertions, 15 cross-language
authority assertions, 8,752 exhaustive navigation assertions, both native
invariant suites, hook-scope validation, workflow YAML parsing, and the
signed/verified v0.0.24 (`versionCode=24`) APK build. The APK retains the
upgrade-compatible signer and has SHA-256
`1cef6b0bdb88ee57901e6d37b87920a49118e727af2977acbba6ffa24a374c25`.
A fresh clean exact-head Ultra review and focused hardware validation remain
release gates; PR #16 stays draft.

## Review pass 73 exact-head authority closure - LOCAL PASS

The final integrated Ultra review closed the remaining authority and release
races. Ordinary PDFs now bypass Virtual Spread immediately when native MuPDF
definitively reports no embedded representation metadata. Manifest verification
uses bounded descriptor-authoritative background work, a short freshness lease,
and demand-driven retry without a permanent transient-failure cache or an
autonomous polling loop. A successful cached refresh schedules further work only
for an authenticated Virtual Spread manifest.

Back and Original Back now bind one exact preflight manifest/view-model snapshot
to the full history-return action. All concrete `BackLinkUtils` history methods
and both listeners share one fair lock, so no competing native history operation
can consume or replace the trail between preflight, the destructive getter, and
the resulting page load or external intent. Saving trails is accepted only after
the exact `saveMarkData` callback acknowledges completion.

Generator publication hashes the exact regular descriptor snapshot and rejects
growth, nonregular files, aliases, and pathname substitution without waiting for
EOF. The trusted release path is split into dependency-bearing tests, a fresh
clean assembly job with no signing secret, and a protected sign-only job with no
checkout or project scripts. The protected job verifies the assembly digest,
pins the expected certificate, deletes the decoded key, and publishes only the
stable signed APK. An unsafe `-SkipTests` invocation is rejected unless it is the
explicit aligned-only clean-assembly mode.

Deterministic regressions cover ordinary-PDF bypass, transient and stable
manifest failures, stale async verification, demand-only retry, exact Back
snapshot and lock authority, callback-acknowledged saves, descriptor growth and
FIFO/nonblocking publication, and the three-stage signing boundary. Exact-head
validation passes 154 generator tests on Windows (14 expected platform,
filesystem, or privilege skips) and 154 on Linux (two Windows-specific skips),
160 focused navigation/manifest/cache assertions, 15 cross-language authority
assertions, 8,752 exhaustive navigation assertions, both native invariant
suites, hook-scope validation, workflow checks, and clean aligned assembly. The
final release-equivalent v0.0.24 (`versionCode=24`) APK verifies with the pinned
upgrade-compatible certificate and has SHA-256
`119b7fec18ee1939e836eec66a10905283887478916f36f4dfbd79434985e97f`.
The clean exact-head Ultra review reports no actionable findings. Focused
hardware validation remains the release gate; PR #16 stays draft.

## v0.0.24-r1 focused Nomad gate - SUPERSEDED HARDWARE PASS

The complete v0.0.24 gate passed on the Nomad on 2026-08-26 with isolated
schema-v2 fixtures. Cold activation, cover and non-cover RTL parity, same-path
replacement fail-closed behavior, replacement reopen, explicit `/XYZ` viewport
preservation across orientation refresh, native link-history restoration, a
rejected missing-sidecar turn, native ink persistence, and ordinary sidecar-free
PDF pass-through all behaved as required.

The final pass also exercised the cold-verification link queue. An internal
link under a newly scheduled verifier owner logged exactly one queue and one
replay, then opened page 7 only after authenticated activation. An earlier
retry-backoff invocation exposed a firmware crash because the hooked
`showLinkJumpView(...)` primitive-boolean result had been replaced with null.
The r1 module returned `Boolean.FALSE` on every blocked link path; the exact
race then produced no fatal or `Boolean.booleanValue()` log and the document
reader remained usable. Subsequent exact-firmware review proved that false lets
the single-tap listener fall through into its page-turn branch. r1 is therefore
superseded despite that focused race appearing correct.

MuPDF's absent metadata values were also observed as empty strings on hardware.
The native authority classifier now treats null and trimmed-empty strings as
absent, keeps nonblank and unexpected typed values fail-closed, and is pinned by
focused tests and the hook-scope guard. On the exact rebuilt APK, the ordinary
fixture advanced from `2 / 7` to `3 / 7` with zero blocked-navigation lines,
while the generated missing-sidecar fixture stayed at `1 / 4` and logged the
expected blocked turn.

The signed v0.0.24-r1 (`versionCode=25`) APK SHA-256 is
`4454237d921a090174c2b0e7c60726e2f73fd8164539557614fa18fe29bd57c4`;
its signer certificate SHA-256 is
`a5a8551131de84d41660a3cf22d224f320f7a2f05a380282f76f6fe731807c67`.
Final local validation passes 154 generator tests (14 expected Windows skips),
165 focused navigation assertions, 15 cross-language authority assertions,
8,752 exhaustive navigation assertions, both native invariant suites,
hook-scope validation, and the signed APK build. PR #16 remains draft until
fresh exact-head CI and review complete.

## v0.0.24-r2 mixed-menu authority and blocked-tap consumption - LOCAL PASS / HARDWARE PASS

Exact-firmware review found that `showLinkJumpView(...)` returns true whenever
native firmware handles a tap; false means unhandled and falls through to page
turning. Every blocked pure-link path now returns `Boolean.TRUE`, preventing both
null unboxing and page-turn leakage.

The review also established that a non-null link is not always immediate
navigation. When a link overlaps a digest or annotation, firmware first opens a
combined native menu. r2 leaves that menu and all non-Link actions native, then
authenticates only the later `jumpLink(...)` callback if Link is actually chosen.
The short-lived candidate and any cold direct-jump replay are bound to the exact
document, native MuPDF object and embedded authorities, source page, generation,
arguments, and age. Annotation/digest-only activity cancels an older queued link.

The integrated exact-head review also hardened every publish/activation and
freshness-invalidation interleaving. Posted activation is bound to the exact
verification owner and native MuPDF object; passive UI binding preserves only
same-verification deferred intent; real native page loads invalidate deferred
intent while explicit synthetic activation may preserve an open mixed menu; and
pre-removal freshness tokens cannot erase a newer turn, link, history action,
queue, or menu candidate.

The final review batch also makes Back/Original Back synchronously supersede an
open mixed-link menu and binds every retained mixed-menu candidate to its exact
verifier generation. A candidate from an older or unbound verification cannot
be rebound or authenticated by a newer manifest.

Deterministic checks pin pure-versus-mixed classification, TRUE tap consumption,
annotation-only supersession, exact direct-jump arguments, candidate invalidation,
dual replay dispatch, and the concurrency state machine. Local validation passes
199 focused navigation
assertions, 15 authority assertions, 8,752 exhaustive assertions, hook-scope
validation, both native invariant suites, and signed compilation as
v0.0.24-r2 (`versionCode=26`). The upgrade-compatible APK SHA-256 is
`be2427543b8e41d6c4e5e42131fcfda92cbe8e82eeafa32582aa55083558fd38`.

The focused hardware matrix passed on 2026-08-27 on a Supernote Nomad with
firmware fingerprint
`Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys`
and SupernoteDocument `1.02.446`. The installed artifact was the exact
v0.0.24-r2 (`versionCode=26`) APK above, built from reviewed code head
`76ea0b71b518fb3c7c969fdd9bd9c1eb08dd53e6`.

The device matrix observed all r2-specific boundaries:

- a pure internal link without a sidecar stayed on `1 / 4`, was consumed, and
  logged one `link_jump_queued`, one pending-verification block, and one
  verification-failure discard without a page load or native page-turn
  fallthrough;
- the firmware's mixed `DocumentLinkJumpView2` menu kept Underline native,
  while a later explicit Open Link action logged `mixed_link_menu_observed` and
  reached source page 7 exactly once;
- replacing an authenticated sidecar with an identical copy forced cold
  verification, then produced exactly one `link_jump_queued source=3 target=1`,
  one `link_jump_replayed`, and one target page load without reopening the
  menu;
- a markerless ordinary PDF created no manifest-verification, activation, or
  blocked-turn state; and
- both missing-sidecar fixtures rejected with `ENOENT`.

The Live fixture's sidecar and `.mark` were restored to their pre-test hashes,
and the disposable blocked-link PDF was removed from the Nomad. The r2 hardware
gate is complete; PR readiness is governed only by the repository's final
exact-head CI and review gates.

## v0.0.25 authenticated mapping/view contract - HARDWARE PASS

The focused v0.0.25 hardware matrix passed on 2026-08-27 on a Supernote
Nomad with firmware fingerprint
`Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys`
and SupernoteDocument `1.02.446`. The exact installed v0.0.25
(`versionCode=27`) APK had SHA-256
`eeab846aa6a937d14fad0702b079ecb4d24a326d40ab64613b2f730196407b76`;
its upgrade-compatible signer certificate SHA-256 was
`a5a8551131de84d41660a3cf22d224f320f7a2f05a380282f76f6fe731807c67`.
The behavior-changing code head was
`5ff122ebdd9824d28ce1b774c9568a6678d3b9fc`.

The device opened and authenticated a freshly generated schema-v3 pair directly
from `/storage/emulated/0/.inkbridge/virtual-spread/v1/`. It logged
`manifest_accepted`, `native_snapshot_accepted`, and
`manifest_activated`; showed `blank | page 1`; advanced in RTL order to
`page 3 | page 2`; and returned to `blank | page 1` on the reverse swipe.
The same generated PDF without its sidecar failed closed without activation, and
an altered sidecar mapping authority was rejected with
`reason=mapping_authority`. The original sidecar-free source PDF remained on
the ordinary native-reader path with no accepted or activated manifest event.
Supernote's native reader could open the deterministic pair by direct path,
while its normal Documents library displayed neither the `.inkbridge`
directory nor the cached document.

This hardware gate validates only RTL Reader's narrow authenticated detection,
RTL navigation, and native viewport/focus boundary. It adds no annotation
interception or conversion; InkBridge owns canonical annotation conversion using
the authenticated schema-v3 mapping authority. Full hardware steps and hashes
remain recorded in `virtual_spread/HARDWARE_VALIDATION.md`.

## v0.0.26 authoritative native viewport - HARDWARE PASS

The focused v0.0.26 publication and invalidation matrix passed on 2026-08-28 on
a Supernote Nomad (`SN078C10015092`) with firmware fingerprint
`Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys`,
display build `Chauvet.E103.2606161001.2393_release`, and SupernoteDocument
`1.02.446`. The installed upgrade-compatible v0.0.26 (`versionCode=28`) APK had
SHA-256
`95e39ce2083b3c9b40f5cbff17ce124ca79163ef01959c3a7c76c8235699a060`;
its signer certificate SHA-256 remained
`a5a8551131de84d41660a3cf22d224f320f7a2f05a380282f76f6fe731807c67`.

The normative schema-v3 page-143 fixture was installed at its deterministic
hidden cache path under
`/storage/emulated/0/.inkbridge/virtual-spread/v1/inkbridge-doc-v1-c9271098e6d98f7fff378c4d630dc9c179cf45cb5283f3559eee910e3afafeb4/inkbridge-view-v1-7cb2c2fda17d5510d33b0a97e702cbc66d5124735be45f810aef6053c1775f30/`.
The device-side PDF and sidecar SHA-256 values were respectively
`0c895249809a36f382312ae42547ec2f9755e0b4095ce2b8e8a5f6145be3a32f`
and
`37cda3d96db8b2f8f311df60ccfbbd397bbb446b9e4a7451dcbbffc283aff9df`;
the authenticated mapping-authority digest was
`646b905c12266774882e0c4d7ebbbca77b2f386f432979ebcbfcda1d9ace268a`.

For zero-based virtual page 1, `PluginFileAPI.getPageSize` and the native
reader reported an `1872 x 1404` canvas. The module published this exact
descriptor:

```json
{"schemaVersion":1,"authority":"rtl-reader-native-viewport-v1","documentId":"inkbridge-doc-v1-c9271098e6d98f7fff378c4d630dc9c179cf45cb5283f3559eee910e3afafeb4","viewId":"inkbridge-view-v1-7cb2c2fda17d5510d33b0a97e702cbc66d5124735be45f810aef6053c1775f30","virtualPageIndex":1,"nativePageSize":[1872,1404],"spreadToNative":[2.164006674264231,0.0,0.0,-2.1636211394924048,0.999465811965812,1402.0264983910781]}
```

The canonical provider payload (no terminal newline) had SHA-256
`a590afc7a95e92fbf7b9ac03fd949bcd6b474bcba70e06e4ec63936de937d033`.
The checked-in fixture file includes one terminal LF and therefore has SHA-256
`27145685a793ce2716a5da6c26db4a1fa64bac0e1ad6bc1329e0c502326a48e4`.
The nonzero translation and slightly different x/y scale are measured native
fit authority, not an aspect-ratio reconstruction.

The first cold-reopen attempt found one fail-closed lifecycle defect: an
unbound native completion could establish the page before asynchronous manifest
activation, leaving no descriptor to publish. The corrected module synthesizes
an exact-current completion only when manifest activation owns initialization,
the page is known, viewport authority is absent, and no real page load or
pending navigation owns the state. Focused tests pin both recovery and the
opposing active-load boundary.

The exact-head review then identified a separate same-page overlap risk: an
older `onPageLoaded` callback could previously begin a fresh generation at
completion time and adopt a newer load's authority. The final module instead
binds cached synchronous loads and the exact firmware's asynchronous
`DocumentViewModel$6` page workers to a per-page request serial when the load
is initiated. Adjacent prefetch workers receive no provider generation; only
the exact worker whose page and request serial still match the live reader may
begin or complete publication. Older same-page workers, replaced native MuPDF
instances, and unmatched callbacks fail closed. The task constructor and typed
completion hook are exact-firmware locked and included in the narrow-hook scope
guard.

The final review also identified two lifecycle ownership gaps. First,
same-document manifest binding could clear an in-flight native-load marker and
temporarily permit a synthetic completion from older page state. Verification
binding now preserves that marker, and first-page activation checks it even
before `lastPage` has been established; only a real document replacement clears
it.
Second, teardown from a replaced `DocumentActivity` could clear the viewport
owned by the replacement activity. Destruction now clears provider and reader
state only when the destroyed instance is still the active owner. Pure
lifecycle regressions pin both rules, and the hardware gate exercised rapid
ordinary/Virtual-Spread replacement before confirming that the final page-1
record remained authoritative.

The final exact-head review also found that missing native `PageInfo` render
offset accessors were previously converted to zero by a general-purpose
fallback helper. Viewport publication now reads both offsets directly and
requires finite numeric values; a missing accessor, non-number, NaN, or
infinity fails closed. Focused tests and the static scope guard prevent the
zero-offset fallback from returning.

The following complete-head review found two further asynchronous lifecycle
edges. Current-page fit/orientation workers constructed outside the hooked
`loadPage` path now begin and clear the provider generation immediately; only
non-current adjacent prefetch workers remain generation-less. An unmatched or
unbound completion now returns before clearing `nativeViewportLoadPending` or
touching provider authority, so an older callback cannot invalidate the newer
load it failed to match. Pure worker-page tests and structural ordering guards
pin both rules.

The last exact-head review found the opposing first-open race: the exact
current load could finish before asynchronous manifest verification, yet its
generation-less completion left `nativeViewportLoadPending` set. Verified
activation would then refuse to recover the already-loaded page indefinitely.
The exact task/request binding now records only that its load completed when
authority is still unavailable; it does not publish or adopt a generation.
Manifest activation can subsequently synthesize the live exact-current
completion, while stale, unmatched, replaced-document, and superseded-request
callbacks retain the pending fence and remain unable to affect authority.
Pure lifecycle tests and the runtime scope guard pin this fail-closed split.

The final lifecycle correction was hardware-tested from code commit
`c55ec367c7e0d3822550878601ac09786570902a`. A markerless ordinary PDF
completed its first load before any manifest was available and logged the new
deferred-completion path; it neither published viewport authority nor activated
Virtual Spread. The same control advanced natively from page 1 to page 2 and
back, returned to a pixel-identical page-1 screen, and produced zero manifest
acceptance, activation, RTL navigation, page-loaded, orientation-remap, link,
history, or viewport-publication events.

On the final artifact, a cold reopen of page 1 began generation 5 from manifest
activation. An early unbound callback was rejected before it could change load
or provider state. The exact later worker then cleared authority at load start,
began generation 7 only after its request binding and manifest were verified,
and published the measured descriptor. Fifteen seconds of additional idle time
produced no late clear or replacement. The same final sequence repeated after
the ordinary-PDF control and ended with the normative page-1 descriptor
authoritative. No stale descriptor survived a load transition or unmatched
callback.

Native page-bar turns then exercised two complete invalidation cycles. The
page-1 descriptor was cleared before generation 9 loaded zero-based virtual
page 0, which published descriptor SHA-256
`876619fb59bda77de4b728dd6b65f6359f1ae3cca3ef2a52902175526b47b4d4`.
The return turn cleared it before generation 11 and republished the normative
page-1 descriptor SHA-256
`a590afc7a95e92fbf7b9ac03fd949bcd6b474bcba70e06e4ec63936de937d033`.
The final cold process reopen repeated manifest and native-snapshot acceptance,
generation-5 activation, generation-7 exact-load publication, and the same
page-1 descriptor. The device-side PDF and sidecar hashes remained unchanged,
the disposable ordinary control was removed, and auto-rotation was restored.

A controlled ordinary PDF copy with no authenticated sidecar opened normally
in SupernoteDocument. It produced only the module-load and document-observation
diagnostics: no manifest acceptance, viewport publication, landscape/portrait
remap, or navigation-ownership event occurred. The disposable ordinary fixture
was removed after the check, while the normative hidden-cache pair remains for
InkBridge's shared gate.

A final exact-head review found that publication-failure cleanup still used the
process-wide session alone: a delayed failure or a callback from a replaced
`DocumentActivity` could clear a newer load fence. Commit
`53965eb06de61d581ba717cf58bd7391f1176131` scopes failure cleanup to both the
exact page-load generation and the view model currently owned by the active
activity. Pure tests prove that an older generation and a replaced view model
cannot clear newer authority. Its signer-verified version-28 APK had SHA-256
`cc265edda0785b0f8f317650c3ca33d53d579c07a1184d8928b42b019d0866f4`.

The focused post-review hardware gate reproduced the same cold page-1
descriptor, cleared it before generation 9 published page 0, and cleared page 0
before generation 11 republished descriptor SHA-256
`a590afc7a95e92fbf7b9ac03fd949bcd6b474bcba70e06e4ec63936de937d033`.
The ordinary three-page control changed pixels on the forward turn, returned to
the identical page-1 screenshot SHA-256
`bf63f5f384743339929ce9a75d13810f099985a7bcc00e6c95fa69da3de316d4`,
and emitted zero Virtual Spread authority or navigation events. The disposable
control was removed and a final normative cold open again published the page-1
descriptor.

The next exact-head review identified a retention-only lifecycle edge: each
`ReaderState` held load bindings that strongly referenced its own weak-map key,
and replaced-activity teardown released state only for the active owner. Commit
`5d970328a108013b19c97562e28d45270102ece0` always releases an obsolete destroyed
view model and its task, page-info, and thread-local bindings, while preserving a
view model reused by the replacement activity. Its signer-verified APK had
SHA-256
`393929b301eac71f4a1e61d53d162dd2c502576d1297659da29c5890aabc0825`.
The Nomad task-recreation gate created the replacement activity before the old
one was destroyed; the old teardown logged
`active_owner=false state_released=true`, and the replacement retained the
authoritative page-1 descriptor SHA-256 `a590afc7a95e92fbf7b9ac03fd949bcd6b474bcba70e06e4ec63936de937d033`.

The final exact-head review then exposed the complementary startup race: a
replacement reader could construct its first page worker synchronously inside
`onCreate()` before the old after-hook changed process-wide ownership. Commit
`a9853afb3fcf94b013bdc0121e9374af6e8f3b09` moves ownership and authority
invalidation to the `onCreate()` before-hook and constrains the temporary
pre-field view-model fallback to that exact creation scope. The signer-verified
version-28 APK had SHA-256
`6bf77b81c6e822656367351e0864532d643e12b71d95df670f99ceff658dec05`.
Forced task recreation on the Nomad cleared the prior viewport with
`reason=activity_creation_started` before the replacement claimed ownership or
began a page-load generation. The new activity then accepted the normative
snapshot and republished descriptor SHA-256
`a590afc7a95e92fbf7b9ac03fd949bcd6b474bcba70e06e4ec63936de937d033`;
the old teardown released only its obsolete state. This proves fail-closed
authority across both halves of activity replacement: startup and teardown.

The next exact-head review found one remaining ownership writer: late
`screenChange()` and `onConfigurationChanged()` callbacks still reassigned the
active activity. Commit `c41f674404f4ecf825b3d1c32f974d2b38938918`
removes those assignments and accepts either callback only when its activity is
already the current owner. Pure tests prove that a replaced or null activity
cannot reclaim authority. The signer-verified version-28 APK had SHA-256
`9a8a273a95d15e95a33b3aedeb1bb3b8e2a05749958f17ce64308d9579ed9a4a`.
The focused Nomad gate again cleared the prior descriptor before replacement
startup, published the unchanged normative page-1 descriptor SHA-256
`a590afc7a95e92fbf7b9ac03fd949bcd6b474bcba70e06e4ec63936de937d033`,
and observed obsolete teardown with `active_owner=false state_released=true`;
no stale callback reclaimed ownership or cleared the replacement.

This gate proves authoritative descriptor publication, cold-reopen recovery,
and page-load/reload invalidation on the Nomad. It does not claim that the
InkBridge consumer read or the cross-device annotation round trip has run; that
shared page-143 gate remains the next cross-project phase.

## v0.0.27 bookmarks and adjacent-link filtering - HARDWARE PASS

The focused v0.0.27 gate passed on 2026-08-30 on Supernote Nomad
`SN078C10015092`, firmware fingerprint
`Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys`,
display build `Chauvet.E103.2606161001.2393_release`, and SupernoteDocument
`1.02.446`. The tested behavior head was
`759b4586e561b5958d1d9462750129e901bb8d74`. The installed
upgrade-compatible v0.0.27 (`versionCode=29`) APK had SHA-256
`c4c6792614d296cc42371effa71c5e52c777649d4be2d68056b45f5beb258977`
and retained signer-certificate SHA-256
`a5a8551131de84d41660a3cf22d224f320f7a2f05a380282f76f6fe731807c67`.

A disposable seven-page schema-v4 fixture exercised one structural outline,
three outline destinations, and four page-2 link annotations. Its source PDF
SHA-256 was
`6ba6f40126c55c61dd0f61474f4944579f9270e2b2e48318b98075132bca948f`.
The generated PDF and sidecar SHA-256 values were respectively
`0dd5a24c24af5cf6b7a8ad4bf60e6f9cf69688e37370b1d7319170bb22cc23ef`
and
`0145cd78ad9202b59a4b73619824d683e32f5c000ad1676f3132bd448b5a4e60`.
The representation view ID was
`inkbridge-view-v1-9b9235712e21f7304b968332b770b0056cb2a64572d0c35a17d1944086510917`,
and its authenticated navigation-authority SHA-256 was
`2bee6d4654af04dd47ae613df874fe4a3260bd8697fa5df1b5c1dc5f7d42fb7a`.
Generation reported one removed adjacent-page link and three retained links.

The native reader authenticated and activated the four-page representation.
In landscape, the `RIGHT - source page 2` bookmark opened source page 2 on the
right half, `LEFT - source page 3` targeted source page 3 on the left half of
the same spread, and `DISTANT - source page 6` opened source page 6 on the
right half of the final spread. In portrait, the page-2 and page-3 bookmarks
each opened their source page as a normal full page. The hierarchy and titles
remained available through Supernote's native bookmark menu.

On source page 2, tapping the printed box whose adjacent-page link had been
filtered caused no visible change and produced no page-load event. The retained
distant link opened source page 6 on the right half and logged
`page_loaded page=3 ... target_half=RIGHT reason=internal_link`. The retained
same-page link stayed on source page 2/right and logged
`page_loaded page=1 ... target_half=RIGHT reason=internal_link`. The external
URI record remained authenticated in the generated PDF and manifest; the gate
did not launch an external browser.

Backward compatibility was checked with the checked-in normative schema-v3
page-143 fixture. v0.0.27 accepted and activated its exact PDF/sidecar pair,
loaded it normally, and repeatedly accepted its freshness snapshot. Finally,
the sidecar-free source PDF opened through the ordinary native-reader path and
logged only document observation: no manifest acceptance or activation event
occurred. This confirms that schema-v4 navigation authority is additive and
that ordinary PDFs and existing schema-v3 representations remain unaffected.

The post-gate exact-head review found that a named destination referenced by a
copied link or outline was resolved and inlined, but its externally addressable
catalog entry was not recreated. The final generator transforms and preserves
every supported name-tree or legacy-dictionary destination in the output name
tree; named destinations also select schema v4 so they cannot reuse an older
schema-v3 cache identity. Standalone, referenced, legacy, filtered-link, and
unsupported-mode regressions cover this correction. The generator also walks
and validates every raw name-tree or legacy-dictionary leaf before trusting
pypdf's parsed projection, so a malformed leaf cannot be logged, omitted, and
silently dropped from the derived PDF. The complete 173-test generator suite
and both repository invariant suites pass. These generator-only corrections do
not change the hardware-tested companion APK or runtime path.

## Failure capture

Before reproducing a failure:

```powershell
adb logcat -c
```

After reproducing:

```powershell
adb logcat -v raw -d | Select-String RTL_READER
```

For a visual/layout failure, note portrait/landscape, RTL/LTR, Auto/Single/Spread, Cover On/Off, and the PDF page numbers visible on screen.
