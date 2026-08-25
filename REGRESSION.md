# RTL Reader hardware regression

Device baseline: Supernote Nomad, plugin beta firmware.

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
- [x] Static invariant: failed trace startup stops observers, cancels pending
  work, and removes the stale `active.txt` session pointer.
- [x] Static invariant: `last.txt` is published only during successful trace
  finalization, before `active.txt` is removed; failed startup preserves the
  previous completed-session pointer.
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
- [x] Static invariant: completed/incomplete pointer publication always attempts
  `active.txt` cleanup in `finally`; a failure preserves the exact session via
  `publication-failed.txt`, which the helper checks before `last.txt`.
- [x] Static invariant: completed publication rejects an undeletable stale
  `incomplete.txt` and preserves an explicit publication-failure session.
- [x] Nomad helper simulation: `Stop` reported a disposable `incomplete.txt`
  session by name, refused the preceding `last.txt`, retained its partial
  directory, and left the prior completed pointer unchanged. The disposable
  marker and directory were then removed.
- [x] The trace collection script waits for asynchronous finalization and
  verifies the completed session pointer before pulling the bundle.
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

## Native Virtual Spread v0.0.8 architecture validation — PASS

Hardware validation was completed on 2026-08-21 on a Supernote Nomad, using
the native `com.supernote.document` reader. The legacy dual-page Native Spread
compositor was disabled and absent from the document process.

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
