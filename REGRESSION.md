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

## v0.4.10 protected native editing pilot

Safety and setup:

- [x] v0.4.10 identifies Native Spread v0.0.66 through the live handshake.
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
- [x] Backup-creation failure removes a newly copied orphan snapshot when no
  manifest exists.
- [x] Successful restore uses the same staged, rollback-capable cleanup as
  backup retirement before reporting completion.
- [x] Cover controls and synchronization are blocked while a native-mode
  transition is pending; a Cover change holds the same lock until its own
  marker update completes.
- [x] A successful Off or read-only transition clears the retired recovery
  snapshot status and Restore action from the settings UI.
- [ ] A document with no `.mark` records and can restore the original absent state.
- [ ] Removing or modifying a backup file makes editable mode fail closed.
- [ ] Read-only mode and **Off** retain their v0.4.7-r1 behavior.

Protected duplicate editing:

- [x] Native writing persists on the active left page through a cold restart.
- [ ] Saved ink remains visible on the inactive page and after spread turns.
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
