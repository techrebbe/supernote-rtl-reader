# RTL Reader hardware regression

Device baseline: Supernote Nomad, plugin beta firmware.

v0.0.9 established the hardware-validated reading-engine baseline. v0.1.1 subsequently validated the polished UI and direction-aware footer. The v0.2.x branch adds performance optimizations and should preserve all of that behavior.

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

## v0.2.1 recent-render-cache spot check

- [ ] Normal portrait and landscape reading still looks identical to v0.1.1/v0.2.0.
- [ ] Rapid sequential turns do not crash, blank, or show stale pages.
- [ ] Close/native-reader handoff still lands on the focused page.
- [x] Native logs continue to show renderer reuse (`reused=true`) after the initial open.
- [x] Repeated requests show `cacheHit=true` with `renderMs=0` and `pngMs=0`; captured cache-hit median total was about 16 ms versus about 419 ms for cache misses.

Hardware timing capture for v0.2.1 contained 107 native render requests: 14 cache hits (about 13.1%). Cache-hit median total time was 16 ms; cache-miss median was 419 ms. Cache hits therefore avoided roughly 403 ms of native work per hit in this test while preserving the same PNG output path.

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
