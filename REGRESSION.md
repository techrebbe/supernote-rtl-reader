# RTL Reader hardware regression — v0.0.9 baseline

Device baseline: Supernote Nomad, plugin beta firmware.

v0.0.9 has already passed the core native-reader handoff test: closing RTL Reader synchronizes the PDF page and reopens the native reader at that page without `su`.

Use one long PDF with a normal cover for most tests. Clear logcat before a failing case only; routine passes do not need logs.

## 1. Portrait single-page RTL — PASS

- [x] Open a PDF natively on a known page and launch RTL Reader.
- [x] Portrait / Auto shows one page.
- [x] Right swipe advances one PDF page.
- [x] Left swipe goes back one PDF page.
- [x] Right-edge tap advances one PDF page.
- [x] Left-edge tap goes back one PDF page.
- [x] Center tap hides/shows chrome.
- [x] Page counter jump opens the requested physical PDF page.
- [x] Close reopens native reader on the RTL Reader page.

## 2. Landscape Auto spread, RTL — PASS

- [x] Rotate to landscape while View = Auto; display changes to a two-page spread.
- [x] Earlier/lower page is on the RIGHT; later/higher page is on the LEFT.
- [x] Right swipe / right-edge tap advances exactly one spread.
- [x] Left swipe / left-edge tap goes back exactly one spread.
- [x] Footer labels match the two visible physical PDF pages.
- [x] Rotate back to portrait; the focused PDF page is retained.
- [x] Close from landscape/spread mode reopens native reader at the focused RTL Reader page.

## 3. Treat Cover Page Separately

With RTL + Spread + `Cover: On`:

- [ ] First spread is `Blank | Cover 1`.
- [ ] Next spread is `Page 3 | Page 2`.
- [ ] Next spread is `Page 5 | Page 4`.
- [ ] Turning `Cover: Off` returns to ordinary pairing (`Page 2 | Page 1`, then `Page 4 | Page 3`, etc.).
- [ ] The setting persists after Close/reopen for this PDF.

## 4. LTR sanity check

- [ ] Switch direction to LTR.
- [ ] Single-page swipe/tap directions reverse correctly.
- [ ] Spread order becomes earlier page LEFT, later page RIGHT.
- [ ] With `Cover: On`, first spread is `Cover | Blank`.
- [ ] Direction persists after Close/reopen for this PDF.

## 5. Native/RTL position and per-document persistence

- [ ] Leave PDF A at a distinctive RTL Reader page and Close; native reader reopens at that page.
- [ ] Launch RTL Reader again; it opens at the synchronized position.
- [ ] Open PDF B natively and launch RTL Reader; PDF B does not inherit PDF A's saved page/settings unexpectedly.
- [ ] Change PDF B settings, Close, then reopen PDF A; PDF A's own settings are restored.
- [ ] Move the native reader manually to a different page, then launch RTL Reader; the externally changed native position wins rather than stale saved RTL position.

## 6. Beginning/end boundary cases

These catch spread-anchor/clamping bugs that ordinary reading may not expose.

- [ ] At the first spread, Previous does nothing and does not alter the footer/focused page.
- [ ] At the final spread with `Cover: Off`, Next does nothing immediately; there is no extra invisible page-step where the spread stays visually unchanged.
- [ ] At the final spread with `Cover: On`, Next does nothing after the true last spread/page.
- [ ] Closing from the final spread hands off the page that RTL Reader actually considers focused.
- [ ] Jump to PDF page 1 and to the final PDF page works without crash or blank unintended pages.

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

## Release gate

v0.0.9 can be promoted from validated baseline to release candidate after sections 1–6 pass, or after any discovered regression is fixed and re-run against the affected section.
