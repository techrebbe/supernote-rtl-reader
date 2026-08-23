# Virtual Spread hardware validation

- Date: 2026-08-21
- Device: Supernote Nomad
- Reader: native `com.supernote.document`
- Legacy Native Spread compositor: disabled and not mapped into the process

## Test documents

| Document | Virtual spreads | Purpose |
|---|---:|---|
| `VS-Calibration-2Page.pdf` | 1 | writing, erasing, lasso, undo/redo, highlight, portrait persistence |
| `VS-General-Cover-Links.pdf` | 4 | cover parity, navigation, internal links |
| `VS-Odd-Page-Shapes.pdf` | 4 | mixed rotations and extreme source page dimensions |
| `VS-Link-Target-Sides.pdf` | 4 | explicit links to left and right portrait halves plus landscape regression |

## Results

| Area | Result | Evidence |
|---|---|---|
| Initial landscape layout | PASS | Native reader displayed both fitted source pages as one full spread. |
| Cover parity | PASS | First spread was `blank | cover`; subsequent spreads were `3 | 2`, `5 | 4`, and `7 | 6`. |
| End boundary | PASS | Next on the last virtual spread was an exact visual no-op. |
| Native page-bar boundaries | PASS | Beginning/end buttons were truly disabled at their RTL virtual boundaries in portrait and landscape; intermediate arrows remained enabled. |
| Internal links | PASS | Portrait links opened both explicit target halves correctly (`page 7` left and `page 6` right); the same links navigated normally in landscape. Supernote's top-down MuPDF bounds were normalized against the manifest's bottom-left PDF coordinates. |
| Native link history | PASS | Back restored the newest link's exact source half, Original Back restored the oldest source half, and a process-restart test recovered the correct source half from the manifest when runtime history was unavailable. |
| Portrait/landscape transition | PASS | A focused portrait half rotated directly to the complete mixed-shape landscape spread, then returned to the focused native portrait view, without requiring a page turn in either direction. |
| Odd source page shapes | PASS | All normalized spreads opened and navigated without the former page-turn failure. |
| Ordinary PDF pass-through | PASS | A PDF without a sidecar retained native LTR navigation and emitted no virtual-spread events. |
| Pen | PASS | Native strokes on left and right halves saved as ordinary trails on the same virtual page. |
| Eraser | PASS | Erased region persisted after switching documents and reopening. |
| Lasso | PASS | Selection aligned, moved without duplication, and dismissed in its new location. |
| Undo/redo | PASS | Undo restored the original location; redo was pixel-identical to the pre-undo moved state. |
| Text highlight | PASS | Selection aligned to the intended sentence and persisted after reopening. |
| Portrait writing | PASS | `123` written in Box D remained after a clean document round trip. |
| Existing annotations | PASS | Earlier ink, erasure, lasso move, and highlight all survived subsequent tests. |

## Automated navigation coverage

The v0.0.8 navigation test passed 32 focused assertions, including the exact
MuPDF Y-axis inversion observed on the Nomad and deterministic Back/Original
Back history behavior. The exhaustive state-machine test passed 8,752
assertions across portrait/landscape, cover parity, spread occupancy,
direction, and boundary combinations. The hook-scope guard also passed,
confirming that no annotation or rendering subsystem was added to the module.

## v0.0.8 orientation transition

The link-history hardware pass exposed one independent transition issue: after
focusing a portrait half, rotating to landscape could leave the old half-page
bitmap visible until the next page turn. Hardware testing showed that a direct
`reloadPage()` is insufficient because it leaves Supernote's portrait split
state active.

v0.0.8 schedules Supernote's own forced `screenChange(true)` pipeline after
`onConfigurationChanged()`. The call remains manifest-gated and is skipped when
a native page load already completed. The post-reboot hardware check passed on
the mixed-shape `VS-Link-Target-Sides.pdf` fixture:

- The reader began on the right portrait half of virtual page 2.
- Rotating to landscape logged `orientation_refresh orientation=landscape` and
  immediately displayed the complete `page 3 | page 2` spread without a page
  turn.
- Rotating back logged `orientation_refresh orientation=portrait` and
  immediately restored the focused page at the native portrait scale, again
  without a page turn.

The transition preserves Supernote's own split-state, toolbar, annotation, and
page-loading pipeline rather than constructing a replacement viewport.

## Portrait persistence artifact

Before the portrait stroke was serialized:

```text
size:   82566 bytes
sha256: 4e689512f5f5890fbb2b4b942eaa6927973cbc45ca0ebb15e235471f242babf7
```

After switching to another PDF and reopening the calibration PDF:

```text
size:   134698 bytes
sha256: 224865d95794788b15f420e893603e18ecef512ae641d911c53f2470534d62da
```

The reopened native reader visibly retained `123` in Box D. This is a direct
regression test for the former failure where portrait handwriting appeared but
did not survive a reload.

## Decision

Proceed with the virtual-spread architecture. Do not port the legacy dual-page
writer, eraser, lasso, highlight, or `.mark` interception into this design.
Limit device-specific hooks to virtual-spread detection, RTL navigation, and
native viewport/focus behavior. Internal-link observation only recovers the
manifest-declared destination and history-source halves; native link navigation
and history remain authoritative.
