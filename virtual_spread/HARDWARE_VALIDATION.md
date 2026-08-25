# Virtual Spread hardware validation

- Date: 2026-08-21
- Device: Supernote Nomad
- Firmware fingerprint: `Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys`
- SupernoteDocument: `1.02.446`
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

## v0.0.15 focused revalidation - PASS

On 2026-08-25, a fresh `VS-v15-Smoke.pdf` and companion sidecar were generated
from the mixed-shape, internal-link source fixture. Companion module v0.0.15
accepted the four-page manifest and activated it on the Nomad. Hardware then
confirmed:

- landscape cold-open and all RTL spread pairings;
- correct beginning/end boundaries and reverse navigation;
- immediate full-size portrait focus for the right source half and immediate
  complete-spread restoration after rotating back;
- both internal-link target halves and exact native Back restoration;
- native pen persistence across a portrait page round trip and into the
  corresponding landscape half; and
- complete pass-through for the same seven-page source PDF when opened without
  a sidecar, including native single-page landscape layout and LTR portrait
  turns.

The regenerated output PDF SHA-256 was
`322f0845b3c62a32c95bd9a5ee23cb8917faf64d32265cc05dc23cfff7a5e8b7`.
The runtime activation revision was
`ed5a1e7eca9088336ef7cb7171d9585188be783dbea8d1f6dac0b93ad81ac0f9`.
No v0.0.8 annotation subsystem was reimplemented or intercepted by v0.0.15.

After the hardware pass, PDF-semantic review hardening changed `/XYZ` zoom
normalization, duplicate annotation-name handling, and rejection of incompatible
source multi-page layouts, and added finite-result guards for transformed link
destinations. The smoke source has no persisted `/PageLayout` and uses only
non-overflowing link geometry. Regenerating the exact fixture left every manifest
mapping and link entry unchanged; only the output PDF hash and size fields
changed. The regenerated PDF
added one harmless whitespace separator to three composed content streams, and
all four pages had pixel-identical 150-DPI render hashes to the device-tested
copy. The fixes do
not touch the companion module or any navigation, viewport, focus, or native
annotation path, so the focused hardware evidence remains applicable.

## v0.0.16 source-Fit link validation - PASS

On 2026-08-25, a fresh v0.0.16 pair was generated from
`VS-Link-Target-Sides-source.pdf` specifically to exercise link-authority v2
and source-page `/Fit` preservation. The device accepted sidecar revision
`9fa9a9b875c0cc29a217c159693cf269b82ec0406372e0139a4ec10f3806ab29`;
the output PDF SHA-256 was
`09527f32803161d5d0b664cd68ce0f7409c8e3f2e86e25229847f2c23f0484ef`.

The focused Nomad pass confirmed both page-6/right and page-7/left link targets
in portrait and landscape. Portrait targets used the native full-page Fit view,
and native Back restored the exact page-2 source half. Landscape targets settled
as the complete `7 | 6` spread, native Back restored `3 | 2`, and no visible
zoom, flicker, stale page, or incorrect target appeared during the guarded
`internal_link_fit_reset` refresh. A forward/reverse RTL turn also passed. The
same seven-page source, copied under a new name without a sidecar, remained an
ordinary native single-page landscape PDF with native LTR swipes.

The exact post-review v0.0.16 APK added one fail-closed ambiguity guard: native
link matches that agree geometrically but conflict on authenticated target-view
policy are rejected. Its SHA-256 was
`73d0e1024c58993a3b8ec7646f75739b2f0886cd7273ef80fbe0b1fb8e57e679`.
It was installed after the visual run and accepted and activated the same unique-
link fixture. The companion suite passes 55 focused navigation assertions, 10
cross-language authority assertions, 8,752 exhaustive assertions, and the hook-
scope guard.

## v0.0.23 native-open snapshot binding and portrait viewport - PENDING HARDWARE

Review passes 40-46 bind the authenticated sidecar to the actual PDF object
retained inside Supernote's native reader and harden all transformed link,
manifest, and page-box boundaries. The generator adds a descriptor-verified
source-authority marker before the layout and link markers. The companion reads
all three values through MuPDF's `Document.getMetaData()` on the exact native
`Document` instance. It requires exact JSON integer tokens for page counts,
indices, and the persisted nonnegative output byte size. Spread dimensions,
gutter, and link rectangle coordinates must be raw finite JSON numbers. Raw
sidecar bytes must be valid UTF-8, and a strict pre-parser rejects malformed JSON
and duplicate names anywhere in the manifest.
The generator rejects transformed URI `/IsMap true` actions, a CropBox extending
outside its MediaBox, and link geometry outside the source CropBox, while scaling
an omitted link border's PDF-default width.

The local automated gate passes 87 generator tests on Windows (five expected
platform skips), 112 focused navigation/manifest/cache assertions, 12
cross-language authority assertions, 8,752 exhaustive navigation assertions, both native
invariant suites, hook-scope validation, and the signed/verified v0.0.23
(`versionCode=23`) APK build (SHA-256
`bd51d1397c7057fa0fd2957ea476cba43417b66a98f2e9b99edf1d56f4010c0c`).
CI independently runs the same generator suite on
Linux without the Windows-only skips.

The remaining focused Nomad gate is:

1. cold-open a newly generated v0.0.23 pair and confirm normal activation;
2. replace the PDF/sidecar pair at the same path while the original PDF remains
   open and confirm the companion fails closed rather than applying the new
   mappings to stale native content;
3. reopen the replacement and confirm its matching authorities activate; and
4. confirm a portrait explicit `/XYZ` or `/FitR` internal link retains its
   native viewport rather than snapping to the destination page edge; and
5. confirm a sidecar-free ordinary PDF remains completely native.

## Decision

Proceed with the virtual-spread architecture. Do not port the legacy dual-page
writer, eraser, lasso, highlight, or `.mark` interception into this design.
Limit device-specific hooks to virtual-spread detection, RTL navigation, and
native viewport/focus behavior. Internal-link observation only recovers the
manifest-declared destination and history-source halves; native link navigation
and history remain authoritative.
