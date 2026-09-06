# Single native-page viewport experiment

Status: saved-ink diagnostic and isolated Android display-substrate validated;
**no native viewport adapter installed or proven**.
Branch `agent/native-single-viewport-probe` starts at recorded merged main
`69e2aa273b9d1943f19afaeac6a1e324abbf9481`. The earlier post-merge working patch
and complete stock hardware evidence remain untouched in the sibling
`supernote-rtl-reader-pr22-upload` worktree. The installed companion remains
disabled for the stock baseline. No production package includes these files.

## Implemented preparation

- `ViewportFrame`: one immutable native-page-canvas to window transform and a
  contact route classified at DOWN from current visible native chrome. It is
  only a mathematical contract, **not** the missing native adapter. It neither
  programs DrawPath nor changes saved coordinates, page state or global sizes.
- `ink_oracle.py`: strict offline evidence validation and exact native-record
  comparison. Includes point samples, pressure, thickness and all extra native
  fields. No tolerance is invented. Diagnostic trail identities are not claimed
  stable across native compaction. Invalid/missing evidence cannot become PASS.
  All 62 top-level fields of the pinned native record are required; decimal
  floats are rejected before parsing can round or underflow them. The field
  inventory was independently compared with the pinned firmware source.
- `SavedInkReader`: compiles as a standalone Android helper for a separate
  `app_process` and a disposable `.mark` COPY only. It uses the pinned native
  `getFilePageTrails` read interface, never live `getTrailContainer`. It does not
  attach to Document/DrawPath, install hooks, connect Binder, or write a mark.
  Native initialization/cleanup is private to its process. Firmware/copy hashes
  are checked before and after. Its disposable-copy gate is recorded below.
  Read-only `fetchPagesOfMark` must admit the requested page first. A page with
  no saved mark record is explicitly unavailable to this diagnostic, not a
  successful empty capture, and no mark/page is created to change that result.

The evidence JSON files are local test results, NOT a new document conversion
or InkBridge contract. The original PDF and native annotations stay authoritative.
The source digest in a collector request must come from the host-verified source
fixture; the helper does not claim to derive a PDF identity from a `.mark` file.
Native float values use binary32/binary64 hex wrappers and longs use decimal
strings so Android's JSON formatter does not discard precision or signed zero.
`ViewportFrame` maps native presentation-canvas pixels, not the persisted EMR
sample coordinates. Native records include their own axis, maximum-coordinate,
resize and redraw metadata. Preserve that metadata; do not apply the canvas
matrix directly to `m_points` or assume they are screen pixels.

## Observed boundary constraints

Pinned firmware source `DocumentConstants.getDisplayPoint()` returns1404x1872
for Nomad, not current window dimensions. `loadHandWrite`/`refreshBitmap`,
`setHandWriteRotation`, selection and page-hit testing independently consume
that size plus native split/crop state. Shrinking an Android view is therefore
not sufficient. The compiled frame must be consumed by a coherent replacement
geometry producer; do not reuse the previous reassert/restore loop or claim that
this host transform itself fixes native tools.

For the calibration native canvas1404x1872, left/right936x1404 halves fit at
2/3 scale with78px top/bottom margins. That is aspect-preserving Fit Page,
not filling by distortion. Canonical sample(939,388) presents at(626,336 2/3)
on the left and(1562,336 2/3) on the right. These arithmetic vectors do not
establish the still-unproven native pen-service mapping.

## Next gates, in order

1. DONE for the saved calibration checkpoints below: review/build the isolated collector, then validate it on disposable copies
   of existing saved baseline checkpoints without asking for another stroke.
   Repeated capture must be identical and must leave both the copied file and
   untouched native reader unaffected. A native initialization failure is a
   collector blocker, not lost-ink evidence.
2. Implement the scoped native geometry producer/consumer boundary for ONE
   source page/one presenter/one note. Keep native saving/history authoritative.
   Exclude legacy/v2 mutating routes. No page switch or second live writer yet.
3. Automated/adversarial tests, full independent exact-head review, exact
   package verification, then reversible disposable-file installation.
4. One short physical batch in the left half, then the right: writing, both
   erasers, native Undo/Redo, lasso move/resize/commit, text selection. Automate
   capture at meaningful boundaries, analyze after the batch, and compare
   saved native records after reopening in the unchanged native reader.
5. Only after those gates pass, add two live page contexts and test focus changes.

Do not operate the Nomad from a review session, install an incomplete probe,
push/advance a PR on this preparatory subset, or merge without the user's decision.
Do not repeat the complete stock tool suite just to obtain duplicate screenshots.

## Host checks

Run `check.ps1` with the explicit local JDK, Android SDK and Python paths.
This compiles diagnostics/tests only; it does not package or install an APK.

2026-09-06 preparation checkpoint:280 viewport assertions and13 evidence tests
PASS; Android collector compiles. Actual Nomad system library hashes match the
collector's pinned hashes. Device access this turn was read-only path/hash/PID
inspection; no helper deployment, pen injection, module enable, or app restart.
The initial review connection failed TLS validation and was terminated. The user
then explicitly approved uploading only the probe source/tests and required
geometry dependencies, excluding PDFs, saved annotations and credentials. The
normal-host review of the isolated eleven-file bundle completed with three
findings: incomplete record admission (P1), bare decimal precision loss (P2),
and unbounded file allocation before the size check (P2). All three have fixes
and deterministic regressions. The completed confirmation and device-copy gate
are recorded below; neither certifies an arbitrary native viewport.

## Completed review and disposable-copy hardware gate

Final r3 source-only independent review: no actionable findings. The initial
three findings were fixed and retested; a separate pinned-firmware check caught
the native initialization enum offset before execution. The helper now follows
stock `getDeviceType()+2` (Nomad 2 -> initialization argument 4), with the enum
read from the pinned APK and other devices rejected before note creation.
Review evidence is preserved outside this worktree at
`../../reviews/native-viewport-host-20260906-confirmation.md`.

Nomad `SN078C10015092`, 2026-09-06 ~20:22-20:24 device time:

- Ran as ordinary ADB **shell UID 2000**, NOT root. No APK install, module enable,
  app restart, hook attachment, UI manipulation or pen action. Future runs of
  this diagnostic must retain that unprivileged execution condition. Native
  initialization attempted input-device queries and logged access failures;
  do not elevate it to bypass those denials.
- Separate `app_process` instances read host-saved disposable calibration copies,
  never the live document's mark. Before copy: 1 trail / 66 samples. After copy:
  unchanged prior trail plus 1 new trail / 53 samples. All 62 fields of the
  prior trail compare exactly, including samples, pressure and thickness.
- Repeated after-capture: exact equality of both complete native records.
- Deliberately absent page 999: rejected, exit 2, no success envelope.
- Successful captures: ~2.1 seconds each, including process startup, firmware
  checks, native initialization and cleanup. This is not a page-turn benchmark.
- Copy hashes unchanged; live PDF and mark hashes and Document PID 2027 were
  identical immediately before/after the gate. No diagnostic process remains.

Artifacts (local, ignored): `build/hardware-r3/` contains raw diagnostic logs,
live before/after fingerprints and a reproducible checkpoint verifier.
Native mark identities in this fixture are `(1,0,0,5)` and `(1,0,0,6)`; these
are diagnostic tuples, not stable cross-compaction IDs. The raw sample bounds
are not screen bounds, consistent with native axis metadata.

The live mark at this later gate had a different hash from the earlier archived
checkpoints, before any helper execution. No cause is inferred; all comparisons
use the explicitly identified archived copies, and the live hash remained
unchanged during this gate.

Three read-only temporary device files remain under
`/data/local/tmp/native-viewport-ink-reader/` (two disposable marks and the
diagnostic JAR; ~93 KB total). Nothing is installed or running. Original files
and all prior worktrees/evidence are preserved. The native arbitrary-viewport
adapter remains unimplemented, so left/right-half hardware testing is NOT ready.

## Display-substrate preparation (later on 2026-09-06)

`display-host/` now implements one fixed-size Android display presented FULL /
LEFT / RIGHT, with an independent calibration activity. This is a built
display-only probe, NOT yet a hosted native Document page or pen adapter.
It has no storage/network permissions, native libraries, LSPosed hooks, input
injection, Document launch or save operations. It does not replace any installed
package. Its no-pen warning is not a direct-pen-service safety interlock.

See [the bounded implementation and gates](DISPLAY_BOUNDARY_EXPERIMENT.md).
The native firmware's special-case scale field and possible direct framebuffer
path are explicit unresolved integration constraints, not hidden behind a tool
fix. The exported function name alone does not prove physical framebuffer access.
The independent native task/display boundary is the next candidate to prove;
the old production architecture has not been discarded or replaced.

Host validation: 280 existing viewport assertions, 45,453 display-fit/lifecycle assertions,
15 Python tests, Android compilation and unsigned APK packaging pass. Windows
packaging initially rejected a long artifact path; shorter generated filenames
fixed it without moving or deleting any earlier evidence. No APK installed and
no physical action requested. A calibration pass will not count as a native
writing/tool/persistence pass.

Independent display-probe review found two P2 defects: restored instances could
restart a stopped experiment, and opaque controls covered calibration corners.
Both are fixed together: restored admission starts in a sticky STOPPED state,
and controls can be hidden/shown by finger without forwarding any input. Tests
cover stopped/restored admission and the Android wiring/hidden-control route.
The full updated r2 source-only confirmation review is now clean. All 15 Python
tests also passed independently; Android task migration, teardown and compositing
remain hardware gates. The reviewed source snapshot is preserved outside the
worktree at `../../reviews/native-viewport-display-20260906-r2/` with its adjacent
`-review.log`. It contains no firmware, PDFs, annotations or signing credentials.

Prepared test artifact: `build/d-fce8d4538a354c81b4e81e41ca1e0b54/viewport.apk`.
This is a separate `0.0.1-display-only` package, locally signed with a newly
generated temporary test-only key. The user's existing debug keystore was not
used or uploaded. APK SHA-256:
`e9315eefec9ed0c4652e11575b09eb057a83b9832909f4eaf27c68356ab0e7a7`.
Verified signer certificate SHA-256:
`b0a6859721488d06624a90e4c077fee7ad379ce638d65a6535910b0696be75eb`.

Device preflight found the correct Nomad connected, but a different document
was open instead of the disposable stock fixture. Stopped before closing it,
installing the probe or changing orientation. Asked whether the device is idle.
No display-substrate hardware PASS is claimed. The stock fixture PDF/mark
fingerprints remain unchanged; this does not establish the currently open
document's save state. Evidence is local in `build/display-hardware-20260906/`.

After the user released the device, the current document was closed normally.
The v1 display probe created a 1404 x 1872 display but Android denied the
ordinary calibration launch onto it. Its display was released and the probe
uninstalled; File Manager is foreground, Document PID 2027 and the stock
PDF/mark hashes are unchanged, and rotation settings remain 1 (automatic) / 0.
No native pen actions or reader-module changes occurred.

The prepared v2 display-only revision retains the live display for an explicit
host-side root launch of its own non-exported calibration activity, checking
the actual display and current owner UUID. No app-side root execution or global
policy change is introduced. Its own full confirmation review and bounded
display-only hardware gate are now complete: [evidence and limits](DISPLAY_HARDWARE.md).
Duplicate launches are rejected by a single calibration claim; only the admitted
calibration may signal termination. That signal clears attachment status and
stops the display. Full/left/right presentation, rotation and cleanup passed.
No native Document page or handwriting was tested. The temporary APK is removed.

The next lower-level investigation is now checkpointed in
[NATIVE_PEN_BOUNDARY.md](NATIVE_PEN_BOUNDARY.md). Read-only live metadata confirmed
that DrawPath's pen planes bypass the Android surface. A separately reviewed,
short-lived input-device helper proved exclusive acquisition and release with
the reader closed, without generating input or changing annotations. The helper
was removed. This is not a held pen barrier or permission to write on the
display-only host. See [overnight continuation](OVERNIGHT_CHECKPOINT.md) for the
exact remaining work and preserved evidence.

The next host-only preparation records the actual service startup, separate
Binder caches, painter-held EBC aliases and canonical-background dependency in
[NATIVE_ENGINE_STARTUP.md](NATIVE_ENGINE_STARTUP.md). A disposable-process
[isolation diagnostic](ISOLATION_PROBE.md) compiles for Android and passes its
portable and unprivileged Linux host checks. It has NOT run on the Nomad and
contains no firmware loader. Independent review of the new source/notes is
blocked pending explicit external-review disclosure approval. Existing r2
review does not cover these new files; do not use the host results as permission
to start a native writer. No final physical-pen batch is ready yet.
