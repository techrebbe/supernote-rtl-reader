# Supernote Native Spread companion module

This LSPosed module supplies the rooted native-reader enhancement controlled by
Supernote RTL Reader. It keeps Supernote's own PDF renderer, links, highlights,
and `.mark` annotation data while adding:

- RTL page progression in portrait;
- automatic two-page RTL spreads in landscape;
- optional separate-cover parity;
- per-document opt-in through a hidden `.snspread` sidecar;
- a fail-closed read-only pilot mode;
- protected per-document editing backed by a verified annotation recovery snapshot.

## Compatibility and safety

The module intentionally refuses to operate unless all of these match the
hardware-tested environment:

- firmware fingerprint
  `Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys`;
- `SupernoteDocument` version code `102446`;
- document APK length `138486560` bytes;
- LSPosed scope limited to `com.supernote.document`;
- an enabled marker beside the current PDF.

The read-only marker sets `editable=false`. In that mode v0.0.75
forces a full-page disabled handwriting region and blocks the native
annotation-commit callback. It displays existing `.mark` ink but does not allow
new native writing. An editable marker for an ordinary document is accepted
only when the module can verify the exact PDF identity, recovery-manifest
SHA-256, and original `.mark` snapshot bytes. Disposable calibration markers
remain supported. Any failed protected-backup check downgrades the document to
read-only. v0.0.75 performs the full PDF and snapshot hashing on a background
thread, keeps editing disabled until that verification completes, and refreshes
an already visible landscape spread to reapply native handwriting geometry.
The protected-verification cache also tracks the current PDF length,
modification time, device/inode identity, and nanosecond change time. An
in-place rewrite or metadata-preserving replacement therefore immediately fails
closed and starts a new background attestation rather than retaining prior
authorization.

Before the plugin reports this mode as active or creates a marker, it sends a
random challenge to the currently hooked `DocumentActivity`. The module answers
only after all hooks have registered and only when the challenge names the PDF
that is actually open. The response binds the nonce to the handshake protocol,
module version, document APK identity, and live document-process PID. An
installed-but-disabled, incorrectly scoped, or compatibility-rejected module
therefore fails closed.

v0.0.75 also clears the destroyed activity reference and recycles all
per-activity full-resolution page, ink, and digest bitmaps when the native
reader closes.

For canonical landscape lasso moves, v0.0.75 converts the translated origin
from half-page display coordinates but preserves the native selection width and
height. This prevents a pure move from applying the inverse spread scale to the
selection dimensions a second time.

For normal pen input on the inactive half of an editable landscape spread,
v0.0.75 prearms the low-latency writer for the page under the pen, captures the
completed trail, converts it to native document-page coordinates, and merges it
with the page's existing `.mark` trails. It suppresses the native intermediate
save during that transition because the native in-memory list may contain only
a subset of the page and would otherwise replace older annotations.

v0.0.78 applies the same page-local transaction to Supernote stroke-eraser
paths. It normalizes saved ink and the eraser path before intersection testing,
then rewrites the target page with only the matched ink removed. Inactive-page
highlighter and lasso operations remain separate validation targets.

v0.0.79 fails closed if that page-local write does not succeed: it cancels the
page activation and visibly reports that the edit was not applied instead of
discarding retained ink or eraser buffers. It also adds device, inode, and
nanosecond change-time identity to the marker and both recovery sidecars, so a
metadata-preserving replacement invalidates cached editable authorization.

v0.0.80 requires the complete sampled stroke and its ink-defining attributes to
match before an inactive-page capture is considered already persisted. Point
count and endpoints are no longer sufficient, so retraced lines and colocated
dots remain distinct annotations.

v0.0.81 keeps normal pen commits additive in the composed landscape ink layer.
The newest settled trail is drawn over the canonical saved page rather than
clearing the active slot, so earlier strokes do not disappear until a page
reload. Eraser, lasso, undo, and redo remain replacement operations because
their transparent pixels must remove or relocate existing ink.

v0.0.82 adds per-document divider and page-sizing controls. **Fit page** keeps
the complete page visible. **Native fill** preserves the page aspect ratio,
fills its half of the screen, and clips overflow like Supernote's native
full-screen reader. The PDF, committed ink, highlights, lasso/link geometry,
and handwriting input all use the same full-page transform plus visible-slot
clip. Disabling the divider removes the dark rule and gives both pages the full
936-pixel half-screen width.

v0.0.84 fixes the first portrait frame after leaving a landscape spread. The
module waits until the native ImageView reports portrait dimensions and then
uses Supernote's own `reloadPage()` path for the unchanged current page. This
regenerates the native portrait display bitmap instead of resubmitting the
landscape-scaled cached origin bitmap.

v0.0.86 commits an inactive-page pen transaction directly after
`receiveTrials()` captures its completed trail. The native callback does not
call `saveTrails()`, so waiting for that separate lifecycle operation allowed
the fail-closed completion guard to run first and cancel valid ink. Persistence
now finishes before page activation; a failed write still cancels activation
without discarding or overwriting the retained annotation data.

v0.0.87 suppresses the single delayed native `saveTrails()` call after a
successful inactive-page stroke erase. Without that guard, the page-local erase
correctly removed the intersecting trail, but the delayed save could restore it
from stale memory while dropping a newer trail. The bypass is erase-only,
one-shot, and expires after two seconds.

v0.0.88 adds the page-local transaction to Supernote's existing Undo/Redo
control stack after the target page finishes loading. A protected inactive-page
write or erase records the trail lists immediately before and after the edit;
Undo and Redo restore those snapshots through the same page-local native file
API and reload the active annotation layer.

v0.0.89 preserves the inactive page's prearmed writable geometry across
Supernote's first-pen-down writable-area refresh after document launch.

v0.0.90 invisibly loads the inactive target into Supernote's native mark engine
before writing, while suppressing that intermediate bitmap from the spread UI.

v0.0.91 renders settled eraser refreshes from the saved canonical `.mark` page
instead of replacing the active spread slot with an incomplete native refresh
bitmap after deferred page activation.

v0.0.92 synchronously saves a completed native active-page eraser operation at
pen-up so that the canonical spread redraw sees the erased state rather than
the older on-disk page.

v0.0.93 keeps finger taps in the native top toolbar and bottom page-number bar
out of the inactive-page activation path. Native Undo/Redo and page-bar controls
can therefore operate without first changing the active spread page.

v0.0.94 forces Undo/Redo refreshes through the canonical `.mark` renderer after
Supernote updates the operation history, avoiding an incomplete transient
bitmap that could visually clear all ink from the active spread page.

v0.0.95 saves the in-memory native Undo/Redo result and reloads that page before
the canonical spread redraw, making the restored or reapplied edit visible and
durable without a page turn. This was hardware-validated on the Nomad with an
active-page erase, top-toolbar Undo and Redo, and a spread reload; unrelated
trails remained unchanged throughout.

v0.0.96 exempts deliberate active-eraser and Undo/Redo canonical saves from the
short stale activation-save guard. The explicit transaction reaches `.mark`,
while the guard remains armed to consume the delayed stale save it was created
for.

v0.0.97 adds the `showHeader` marker property. It defaults to `true` for older
markers; when disabled, normal ACTIVE LEFT/RIGHT and READ ONLY status banners
are removed while failure and annotation-save warnings remain visible.

v0.0.98 adds explicit, diagnostic-only annotation trace sessions. Tracing is
off by default and can be controlled only through an ADB broadcast protected by
Android's `DUMP` permission. A session records structured JSONL events for pen
contact, page routing, trail-container results, save/load boundaries, Undo/Redo,
and display composition. It watches the active `.mark` file and copies a new
snapshot only when its SHA-256 changes. Snapshots are capped at 64 MiB. No
annotation or rendering decision is changed by enabling the trace.

v0.0.99 reloads the active mark page after an eraser transaction is explicitly
saved. The native committed-ink callback can otherwise render from the older
canonical file before `receiveTrials()` flushes the erase, leaving the erased
stroke visible until a page-focus change even though persistence is correct.
The save-before-reload ordering now makes the settled active-page view match the
updated `.mark` immediately.

v0.0.100 scopes inactive-page eraser save suppression to the stale save made
inside the deferred target-page `loadPage()` call. Ordinary pen, page-switch,
and canonical saves are no longer eligible for suppression. Trace snapshot
hashing and copying now run on a debounced single-thread worker instead of the
document UI thread. Ordered trace fingerprints include all trails even when the
detailed `items` array is truncated after 256 entries.

v0.0.116 also moves trail JSON serialization and fingerprint hashing to that
worker. The hook thread copies an immutable trail representation first, so the
worker cannot observe later native mutations. Annotation-boundary `.mark`
hashes are reported as `pending` until the live file identity matches a
completed snapshot, rather than attributing an older hash to a new save. Trail
fingerprints include the captured rotation, redraw dimensions, and coordinate
extents so geometrically different states cannot compare as equal. It also
captures and hashes the remaining trail identity fields used by the production
ink matcher: layer, pen-up/special flags, recognition and EMR modes, trail/draw
versions, recognition type, and writing-app identity.
Recognition, refresh, before/after-shift rectangles and contour point geometry
are copied into immutable scalar arrays and included in worker-side details and
fingerprints.

The active settled-ink transform is clipped to the active page's visible slot,
matching Native Fill's PDF and canonical-ink clipping and keeping cropped ink
from bleeding across the center divider.

Trace startup failure now cancels pending work, stops any created file
observer, and deletes `active.txt`, so the collection helper cannot mistake a
failed session for a recording trace. It does not publish `last.txt` until a
session has completed final snapshot collection, preserving the preceding
completed-session pointer if startup fails.
An `active.txt` left by a killed document process is reconciled by every desktop
trace-helper action. The helper compares the session's recorded PID with the
live Supernote document PID before removing the pointer; it retains the partial
directory without publishing it as completed. `Stop` then raises an explicit
incomplete-session error rather than substituting and pulling an older trace
from `last.txt`.
Finalization retries an unstable stop-time `.mark` hash/copy up to five times.
Only a stable, SHA-256-verified snapshot can publish `last.txt`. Exhausted
retries publish `incomplete.txt` instead, remove the recording pointer, retain
the partial directory, and cause `trace.ps1 Stop` to report the failed session
without substituting an older trace.
The live source identity is checked once more after the copied snapshot's hash
is verified, so a rewrite during that verification cannot be accepted.
The missing-file and unchanged-hash fast paths likewise recheck the live source
before reporting a stable final state.
Successful snapshot events are written only after final source verification
and acceptance, so rejected candidates cannot leave an event that names a
deleted snapshot.
Every event is serialized to an immutable record and queued to a dedicated
per-session writer; hook, pen, native-writer, and UI threads no longer open or
flush `events.jsonl`. Finalization drains the writer before publishing its
pointer. A pointer-write failure moves or records the session in
`publication-failed.txt`, attempts `active.txt` cleanup in `finally`, and makes
`trace.ps1` refuse the preceding completed session.
An undeletable stale `incomplete.txt` also enters this fail-closed publication
path instead of overriding the new completed pointer.

This is firmware-specific experimental software for a rooted device. Back up
documents and `.mark` files before testing a new firmware or module revision.

## Build

Requirements:

- JDK 17 with `javac` and `jar` on `PATH`;
- Android SDK platform and build-tools 35.0.0;
- Android NDK 27.0.12077973;
- an Android debug keystore.

`build.ps1` reads `ANDROID_SDK_ROOT` or `ANDROID_HOME`, and
`ANDROID_NDK_HOME` when set. Paths can also be passed explicitly:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
```

The signed APK is written to `build/artifact/`.

## Install

Install the APK, enable **Supernote Native Spread Probe** in LSPosed, scope it
only to `com.supernote.document`, and restart the document reader. Supernote
RTL Reader v0.4.12 or newer and Native Spread v0.0.116 or newer are required for
protected editable mode. Its
recovery manifest binds the backup to the PDF's full SHA-256 because
Supernote changes the PDF modification time when the document activity
reopens.

## Annotation trace laboratory

Open an RTL-editable disposable or protected document before starting a trace.
From this directory, run:

```powershell
.\trace.ps1 -Action Start -Label portrait-control
```

When more than one Android device is connected, pin every command to the
Supernote serial, for example `-Serial SN078C10015092`. The script also honors
the standard `ANDROID_SERIAL` environment variable.

Perform one tightly scoped operation. Record named checkpoints after the ink
settles or after a page turn:

```powershell
.\trace.ps1 -Action Checkpoint -Label stroke-1-settled
.\trace.ps1 -Action Checkpoint -Label returned-to-page
```

Stop and pull the complete bundle:

```powershell
.\trace.ps1 -Action Stop
```

The collector places a session directory and ZIP under
`Downloads/SupernoteNativeSpreadTraceBundles/` by default. Pass `-Destination`
to choose another short local path. Each bundle contains `events.jsonl`,
session metadata, changed `.mark` snapshots, checkpoint screenshots, and the
matching `SN_SPREAD_PROBE` logcat capture. Treat the bundle as private document
data. Use the same short operation once in portrait native mode and once in
landscape Native Spread so their event sequences and canonical trail states can
be compared directly. See `TRACE_SCHEMA.md` for the event and fingerprint
contract.

## Hardware validation

v0.0.61 passed on a rooted Supernote Nomad using both a disposable calibration
PDF and a protected copy of a 738-page annotated Hebrew PDF. The real-document
pass confirmed persistent two-page annotation display, outer-edge-only tap
navigation, side-preserving spread turns, and an unchanged `.mark` checksum.

v0.0.82 compiles and passes automated handshake, backup-attestation,
destroyed-activity cleanup, canonical lasso-move, inactive-page ink-merge, and
scale-independent inactive-page eraser invariants, including fail-closed write
handling, full-stroke deduplication, strong recovery-sidecar cache identity, and
operation-aware settled-ink composition, and shared spread-appearance geometry.
The v0.0.78 focused Nomad
eraser regression removed exactly one of two separated inactive-page strokes,
retained the control stroke, left companion page 4 unchanged, and preserved the
result after a spread turn away and back. The full record is in the root
`REGRESSION.md`.
