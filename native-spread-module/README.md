# Supernote Native Reader v2 companion module

This LSPosed module supplies the rooted native-reader enhancement controlled by
Supernote RTL Reader. v0.0.140 is a pre-hardware, exact-firmware candidate. It
opens the original PDF and keeps Supernote's own writer, links, text tools,
highlights, and page-local `.mark` annotation data while adding:

- RTL page progression in portrait;
- automatic two-page RTL spreads in landscape;
- optional separate-cover parity;
- per-document opt-in through a hidden authenticated `.snspread-v3` journal;
- protected per-document editing backed by a verified annotation recovery snapshot.

The v0.0.135 experimental `SpreadProbe` and native interception source are
retained only as hash-pinned forensic evidence. They are not compiled or
packaged. v2 uses one live native writer page, one isolated read-only adjacent
projection, and a witnessed save/disable/load/verify/publish transaction to
move writer authority. The implementation never edits `.mark` bytes directly.

## Compatibility and safety

The module intentionally refuses to operate unless all of these match the
hardware-tested environment:

- firmware fingerprint
  `Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys`;
- `SupernoteDocument` version code `102446`;
- document APK length `138486560` bytes;
- LSPosed scope limited to `com.supernote.document`;
- an authenticated committed journal record beside the current PDF.

The current authority is a fixed-size, two-slot journal. After one exclusive
initial creation, PluginHost publishes every transition by fixed-offset writes
to the same inode; it does not rename or delete the journal. The Document
process fail-closes on a torn or malformed slot and reports the exact path,
generation, record digest, state, and activation token back to PluginHost as
the transition acknowledgement. A valid v3 OFF record safely supersedes any
preserved legacy `.snspread` file.

An acknowledgement worker is isolated per request, authenticates the live PDF
bytes, and rereads the exact journal after the PDF hash. An expired or blocked
worker can therefore be retired without occupying the admission executor, and
an acknowledged OFF record triggers a fresh admission attempt for the still
open document.

The original recovery snapshot is immutable rollback evidence. A successful
dirty Supernote save instead advances a separate
`.snspread-live-mark-v1` checkpoint whose exact field set binds the original
PDF, backup manifest/snapshot, and current live `.mark`. The checkpoint is
published atomically while the process-shared writer lease remains valid, with
a descriptor-pinned FUSE-safe parent directory. A durable `.pending` sibling is
published before the checkpoint path changes, contains the same exact bound
intent, and remains through the final live-mark, lease, generation, and
checkpoint checks. Its presence blocks ordinary cold admission. After a crash,
the next exclusive writer-lease owner can finish the publication only when the
pending record, published checkpoint, live mark, PDF, and immutable recovery
evidence agree exactly. If explicit recovery already restored the immutable
baseline, the obsolete checkpoint is removed before its pending fence. Every
other pending shape remains fail closed. Cold admission accepts a live mark
that differs from the
rollback baseline only when this persisted witness matches exactly. Empty
regular `.mark` files remain valid and distinct from an absent mark.

Normal Document-process admission never uses an older valid slot when its peer
is malformed. The plugin may classify exactly one valid slot plus one malformed
slot only for an explicit, verified annotation restore after stopping the
Document process. It overwrites the malformed slot with a higher-generation
RECOVERY record on the same inode; this classification is not an authorization
path, and every other malformed shape remains non-repairable.

## Archived experimental engine history

The remainder of this version-by-version section describes the retired
v0.0.75-v0.0.135 `SpreadProbe` experiment. It is retained to preserve the
hardware evidence and design lessons that informed v2; none of these legacy
hooks are executable in the v0.0.140 package. The authoritative current v2
behavior is the architecture and compatibility contract above.

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

Trace startup failure now cancels pending work and stops any created file
observer. If failure occurs before `active.txt` is durably published, the
unpublished pointer is cleaned up. Once `active.txt` has been published, the
exact failed session remains guarded by `active.txt`, `incomplete.txt`, and
`publication-failed.txt`; the desktop helper therefore cannot fall back to an
older successful `last.txt` or mistake the failed startup for a completed
trace.
An `active.txt` left by a killed document process is reconciled by every desktop
trace-helper action. The helper compares the session's recorded PID with the
live Supernote document PID. `Status` reports the abandoned session while
retaining `active.txt`, preserving its identity across helper invocations.
`Stop` atomically moves that exact pointer into a recovery directory, verifies
its filesystem identity and exact contents after the move, and archives the
verified pointer alongside the retained partial directory without publishing
the session as completed. If another pointer replaces it between validation
and the move, the replacement and recovery directory remain guarded for
explicit operator recovery. Every non-status action blocks while that guard
exists, so an older trace from `last.txt` cannot be substituted or pulled.
Finalization retries an unstable stop-time `.mark` hash/copy up to five times.
Only a stable, SHA-256-verified snapshot can publish `last.txt`. Exhausted
retries retain the exact recording pointer, publish `incomplete.txt` plus
`publication-failed.txt`, retain the partial directory, and cause `trace.ps1
Stop` to report the failed session without substituting an older trace.
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
pointer. Completed publication is a single same-directory rename from
`active.txt` to `last.txt`; the event stream has no independently published
success terminal that can disagree with that commit. A pointer-write failure
after active-pointer publication retains the exact session in `active.txt`,
`incomplete.txt`, and `publication-failed.txt`, and makes `trace.ps1` refuse the
preceding completed session. A pre-publication failure cleans up only its
unpublished pointer attempt.
An undeletable stale `incomplete.txt` also enters this fail-closed publication
path instead of overriding the new completed pointer.
The desktop helper validates the exact bytes of every pointer rather than
trimming them, validates one exact numeric owner PID from regular session
metadata, and distinguishes `pidof`'s explicit no-process result from an
unknown command or transport failure. Any ambiguity retains the guard and
blocks mutation or fallback. Checkpoint screenshots are first staged outside
the remotely published session directory, then merged into the local bundle
only after completion identity is revalidated.

v0.0.118 begins the transactional single-active-page release line from stable
v0.0.116. The two-page landscape image remains a visual composition, while one
and only one page owns Supernote's native reader page, handwriting presenter,
DrawPath, Undo/Redo stack, and `.mark` persistence. An inactive-page tap, hover,
page turn, or explicit activation saves the source natively, disables the
writer, loads the target through `DocumentViewModel.loadPage()`, verifies both
reader and presenter identity, and commits only after target-only spread
geometry is installed.

The pen-position hook rejects an inactive-page trigger before the native writer
sees its first coordinate. Hover may finish activation before contact. If the
pen arrives too quickly, the entire trigger gesture is blocked through pen-up;
the target remains active for the next stroke. A unique transaction token binds
completion and timeout work, permits one reload retry, and fails closed rather
than falling back to manual `.mark` merging. v0.0.117's inactive-page
capture/normalize/merge experiment remains available only on its preserved
branch.

Editable authorization is protocol 2 and has two durable states. A `pending`
marker records the activation token, complete recovery identity, intended
transition, and byte-exact previous marker; it never authorizes native writing.
Only an atomically published `committed` marker is accepted. Failed activation
archives the verified recovery baseline into token-bound, self-contained files
before restoring the previous marker. Explicit retry resumes or reconciles
partial archive stages, while ambiguous evidence fails closed without mutation.
Read-only and Off transitions are also pending-journaled before recovery
retirement, so a process death cannot silently lose the protected baseline.

v0.0.119 corrects the firmware's regular vector-eraser coordinate mismatch in
Native Spread. The regular eraser operation arrives with half-page
`932 x 1243` redraw dimensions while the active canonical trails use
`1872 x 2496`. The native wrapper substitutes the canonical dimensions only
when the operation also has the exact regular-eraser pen type and color, calls
Supernote's original eraser once, and restores the original fields immediately.
The established grid eraser path is unchanged. Native eraser readiness is
published only when both firmware symbols have been hooked successfully.

v0.0.120 is the deep-review hardening candidate. Hook installation now uses
atomic attempted/installed state and publishes callable originals only after a
zero result with a non-null backup. An ambiguous installer result remains
fail-closed and is never installed again. Document startup distinguishes a
fresh process from a proved sequential document switch, delayed refresh work
is bound to exact document/component identity, and canonical reloads require an
acknowledged native save plus current authority in lifecycle-safe lock order.
All previously weak cross-thread activity maps are synchronized.

v0.0.121 corrects the transactional marker admission contract found during the
first hardware gate. A committed marker may declare any minimum companion
version from the oldest supported transactional protocol through the currently
installed module, rather than being restricted to one historical value. The
reserved calibration filename uses its automatic disposable mode only while no
authority artifacts exist; a verified protected marker now follows the same
validation path as every other document.

v0.0.122 keeps the lasso polygon out of the active-pen canonical save/reload
path. Supernote's native selection buffer therefore remains authoritative while
the selection floats, instead of the persistent `.mark` bitmap resurrecting
the selected source trail underneath a moved preview. The trace helper also
archives an abandoned pointer by atomically renaming the verified pointer file
into a separately created archive directory. This avoids the `Bad address`
failure produced when Nomad shared storage is asked to rename the recovery
directory itself; the empty recovery guard is removed only after the archived
file's identity is revalidated.

v0.0.123 restores the ordinary active-page header after a completed annotation
trace. An incomplete or failed stop instead leaves an explicit recovery warning,
so the on-screen status can no longer continue to claim that recording is active
after the durable `active.txt` guard has been retired.

v0.0.124 binds an accepted lasso selection to the exact immutable writer,
document, page, presenter, and configuration epoch that admitted it. Native
lasso drag/dismiss contacts bypass the ordinary handwriting-contact timeout;
the transition and final rewrite remain fail-closed unless that exact selection
authority is still current. This fixes moved ink disappearing when a selection
was dismissed more than 15 seconds after its drag began.

v0.0.125 corrects the remaining move geometry and UI lifecycle. Supernote pads
small lasso selections into a 180-pixel square; the module now converts the
centered ink bounds rather than that frame's top-left and retains the original
canonical width and height. It replaces Supernote's thinned drag bitmap with an
exact copy, so thin strokes remain visible while moving, and completes the
immutable selection authority after a successful native move transition as
well as after an unmoved rewrite.

v0.0.126 contains every behavior-changing hook behind an exact, verified
per-document Native Spread control claim. The audit was prompted by a native
highlighter regression that reproduced on ordinary documents whenever the
LSPosed module was installed. The earlier fail-closed owner logic treated a
missing or stale component binding as authority to suppress the firmware call,
even when no document had opted in. Ordinary callbacks now delegate unchanged;
ordinary activity startup and teardown do not enter Native Spread lifecycle
locks or JNI writer-gate paths; configuration discovery cannot arm hardware
without a claim; and returning to Off restores the firmware writer state. The
two native eraser detours remain installed for the target firmware, but their
disabled path calls the original function exactly once with unmodified
arguments and returns its original result.

This is firmware-specific experimental software for a rooted device. Back up
documents and `.mark` files before testing a new firmware or module revision.

## Build

Requirements:

- JDK 17 with `javac` and `jar` on `PATH`;
- Android SDK platform and build-tools 35.0.0;
- an Android signing keystore for signed builds.

`build.ps1` reads `ANDROID_SDK_ROOT` or `ANDROID_HOME`. Paths can also be passed
explicitly:

Create the deterministic unsigned/aligned APK without selecting a signing
identity:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1 -AlignedOnly
```

A signed build must explicitly bind the selected keystore to its reviewed
certificate digest. The repository does not assume that a contributor's
ordinary Android debug key is the protected upgrade identity:

```powershell
$expectedSigner = 'a5a8551131de84d41660a3cf22d224f320f7a2f05a380282f76f6fe731807c67'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1 `
    -ExpectedSignerSha256 $expectedSigner
```

The example digest is the established upgrade identity for this repository's
owner-controlled release key. A contributor using another key must pass that
key's own reviewed, separator-free lowercase certificate SHA-256; the resulting
APK is not upgrade-compatible with the project release.

The signed APK is written to `build/artifact/`. Pull-request CI uses a
disposable, runner-local debug identity only so `build.ps1` can compile,
package, and verify the APK; it does not upload that non-upgrade-compatible
build. Trusted `main` pushes—and repository-owner manual runs of the exact
`main` ref—restore the repository's stable signing identity from an encrypted
Actions secret and publish the verified upgrade-compatible APK as
`supernote-native-reader-v2-v0.0.140`. Review branches never receive that
credential.

## Install

Install the APK, enable **Supernote Native Reader v2** in LSPosed, scope it only
to `com.supernote.document`, and restart the document reader. The v0.0.140 APK
requires Supernote RTL Reader v0.4.23 and refuses every other companion
contract version. Stylus contacts that
begin inside the current visible native toolbar, page bar, selection menu, or
popup are passed to Supernote for that exact gesture without publishing a
handwriting owner or consulting page/writer authority. Only malformed or
mismatched streams are blocked. Contacts that begin on the document retain the
normal Native Spread route even if they later cross visible chrome. The same build finalizes
a moved lasso selection under canonical page authority before restoring the
spread origin, so the persisted layer bitmap and native vector paths advance
together. Native text-selection contacts on the active page are likewise
gesture-scoped: Supernote's native handwriting selection engine remains enabled
while ordinary Native Spread handwriting and activation ownership ignore that
exact contact. The module also holds Supernote's native page-turn gate closed
for only that selection gesture and restores its previous value after the
native reader processes pen-up/cancel, allowing `checkSelectText` to receive
the full highlight/underline stream without leaving navigation disabled.
v0.0.135's contact classifier also handles Supernote's early digital pen-down
ordering: when that signal immediately precedes the authoritative Activity
DOWN for the same otherwise-unowned selection gesture, it is atomically
adopted into the text-selection token instead of being misclassified as
ordinary handwriting. Native-first callbacks and genuinely competing contact
owners remain blocked. Its
recovery manifest binds the backup to the PDF's full SHA-256 because
Supernote changes the PDF modification time when the document activity
reopens.

Recognized straight lines use a distinct two-stage native transaction.
Supernote enters `EditLineView` before the physical pen lift; Native Spread
therefore retains the exact document, writer, page, destination, and native
split-offset authority until `onEditLineTransition`. Live editor points are
mapped into the physical active-page slot, final points are mapped back into
Supernote's split-local frame, and only a successful native transition can
trigger the canonical save/reload. This prevents a held short horizontal line
from jumping into a long diagonal while leaving ordinary pen strokes on their
existing path. The editor and commit hooks also reject a missing or stale
recognized-line transaction while editable spread mode is active; they never
fall through to Supernote's unremapped native line editor after authority loss.

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

The v0.0.119 regular-eraser regression passed on the disposable calibration PDF
in an active-left spread. The erased gap survived an active-side round trip and
a cold document-reader restart. The canonical `.mark` after the erasure and
after cold reopen had the identical SHA-256
`9a61d949f6437a0f55986ba85b5797ba2e01743e46402607faefe351fcd211dd`;
the captured trace reported no potential failures. The first contact after a
document-process restart remains subject to the existing fail-closed
document-context quarantine and may be deliberately discarded.
