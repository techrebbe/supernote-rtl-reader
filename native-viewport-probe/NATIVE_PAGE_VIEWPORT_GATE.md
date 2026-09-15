# One genuine native page in an arbitrary viewport

Status: visual feasibility passed on the pinned Nomad on 2026-09-14; see
`NATIVE_PAGE_VISUAL_HARDWARE_20260914.md`. A fully retained and independently
bound visual/session gate, plus the physical-pen, native-tool, persistence and
graph-identity portions, remain open. This is not yet a writable native
viewport, two-page reader, production package or release candidate.

## Question this gate answers

Can the one real stock Supernote `DocumentActivity` keep one source page, one
presenter, one note, one history/save owner and the canonical 1404 x 1872 native
canvas while only its outer presentation moves between FULL, LEFT and RIGHT
rectangles?

This gate deliberately does not ask whether the physical pen can write in those
rectangles. DrawPath reads the Wacom device and writes the physical EBC planes
outside Android's `SurfaceView`; a correct-looking page is not proof of coherent
input, wet ink, erasing or saved geometry.

## Pinned device/session facts

- Authorized hardware: Nomad `SN078C10015092` only.
- Firmware fingerprint:
  `Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys`.
- Native reader: `com.supernote.document` 1.02.446 / versionCode 102446,
  installed at `/system_ext/app/SupernoteDocument/SupernoteDocument.apk` and
  running as Android system UID 1000.
- Native component:
  `com.supernote.document/.document.DocumentActivity`; the observed firmware
  reports `launchMode=2` (`singleTask`) and a resizable full-screen task.
- Stock canonical display: 1404 x 1872 at 300 dpi.

These observations are prerequisites, not reusable process/task identifiers.
Every run recaptures PID, starttime, task, display and file identities.

## Single ownership boundary

Supernote remains the sole owner of:

- `DocumentActivity`, `DocumentViewModel`, `HandWritePresenter` and
  `SuperNoteNote`;
- current source page and `PageInfo`;
- native Binder client, Undo/Redo history and save/`.mark` authority;
- canonical page dimensions and annotation coordinates.

The diagnostic owns only:

- one fixed 1404 x 1872 `VirtualDisplay`;
- one physical presentation rectangle;
- one random session token, display generation and sticky lifecycle state;
- read-only observation and exact cleanup evidence.

The root-side supervisor owns only the exact non-exported activity launch/task
placement, the bounded physical-pen exclusion lease and teardown. It never
writes `.mark`, programs page/writer geometry or invokes a drawing operation.

## State machine

```text
DORMANT
  -> PRECHECKED
  -> PEN_BLOCKED
  -> DISPLAY_READY
  -> ONE_NATIVE_TASK_BOUND
  -> OBSERVED_FULL
  -> OBSERVED_LEFT
  -> OBSERVED_RIGHT
  -> OBSERVED_FULL_AGAIN
  -> NATIVE_TASK_DESTROYED
  -> DISPLAY_RELEASED
  -> STOCK_REOPEN_VERIFIED
  -> CLEAN
```

Any identity change, unexpected page/configuration event, surface loss,
deadline, helper death, task migration, extra reader task, pen-lease loss,
storage change or incomplete cleanup enters sticky FAILED. There is no automatic
retry. The pen lease stays held until the foreign task and display are gone or
a controlled reboot is required.

## Phase 1: timeout-bounded physical-pen exclusion

Before creating or moving a native task, a separately reviewed native helper:

1. opens only `/dev/input/event7` with no symlink following;
2. verifies character-device identity, `Wacom-pen`, exact axes and required pen
   capabilities;
3. requires pressure, tool, buttons and hover state idle;
4. acquires `EVIOCGRAB` and proves a second descriptor is excluded;
5. holds the lease without reading, logging or replaying coordinates;
6. releases on the authenticated control close, signal, parent loss or one
   absolute deadline; and
7. proves the exact device can be acquired again after cleanup.

Android touch consumption is not accepted as a pen interlock.

## Phase 2: one native task, visual-only

The separate `native-page-host` creates a PUBLIC, OWN_CONTENT_ONLY,
DESTROY_CONTENT_ON_REMOVAL virtual display. It never executes root commands or
launches another app. The supervisor then uses the pinned component and a
disposable allowlisted PDF:

```text
am start --user 0 --display <verified-nonzero-display>
  -f 0x10000000
  -a android.intent.action.VIEW
  -n com.supernote.document/com.supernote.document.document.DocumentActivity
  --es file_path <disposable-pdf>
  --ei page <zero-based-page>
```

Because the reader is `singleTask`, an existing stopped task may be reused. The
result is admitted only if exactly one Document task/activity exists, it is on
the requested non-default display, it runs as normal UID 1000, and its exact
file/page/session identities match. A second task, a task retained on display 0,
or an unexpected existing document is failure.

No finger or pen input is forwarded into the virtual display. No page turn,
link, destination, tool command, save or history operation is allowed.

## Phase 3: presentation-only placements

The virtual display and native activity remain 1404 x 1872 throughout. Only the
host `SurfaceView` rectangle changes:

| Placement | Physical rectangle |
| --- | --- |
| Portrait FULL | `0,0,1404,1872` |
| Landscape LEFT | `0,78,936,1248` |
| Landscape RIGHT | `936,78,936,1248` |
| Landscape centered FULL | `409,0,1053,1404` |

Each transition is bound to the live random session token. A placement command
cannot change display generation, native configuration, page, presenter, note,
history, Binder or saved data.

## Read-only evidence at every placement

The observer captures two matching samples of bounded scalar/object identity:

- activity, task, display and process/starttime;
- source URI/path, page index/count, ViewModel and `PageInfo` identity;
- page CTM/inverse, offsets, CropBox and bitmap dimensions where pinned field
  authority exists;
- presenter page, mark path, native rotation, note/client/Binder identities;
- background, committed-handwriting and digest layer identities where safely
  readable;
- DrawPath process/starttime and its separately pinned scalar geometry.

Missing, changing, ambiguous or nonfinite evidence is failure. Screenshots are
secondary evidence for exact corners, aspect, crop, existing saved ink, digest,
links and chrome. Expected placement geometry is computed independently of the
host implementation.

## Teardown

1. Keep the physical pen lease held.
2. Destroy the exact foreign Document task while the virtual display remains
   valid; do not move it to display 0.
3. Require the host to acknowledge that the foreign task is absent.
4. Release the virtual display and prove no task migrated to display 0.
5. Prove no helper/display/task remains, then release and independently reacquire
   the pen device.
6. Reopen the disposable fixture in the untouched stock reader on display 0.
7. Re-run the SavedInk collector/oracle and verify the native records, PDF and
   `.mark` are unchanged.

Unexpected host loss relies on DESTROY_CONTENT_ON_REMOVAL, but that behavior is
itself a hardware gate. If exact cleanup cannot be proved, preserve evidence and
require a controlled reboot rather than guessing.

## Pass criteria

- Exactly one native reader activity and page authority exists throughout.
- FULL/LEFT/RIGHT/FULL changes only outer presentation.
- Native canvas/configuration, page, presenter, note, Binder, history and layer
  identities remain exact.
- PDF, `.mark` and complete SavedInk native records remain unchanged.
- Existing content, saved ink, digest, links and chrome share one exact affine
  presentation with no crop or stretch.
- The pen lease survives every active phase and releases under normal and
  injected-failure cleanup.
- No reader task migrates to display 0, and ordinary native reopening is
  unchanged.

Any page reload, configuration change, component replacement, save/writer event,
crop/stretch, unexpected task migration, annotation difference or uncertain
cleanup fails the gate.

## Explicit exclusions

Do not reuse the earlier competing-authority mechanisms:

- `programPageGeometry()` or `programWriterGeometry()`;
- Binder transaction-10 geometry replacement;
- synthetic `screenRotation(... + 2000, ...)`;
- inactive-page bitmap composition or page-activation transactions;
- `.mark` merging, copied histories or direct sample-coordinate rewriting.

`ViewportFrame` remains a mathematical oracle only. Passing this visual/session
gate still does not authorize a physical stylus. A later separately reviewed
gate must bind transformed input, every DrawPath wet-ink/erase output alias,
background pixels, refresh calls and both native Binder clients to the same
canonical page before the first user stroke.
