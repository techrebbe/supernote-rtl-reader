# Bounded native display experiment — not a replacement reader

## What was learned before implementation

The pinned Document application uses a fixed 1404 x 1872 canvas on Nomad,
independently of its actual Android view bounds. Its pen service also has a
separate geometry producer. Reparenting one view or applying an arbitrary scale
to saved EMR samples is not a coherent integration boundary.

Local static inspection of pinned DrawPath `librecgnition.so` SHA-256
`3ce8bcf151e92899cb06c64e529723c560718aea36f070761c4ee9fe99bd57e2`
found `g_docFactor` consumed by
`changeRawRightUpZeroTrailContainerAxisOrigin(TrailContainer&,int,int,int,int,int,int,int,int,float)`.
In this exact binary, the path at virtual address 0xfe880 compares the factor
with a constant near 4/3, then conditionally multiplies points by a fixed 4/3.
This is NOT a general affine scale implementation. Do not set that field to
2/3 and treat it as a verified viewport adapter. The remaining integer
screen/total/origin fields affect normalization separately. Their semantics
must be proved, including native metadata, not inferred from screenshots.
Document's native library also exports `MOVEOBJECT::cacheUpdate2framebuff`.
That is evidence to investigate direct drawing during lasso, not proof that
an Android surface captures every native pen operation.

Read-only Nomad query on 2026-09-06 confirms
`android.software.activities_on_secondary_displays`. No device state changed.

## Implementation now prepared

`display-host/` is a separate, **display-only** Android probe, not an LSPosed
module, reader upgrade or PDF conversion. Its package is
`com.techrebbe.supernote.viewportdisplayprobe` (version 2, display-only).

It owns only:

1. One Android `VirtualDisplay`, fixed 1404 x 1872, with physical display density.
2. One fixed-size `SurfaceView` presenting that display in FULL / LEFT / RIGHT.
3. One independent, non-exported calibration activity admitted on that display
   only after an explicit host-side root launch bound to the live display/instance.
4. Explicit display-generation/lifecycle diagnostics and release of its resources.

It does **not** own a native page, presenter, note, history, save, pen engine,
PDF, mark, toolbar route or annotation transform. No Document launch is included.
It cannot claim a native viewport pass. The calibration activity independently
checks the actual display ID and reports its measured canvas rather than
asserting success because a launch request returned.

The landscape 1872 x 1404 host presents a 936 x 1248 buffer at y=78 in either
half. Integer sizes preserve the buffer's exact 3:4 aspect ratio. Portrait
presents full-size when the host is 1404 x 1872. Physical rotation/placement
does not resize the virtual display or recreate its activity.

It requests OWN_CONTENT_ONLY explicitly: accidental screen mirroring must not
look like a successfully hosted native page. It does not request the presentation
category, preventing automatic participation by presentation-aware apps.

Surface loss stops this experiment and requires an explicit restart; it never
automatically opens another document or restores a previous successful state.
Any Android-restored host instance starts STOPPED, including after unhandled
configuration changes. Close and reopen the probe explicitly to start a new
experiment. Its tested admission state has no automatic reset transition.
The controls can be hidden with a finger, exposing all four target corners;
finger-tap the calibration image to show them again. Failure forces them visible.
The unsigned build uses fresh output directories and cannot be mistaken for
the installed Native Reader v2 APK. It contains neither the saved-ink collector
nor native firmware libraries. Source-only review and package inspection precede
any signing/installation. No credential upload is involved.

### Observed launch admission and scoped root bootstrap

On 2026-09-06, the reviewed v1 package created display 1 at 1404 x 1872,
300 dpi, but Android rejected its ordinary app-owned calibration launch with
`SecurityException` / `launchDisplayId=1`. It released the display and reported
UNAVAILABLE. No calibration or native-reader hardware pass occurred. The host
was closed and the temporary package removed. Original orientation settings,
Document PID and disposable stock fixture PDF/mark hashes were unchanged.

Version 2 performs no activity launch itself and executes no root commands.
It reports `WAIT_ROOT_CALIBRATION` with its current display ID and instance UUID.
The authorized host operator may launch ONLY this exact non-exported component
through an explicit `su -c 'am start ...'` command, with `--display` and
`--ei expectedDisplay` both set to that observed ID, and `--es instance` set to
that observed UUID. Use NEW_TASK | MULTIPLE_TASK (`-f 0x18000000`). Never launch
Document or another app as part of this calibration step. The calibration checks
its actual display and live owner before admitting itself; wrong/stale values
finish the calibration task without claiming success. Attachment is logged
separately from its actual measured size. No security setting, export restriction,
system binary, platform signing key or native reader module is changed.

The reviewed v2 calibration gate now passes; see [the evidence](DISPLAY_HARDWARE.md).
Duplicate/stale launches and both calibration/host cleanup paths were tested.
Use launch without `-W` for negative cases: Android's waiter can remain blocked
after a deliberately rejected activity finishes. Native Document and pen
integration are still separate, unimplemented gates.

## Gates — each answers a separate question

### A. Display substrate (automatable; no user pen actions)

- Separate calibration activity really has a non-default display ID.
- Its own canvas remains 1404 x 1872 in FULL, LEFT, RIGHT and after rotation.
- All four corners, axis labels and circle appear correctly; no crop/stretch.
- Placement changes retain the same display/task, not a bitmap screenshot.
- Close releases the display/task. A lost surface cannot advertise readiness.
- Native Document process, live PDF/mark and disabled module remain unchanged.

**Fail:** unsupported launch, default-display fallback, unexpected dimensions,
crop, display loss, process/data side effect. Do not respond by distorting the
buffer or adding a silent screenshot fallback.

### B. One genuine native Document activity (not implemented yet)

Only after A passes, gracefully close stock Document and verify no second live
reader remains. Prepare a separate disposable fixture copy. On this rooted
firmware the DocumentActivity is non-exported and `singleTask`; a generic
ACTION_VIEW chooser or a second Activity does not establish correct ownership.
Use an explicitly verified root/native-UID launch on the host display and
observe its actual task/display/presenter/note identities before any pen input.
Never disable Android export restrictions globally or launch arbitrary user files.

Keep stock Document layout, original PDF, current page, native tool/history/save
methods intact. Investigate the pen boundary at
`HandWriteClient.sendAddressRecognitionMode`, its app-scoped Binder transaction
10, native `screenRotation`, disabled-area publication, and direct framebuffer
draws. Do not repeatedly override/restore independent tool-specific offsets.

The decisive question is whether ALL native visual and input consumers can use
one canonical canvas plus one display transform. The direct pen service bypass
must be resolved before enabling writing. If that requires a lower-level adapter,
implement/review that explicit boundary first; a pretty native page is not PASS.

**Important:** consuming Android MotionEvents does not block DrawPath. This host
is NOT a handwriting-safety interlock for an externally launched Document.
Do not manually place Document on it and begin writing. The current calibration
test runs only after a graceful native close and uses no pen actions.

### C. Native tool/persistence batch (only after B is implemented and reviewed)

One page, one note, one presenter, no switching between live pages. Run one
5–10 minute batch in each half: ink, both erasers, Undo/Redo, lasso move/resize/
commit, text selection/highlight. Capture at operation boundaries and analyze
afterward. Validate untouched-reader reopen plus complete native saved-record
meaning and geometry with the existing diagnostic. Do not repeat the stock suite.
Only after this passes may a second viewport and writer-focus gate begin.

## Retained work and release boundary

Retain the prior native-reader and Virtual Spread worktrees, all stock evidence,
reviewed ViewportFrame/ink oracle, and diagnostic read helper. This experiment
does not replace frozen InkBridge contracts or alter any production APK.
The prior competing-page-state mutators remain disabled. The temporary v1
display-only installation was removed after its failed launch gate. No production
installation or PR is included in this preparation step. No merge without the
user decision.

## Android references

- [Own-content virtual displays](https://developer.android.com/reference/android/hardware/display/DisplayManager#VIRTUAL_DISPLAY_FLAG_OWN_CONTENT_ONLY)
- [Activity launch on a selected display](https://developer.android.com/reference/android/app/ActivityOptions#setLaunchDisplayId(int))
- [Fixed SurfaceView buffer dimensions](https://developer.android.com/reference/android/view/SurfaceHolder#setFixedSize(int,%20int))

These establish Android API behavior, not Supernote pen-service compatibility.
