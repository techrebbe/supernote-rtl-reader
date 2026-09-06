# Overnight checkpoint — 2026-09-06/07

User authorized autonomous testing/fixes while sleeping, approximately through
2026-09-07 05:30 Asia/Jerusalem. No physical-action requests or audible pings.
Heartbeat `prepare-next-native-viewport-tests` is active every 30 minutes until
02:30 UTC. Preserve a checkpoint and restore temporary device changes before
pausing at the deadline. Do not merge or claim physical-pen validation.

## Working boundary

- Worktree: `inspection/native-reader/prototype/supernote-native-viewport-probe`.
- Branch: `agent/native-single-viewport-probe`; starting HEAD `ba9134094656ea1d6608a77cfa8a12ec0467206f`.
- Preserve the separate older dirty `supernote-rtl-reader-pr22-upload` worktree.
- Gate A display-only substrate already passed; do not repeat its hardware suite.
- Gate B genuine native page/pen viewport is NOT ready. No second live page.
- Original PDF/native annotations remain authoritative. Never work on personal
  documents. Do not restart the discarded competing page/tool-offset architecture.

## Device state at 00:00 local, revalidate before reuse

Only Nomad `SN078C10015092` is authorized. File Manager is foreground; native
Document was gracefully closed. Document PID 2027 and DrawPath PID 1425 remain
alive; PIDs must be revalidated. Companion v0.0.140 remains disabled in LSPosed;
plug-in v0.4.23 is unchanged. No calibration APK or helper is running. Orientation
is restored to automatic. Existing Frida server is loopback-only; no script is
currently attached. No production package has been built or installed this turn.

The only stock fixture is `/storage/emulated/0/Document/NativeViewport-Stock-20260906.pdf`:

- PDF SHA-256 `e470c33c6525e02acf88e51352d73b7ed8b6c1591be8d40629a42c708484e720`
- `.pdf.mark` SHA-256 `b95c02b05abd9a4f5a3106ffbe442f1f893256a66f8cac3628f04d300992ffd6`

## Completed this turn

- Read-only native buffer observer, with 34 executable closed-mock cases.
- Independent source-only r1 review clean; observer ran and detached safely.
- Confirmed DrawPath's three cached pen planes all target physical `/dev/ebc`,
  not the Android VirtualDisplay. Detailed ABI/hashes: `NATIVE_PEN_BOUNDARY.md`.
- 280 viewport / 45,459 display assertions, 15 Python tests, Android javac and all
  five repository baseline suites passed (85,407 v2 assertions; 271 mutations).
- Prepared an instantaneous EVIOCGRAB mechanism proof, not a held interlock.
  No event replay, pixel writes, native hooks, document launch or annotation edits.
- NDK 27.0.12077973 AArch64 API30 build passed with warnings treated as errors.

## Completed mechanism operation

Independent full-subset r2 review completed CLEAN using the existing reviewer:
`inspection/native-reader/reviews/native-viewport-pen-boundary-20260906-r2-review.log`.
The source-only snapshot is its sibling `...-r2` directory (29 files).
No review is pending for this subset. All 29 reviewed source files matched
before the device run; subsequent changes are this checkpoint and evidence docs.

Built and hardware-run:
`build/pen-5ff34cfb4df64c03943dc499d980239e/`

- `pen-device-probe`: `c280995392cd261b45ebf545c716991c8a2d4a9f33e6a9a13b3edbee5e99226a`
- `pen-grab-core-test`: `611b5526d10bba90a30e1afd64c4e5c90074a6716c55abf0f3b760e34a38acbe`

At about 00:06 local: 18 fake-operation core cases PASS as UID 2000; real root
`--inspect-idle`, `--prove-exclusive-idle`, and post-proof `--inspect-idle` all
PASS. Foreground/PIDs/fixture hashes were unchanged. Exact temporary directory
`/data/local/tmp/native-viewport-pen-probe-20260907a` and its two helpers were
removed, with absence confirmed. Local evidence is `build/pen-boundary-20260906/`.
Do not repeat this completed hardware mechanism proof.

Success proves acquisition/release only. It does NOT protect a later Document
launch. A held barrier requires separate lifecycle/queued-contact/recovery proof.

## Further useful autonomous work

Trace Document's lasso buffer producer and DrawPath output/refresh ownership,
then implement/test one coherent canonical-canvas adapter boundary. Android
MotionEvent interception alone is not a raw-pen interlock. Do not enable native
writing on an arbitrary viewport before these authorities agree.

Local read-only disassembly found `SnCommon::init_layer_cimage` calls
`rattaCreateImage`; its CIMAGE descriptor is 24 bytes with width/height at 0/2,
stride at 4, data pointer at 8, channels at 0x10. Allocation delegates to umalloc.
This is a lead, not yet evidence about live lasso output. Preserve canonical
page dimensions: `MOVEOBJECT::begin2ShiftTrails` contains geometry rescaling.

Final morning handoff must distinguish automated/static/mechanism passes from
remaining actual stylus checks (write, both erasers, history, lasso and text
selection in each validated frame, then saved-geometry/native-reopen checks).
