# Overnight checkpoint — 2026-09-06/07

User authorized autonomous testing/fixes while sleeping, approximately through
2026-09-07 05:30 Asia/Jerusalem. No physical-action requests or audible pings.
The original heartbeat was every 30 minutes until 02:30 UTC and remains paused.
The user has explicitly approved the source/notes-only OpenAI review; this
continuation resumed directly. Do not send PDFs, annotations, firmware binaries
or credentials. Temporary device helpers from the prior segment are gone.
Do not merge or claim physical-pen validation.

## Resumed after explicit review approval — approximately 04:30 local

- Exact 35-file review of `25aa958` completed NOT CLEAN with two supervisor
  findings (unbounded reap after failed kill; stale PID signaling after ECHILD).
- Both fixed in the shared `isolation_supervisor.h`: SIGCHLD normalization,
  waitable-child authority, CAP_KILL preflight, bounded reaping, independent
  five-second child watchdog, uncertain-cleanup failure with exact-path preservation.
- Android build and portable cases pass. Linux: 102 filter runs / 1,428 checks,
  denied-kill watchdog and inherited-SIGCHLD/reaped-PID regressions PASS.
- New build `build/isolation-1b9348304e074db298129cb2807e8185/`, diagnostic hash
  `4775fe42b615970ece06ef49131d440a7fefc0043e432ef9411473438f67099c`.
- Full updated confirmation review is next; no new diagnostic is staged/run.
- Nomad exact USB serial verified. File Manager foreground, asleep, powered,
  battery 100%, Document/DrawPath still 2027/1425, both stock hashes unchanged.
- Existing full viewport/baseline tests reran PASS. A trailing escalated Git
  diff invocation failed due its execution context; standalone local Git
  status/diff-check and packaging test rerun clean.

## Latest continuation — approximately 01:25 local

- New pinned static findings: actual DrawService startup (not the no-op Activity
  method), nested update-worker startup, both Java/native Binder caches, lasso
  Android-Bitmap preview, and painter-retained physical EBC aliases. Erase also
  consumes framebuffer/background data. See `NATIVE_ENGINE_STARTUP.md`.
- Prepared `ISOLATION_PROBE.md` and the generic C diagnostic. No firmware loader,
  Binder proxy, Document launch, physical input or native writer admission.
- Portable tests: 16 sequencing cases, 56,376 actual-filter vectors, 50 mutations.
  Android AArch64/API30 compile and Clang static analysis PASS.
- Existing WSL kali-linux was available; used ordinary UID 1000, not root.
  The translated Linux filter passed 101 kernel child runs / 1,414 checks with
  no descriptor leaks. A post-report stall test protects the parent exit deadline.
  No Linux mount/chroot or Nomad kernel pass is claimed.
- Full prior host viewport/evidence and five baseline suites reran PASS,
  including 85,407 v2 assertions / 271 mutations. No commands remain running.
- Latest Android build `build/isolation-15a4b0ff6c874a8c8d9c99b945f699f5/`;
  `isolation_probe` SHA-256
  `01aa3493218f3ab8be23e1d5c7c923b64b59635b46b5ddaf23845f649031a28a`.
  Never staged on the tablet. Source/build files remain separate from production.
- Final read-only ADB check: exact Nomad connected, File Manager foreground,
  Document PID 2027, both stock fixture hashes below unchanged. No new device
  modifications, native hooks, input generation, package changes or pen activity.

### Earlier explicit blocker (now resolved by the user's approval above)

The external Codex review request for five architecture/evidence notes was
rejected before execution. The provider was then verified as OpenAI from local
configuration/existing logs; a fresh narrower review of seven generic authored
source/build files, with all internal notes/history excluded, was ALSO rejected
before execution for lack of specific payload-disclosure approval. No r3/new
source review ran. Existing r2 clean review does not cover this new diagnostic.

Ask the user when they return whether the diagnostic source and authored
architecture notes may be sent to OpenAI's Codex review service, excluding PDF,
annotation data, firmware binaries and credentials. Do not silently retransmit,
delegate around the rejection, install/run the unreviewed diagnostic, or claim
an independent review pass. Local source-only snapshots are preserved in
`inspection/native-reader/reviews/native-viewport-engine-boundary-20260907-r3`
and `inspection/native-reader/reviews/isolated-process-source-only-20260907`.

After approval: prepare one exact complete current-source review, fix accepted
findings and rerun relevant host checks. Only a clean source review admits the
bounded isolation mechanism device test, with exact Nomad/ownership/cleanup
checks. Even a successful mechanism test will NOT admit a native engine or
Document writer: native startup virtualization and canonical background/output
coupling still require the next bounded proof. Do not restart the old spread
overrides or repeat completed stock/display/grab gates for duplicate evidence.

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
