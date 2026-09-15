# Native loader preparation — no engine admitted

2026-09-07, resumed from source `68b57c108d1dd67a0cb4dbe0380c374c1f18fee4`.
These records combine read-only device evidence with host parsers and authored
loader fixtures. The host loader harnesses execute only authored fixture
libraries. The completed SavedInk hardware gate did load and initialize the
pinned firmware's isolated, read-only mark path in its own ordinary-shell
process; it did not start or attach to DrawPath, admit a writer, install a native
viewport, or mutate handwriting.

## Current status — ordinary-shell SavedInk collector hardware gate PASS

The corrected no-bootstrap SavedInk collector passed its 2026-09-11 Nomad gate
on `SN078C10015092`. It ran as exact ADB-shell UID/GID 2000; root was used only
to prepare and revalidate the protected read-only disposable input. Two separate
collector processes produced byte-identical 15,866-byte frames with SHA-256
`19ad6004ada5e8a92b994f0b9f3b5fbd78ccc4aa18b06907d29321820464892a`.
Each frame contained exactly one v2 evidence record and no failure record. The
authenticated oracle returned PASS for two unchanged native records, with no
added, removed or changed records.

The deployed JAR is 37,578 bytes with SHA-256
`fe0d42d26a8f2a21ee0a14cb88f0f57bee8cd98d5e3abfeaf8e75da4391e09b2`;
its 31,108-byte DEX has SHA-256
`ede82ef546ac99cc0a4489fb1b78909ecd3f5d440ff34322cb0cf5677034c097`
and contains neither DEX method-handle nor call-site sections. Its embedded
artifact authority is
`c6d449a492d8b4f99c79608a80be01d3de14ec6f98ad1ca39a3c0b8e9381586c`.
The prior Android `BootstrapMethodError` was traced to the sole Java dynamic
bootstrap, `Comparator.comparing(Field::getName)`, and removed with a bounded
manual sort. Two deterministic builds, all 12 artifact mutation tests, the
234-test Windows matrix and the 222-test WSL matrix pass on the corrected source.

Before and after both captures, the PDF, live `.mark`, disposable and protected
copies, firmware hashes, Document PID/starttime and collector hash were exact;
no helper process remained. This admits the independent collector only. It does
not admit a native writer, viewport adapter, annotation mutation or second live
page context. Three independent current-state read-only reviews returned CLEAN;
the bounded one-page viewport experiment is now the next gate. No APK was
installed or enabled, and no code was pushed or merged.
The bounded machine-readable checkpoint is
[HARDWARE_SAVED_INK_GATE_20260911.json](HARDWARE_SAVED_INK_GATE_20260911.json);
raw frames and native stderr remain local evidence and are intentionally not
committed as source or annotation fixtures.

## Pre-hardware host checkpoint — superseded by the result above

At this pre-hardware checkpoint, the repair candidate passed the complete Windows and WSL
host matrices. Windows ran 234 authenticated tests: the 222-test core plus the
12-test generated-device-artifact lane, with 20 expected platform-only skips.
WSL ran the 222-test core with 9 expected skips. The Linux native harness
separately passed 6,439 report checks, 57 loader cases (including the dense-low-
descriptor regression) and 102 isolation-filter runs / 1,428 checks. The
unchanged native containment evidence also includes five repeated stress
passes, UBSan, and the Android AArch64 cross-build/static boundary checks. The
last Android loader binary built by this matrix has SHA-256
`069294cd3b0ab77f0d06006e51ed7aa5cf2cbc03f27318d8c39d324aa32093ef`.

Earlier focused read-only reviews returned **CLEAN** for the unchanged native-
containment and SavedInk-schema slices. Focused reviews of the repaired
publication-state and gate-provenance slices also returned **CLEAN**. One
combined exact-head review remained pending. The authorities at that checkpoint were:

- fifteen authenticated Python sources:
  `c6bfd63eccfbb716e8fad91346cd7bbf69198c82855d2cc5418071fc0840e9cb`;
- launcher gate:
  `8f961715c251e4a80207dc656ecac3ca0a9dd890de10d459236390eed66e133c`;
- bounded runner:
  `b5b643c035114b503952ccf45363d07dbcc3c6f31b119ae3c9c95f719a61d288`;
- pinned 54-file pyelftools tree:
  `09679ad9ea7781df8fe3ef1d39b2189261f57967e06c549ce2891b977018382a`;
- SavedInk payload: 2,532 bytes, SHA-256
  `20a179534dfce744b9be97e8e40c1ab07ef19e1c1ddb618ed38f58002e648158`,
  inside one exact 2,562-byte frame.
- deployable SavedInk reader JAR: 37,810 bytes, SHA-256
  `9204fb1a8e2230527af4bad314e6f52c430c6e94f28020a1251ffc26ef6767c9`;
- embedded `classes.dex`: 31,340 bytes, SHA-256
  `d49bda671c7a16350d35b26a5f0883b4058d938cbc463e0e5f3aee04c6976df9`;
- embedded artifact authority SHA-256:
  `4230ab7067aaa7fe8658c176fb0db65cfac6f9f7760efcf7348b8e75a7e2e296`.

The whole-worktree review found a P1 terminal-publication defect: a complete
binding report could become visible before a later diagnostic returned ordinary
retryable failure. The repair now makes the successful no-replace link/rename
the logical commit, explicitly tracks private, outcome-unknown, published and
collision states, preserves published or uncertain authority, and classifies
collision, relocation and post-commit uncertainty as nonretryable exit 2.
Independent process-backed regressions cover each boundary and prohibit a
second accepted authority.

A follow-on gate-provenance P1 showed that relational loader/finder checks alone
could admit a self-consistent forged graph. The repaired collector binds a reused
gate's complete executable namespace to the exact captured and pinned gate
bytes, retains the accepted authority/method/source/loader/finder identities and
revalidates them on every later call. Regressions reject matching-path callable
preloads, ordinary-loader relabeling, self-consistent custom fake graphs,
altered transitive helpers and post-first-use replacement.

The trust boundary is a fresh launcher process using `-I -S -E -s`, exact
captured and pinned gate/probe bytes, and a trusted unmodified CPython runtime
whose canonical builtins, standard-library module identities, `sys.modules` and
`sys.meta_path` remain quiescent through validation and invocation. Deterministic
regressions reject matching-path callable aliases, ordinary-loader relabeling,
self-consistent fake loader/finder graphs, altered transitive helpers, authority
replacement after first use, ABC virtual-subclass tricks, hostile container
equality and callback-bearing source/root path objects. This is not a claim
against arbitrary code that already poisoned or is concurrently mutating the
same interpreter, builtins, standard library or import state, nor against a
hostile CPython executable. The launcher-isolation tests retain that boundary.
The final sequential matrices and focused boundary-aware reviews passed on this
exact source. These scoped results do not replace the required combined current-
head review.

Both display-host package modes and the arbitrary-capture SavedInk comparison
CLI now use a descriptor-authenticated two-stage production launcher. The shell
captures and pins the launcher before execution; the second stage captures the
complete mode-specific local-source closure before import. The oracle requires
exactly one complete raw-path pair or one explicit framed pair; mixed,
incomplete and autodetected inputs are forbidden. Its wrappers preserve stdout
and stderr independently and retain exact 0/1/2/126 exits. The authenticated
launcher suite has 13 test methods containing deterministic mutation matrices
for startup/import poisoning, local shadows, source and path replacement,
trailing bytes, forged terminal records, stream separation, exact exit/status
semantics and post-publication uncertainty.

`loader_resource.h` is part of the explicit native source inventory. The child
establishes parent-loss protection, closes inherited descriptors, rechecks its
parent, applies exact `RLIMIT_AS=256 MiB` and `RLIMIT_NOFILE=32` caps, and only
then proceeds toward `dlopen`. The ordering is covered by a real dense-low-FD
regression. Exact nonblocking report framing rejects truncation, extra bytes,
trailing writers and nonterminal EOF states.

The SavedInk grammar now matches all 62 pinned firmware fields. In particular,
`disable_area_list` is exact `JniFlagRect`, `m_contours_src` is nested
`PointF`, `m_control_nums` is full int32, `m_mark_pen_d_fill_dir` is `PointF`,
and `recogn_points` is exact `JniRecognData` with an int64 timestamp. Independent
Java-to-raw/framed-to-Python parity covers binary32, binary64, signed zero,
integer extrema, nesting and field-name capitalization.

The Windows-only configured artifact lane performs two clean builds, verifies
their byte-for-byte identity and exact JAR/DEX/provenance authorities, and runs
12 generated-artifact mutation tests through the authenticated gate. Its
collector wire is `native-viewport-ink-evidence-v2`; any DEX carrying the stale
`native-viewport-ink-evidence-v1` wire is rejected. WSL validates the 222-test
core and does not claim to rebuild the Android artifact without the configured
JDK, Android JAR, D8 and JSON JAR inputs.

The SavedInk collector must still run through ordinary ADB-shell `app_process`
with exact UID 2000 and GID 2000, never through `su`. It rejects every other or
mixed identity before arguments, files, firmware, or native code. The separate
read-only loader collectors use `su` only for protected `/proc` evidence.

Inventory generation activates one empty retained directory without
replacement, stages subordinate evidence through that retained descriptor and
commits `inventory.json` last. Downstream consumers reopen and rehash both exact
raw-map witnesses and require live recapture to match. This detects pathname and
post-publication mutation under a trusted host account; it is not a hostile
same-UID sealing claim.

Despite the passing host matrices and focused reviews, a fresh capture from a
disposable saved `.mark` copy on the Nomad, launched by ordinary ADB shell as
exact UID/GID 2000, remains mandatory. It must be repeated exactly, leave both
the copy and live-reader fingerprints unchanged, and leave no helper running.
Until then there is no hardware/collector/viewport-readiness claim. No firmware
was loaded, native engine started, device mutated, package installed, or code
pushed/merged during this validation.

## Prior r11 review record — historical; repair/pass claims withdrawn by r12

All dated sections below this point are contemporaneous historical records.
Words such as "current", schema-v2/v3 requirements, old counts, and old pass
claims describe only their recorded snapshot; they do not override the current
repaired status, inventory-v4 contract, or pending Nomad gate above.

GPT-5.6 Sol Ultra r11 reviewed the next immutable 56-file snapshot and
returned **NOT CLEAN**. Its manifest remained
`6816acb7724e7f9a8450e44e2b49adf58e10e56248f1d94818c25c4889873d06`
before and after review: 56/56 hashes, no missing or extra paths, no reparse
points, no alternate data streams, and no modified files.

The contemporaneous r11 working-tree record described its findings as repaired
and recorded a 103-case Python run plus wider host/repository passes. **Those
mechanism and pass claims are withdrawn.** The subsequent immutable r12 review
found still-live defects in the same boundaries, including process retirement
and Windows supervision, evidence/path authority, exact process-map and `aapt`
wires, staged publication, SavedInk bounds, APK snapshot immutability, serialized
slot sizing, and production-boundary coverage. The former r11 descriptions of
`sigaction`/subreaper restoration, `WNOWAIT` ownership, durable publication,
pinned APK inspection, and a clean current matrix therefore must not be used as
implementation or readiness evidence. Contemporaneous logs and artifact hashes
remain historical evidence only; they do not attest the current tree.

Only the repaired status above is current. The r12 verdict and the r11 repair
claims remain historical evidence superseded by the current host matrix and
focused confirmation reviews. A fresh disposable-copy Nomad collector gate is still
required; no device action, firmware load, native start, installation, push, PR,
merge, or readiness claim follows from the historical r11/r12 records.

## Prior exact-source hardening — 2026-09-08

GPT-5.6 Sol Ultra r10 (`01a084c5-703e-7a61-9411-4e150cfce4e0`)
reviewed the then-current immutable 56-file snapshot and returned **NOT CLEAN**. Its
manifest remained
`f27db9368f401b54e774a0662818fcd647e8c35bfe20d2c8e13d051d4fbb707f`
before and after review: 56/56 hashes, no missing or extra paths, and no
reparse points. All eight P2 groups and three P3 proof/documentation gaps were
accepted and repaired before the r11 review:

- External-command supervision owns one hard deadline. POSIX normalizes and
  restores `SIGCHLD`, retains the waitable group leader while retiring and
  reaping the private group, and closes/reaps on signal errors. Windows assigns
  a suspended isolated bootstrap to a Job before resume, checks both bootstrap
  and Job retirement, and performs no post-deadline target launch or cleanup.
- Local evidence admission opens descriptor-first and no-follow/nonblocking.
  POSIX keeps the parent directory descriptor while opening its child; Windows
  keeps reparse-safe parent/child handles and verifies handle identity. No
  inventory path is resolved away before admission.
- Effective runtime rows retain their owning `PT_LOAD` identity. The effective
  RVA-zero owner itself must be the one unique raw zero/zero anchor; a later
  same-page replacement fails.
- One precharged work budget covers local reads, command captures, both live
  recaptures, planning and incremental report serialization. The report is
  capped, flushed and fsynced in private staging, then atomically linked without
  replacing an existing authority file.
- Final live-ELF recapture is bracketed by identical process and complete-map
  authority. Only the post-recapture identity may reach publication.
- Saved-ink JSON uses a bounded recursive-descent decoder, enforcing depth,
  nodes, list items and decoded-string bytes before container materialization.
  The final named-source digest comes from the still-open source descriptor;
  the sealed memfd is checked separately.
- Both `aapt` evidence producers run through the same bounded command owner.
  The verifier requires the exact complete binary-manifest grammar and hashes
  the same APK before, between and after the two inspections.
- Production-boundary regressions now cover inherited `SIGCHLD`, signal
  failure, no-follow/FIFO admission, Linux memfd write/grow/shrink seals and FD
  cleanup, aggregate publication, final-map bracketing, Java-produced envelope
  parity, exact bool/int distinction, full manifest terminus, bounded producers
  and APK replacement.

Current local evidence is clean: the ordinary and parser-enabled Python suites
run 95 cases (91 applicable Windows cases pass; the four Linux-only cases pass
under WSL); the WSL harness also passes 5,704 loader-report checks, 51 loader
cases and 102 filter runs / 1,428 checks. The real Java/Android host gate passes
280 viewport assertions, 45,459 display assertions, Java-to-Python saved-ink
parity and 34 Node cases. The actual unsigned display-only APK builds and its
two packaged inspection surfaces pass the exact bounded verifier. The full
repository matrix passes 85,407 v2 assertions, all 271 mutations, every reader,
renderer and Native Spread invariant, deterministic build provenance,
fail-closed packaging and trace-helper tests. A new immutable Ultra
confirmation review is still required before any Nomad collector action,
push, PR or readiness claim.

GPT-5.6 Sol Ultra r9 (`01a0848c-2908-7e83-87d5-a784593d495d`) reviewed the
next immutable 56-file snapshot and returned **NOT CLEAN**. Its manifest passed
before and after review at
`5c4c795037c7f8a613987a24b3f66e797cfdab0602e7a43f1e2f9adee8ea0b08`:
56/56 hashes, no missing/extra paths, and no reparse points. The current repair
batch accepts all six P2 and three P3 finding groups:

- POSIX command cleanup retains a waitable leader until its private process
  group is retired. Windows launches an isolated/no-site bootstrap suspended,
  assigns it to a kill-on-close Job before resume, and keeps target output
  behind the bootstrap's bounded internal pipe. Setup, deadline, success, and
  cleanup paths now have one owner and one absolute deadline.
- Binding load bias requires effective ordered PT_LOAD authority at RVA zero;
  a replaced anchor with repeated file offsets fails. One pre-decode work/time
  budget covers strict inventory admission, indexed dependency closure,
  effective-load indexes, local/live recapture, pointer reads, and publication.
- Java and Python count structural depth/nodes from the same `trails` root while
  independently bounding the complete envelope. Java rejects unpaired
  surrogates before allocation, emits explicit UTF-8, and is executed against a
  real JSON runtime at exact depth/escaping boundaries.
- The named disposable `.mark` is opened no-follow/nonblocking, copied and
  hashed into a private memfd, write/grow/shrink/seal seals are verified, and
  native reads receive only the sealed descriptor path. The source path is
  still revalidated conservatively. A fresh disposable-copy Nomad gate remains
  mandatory for this changed collector.
- Packaged permission evidence is streamed to a hard cap, authenticates the
  expected package and complete binary-manifest shape/terminus, and rejects all
  element tokens beginning with `uses-permission`, including punctuation and
  future suffixes. Empty, truncated, malformed, and oversized evidence fails.
- Inventory comparisons are recursively type-exact, including redundant map
  copies and descriptor byte counts. Linux tests inject actual late-reap and
  supervisor-error outcomes through the production wait routine, and the
  escaped pipe-holder timing oracle can no longer pass by waiting for EOF.

Focused parser, Windows host, packaged-APK, and WSL mechanism checks pass for
this repair. The complete integrated repository matrix also passes: 85,407 v2
core assertions, all 271 mutations, Native Reader v2 / renderer / Native Spread
invariants, deterministic build provenance, fail-closed packaging, and the
trace-helper adversarial suite. A new immutable Ultra confirmation review is
still required before any device collector action, push, PR, or readiness claim.

Daybreak r5 independently reviewed all 56 approved authored source/note files
and returned six P2 findings in the host evidence tools. Its immutable manifest
was unchanged at
`8fe68f4b379a7a8d785bfff7409a21f6eb85a4136397cc6b29148dd7c55d8c3e`.
The current local batch fixes all six:

- Android file-page, zero-fill, and anonymous `PT_LOAD` operations are modeled
  separately in program-header order. Short BSS zeroes through the file page;
  an unaligned zero-file load retains its file-backed in-page prefix and zeroes
  from `p_vaddr` onward.
- `native-loader-inventory-v4` has one strict shared schema validator. It binds
  the exact complete raw map bytes as well as the derived filtered mapping set;
  library mapping copies, read plans, and target ownership must derive from
  those authenticated witnesses observed unchanged before and after capture.
- Raw bounded section headers, dynamic metadata, and matched runtime sections
  agree on 24-byte RELA entries; malformed sizes cannot silently yield no rows.
- Each library capture receives the remaining aggregate allowance. The opened
  device descriptor is size-checked before transfer and its bytes are published
  only after per-file and aggregate admission.
- The LLVM comparison uses only dynamically authenticated relocation tables and
  enforces aggregate table/row bounds on both implementations.
- Inventory JSON has no floating-number wire type. Duplicate keys, NaN/Infinity,
  ordinary decimal tokens, and overflowing exponent tokens all fail closed.
- Mapped descriptor identity preserves the exact authenticated `/proc/maps`
  device spelling, root-reachable candidate closure is exact, and every section
  name/table is bounded before `ELFFile` construction.

Daybreak r6 (`01a08250-77a3-7e51-9a26-b3d261e49031`, immutable manifest
`3fddb24637566e5918301fbac0cd1de9241e96a6530f821af88f61edce5105d8`)
completed **NOT CLEAN** with four additional P2 admission findings. Those were
fixed before r7. Daybreak r7 then reviewed a new immutable 56-file snapshot
(`5aa7e692f0005339480045b2c9e3f47f9736dac84477f1baba7788a07e71119a`)
and completed **NOT CLEAN** with six P2 findings plus two P3 test/documentation
findings. The current batch accepts and fixes all eight:

- Writable Bionic final-file-page zeroing is separate from anonymous BSS page
  allocation, while read-only tails remain file-backed.
- Stable complete mappings remain the replacement detector, but pointer-owner
  classification is restricted to the authenticated root-reachable closure.
- External evidence commands have bounded reader lifetime and killable process-
  tree ownership (POSIX session/process group; Windows kill-on-close Job Object).
- Native supervisor outcomes retain timely-exit, elapsed-timeout and error
  provenance; only a confirmed forced kill after an actual timeout passes the
  deliberate-stall case.
- Saved-ink capture and oracle share exact depth, node, string, list and encoded-
  byte limits.
- Every Android permission-tag form and the packaged APK permission table are
  checked fail-closed.
- Section-name rejection is proved before `ELFFile` construction, and direct
  inventory-v3 ambiguity/missing/fabricated/cyclic cases are covered.
- The README's historical isolation status is corrected.

GPT-5.6 Sol Ultra r8 (`01a082b9-0d3d-7ca2-a75c-e3e544fa8b18`) then reviewed
the next immutable 56-file snapshot. Its manifest remained exactly
`b908071c8441ceacaad576e91f67f549e9b2aae60f89af532acbd718842caea5`
before and after review. It completed **NOT CLEAN** with seven P2 groups and
four P3 proof gaps. The current local repair batch accepts and addresses all of
them:

- POSIX evidence commands use one nonblocking deadline-driven pipe reader and
  retire the owned process group even after a successful leader exit. Quiet
  same-group descendants and escaped pipe holders have independent Linux
  regressions.
- Every binding-owner ELF is reparsed from authenticated local bytes, the root
  closure is rebuilt from those `DT_NEEDED` records, and every eligible ELF is
  recaptured through its live mapped descriptor before and after pointer reads.
- Sorted non-overlapping mapping indexes, retained run indices, and one shared
  work/deadline budget replace per-slot map and run rescans.
- Native waits use one absolute monotonic deadline and retain timely, late,
  elapsed-timeout, and supervisor-error provenance across interrupted waits.
- The saved-ink oracle admits only the exact JSON tree types produced by Java,
  rejects out-of-range bare integers and non-UTF-8 wire data, and applies the
  structural/encoded-byte budget on every validation path. The real Java
  counters are exercised by a host executable regression.
- The disposable `.mark` input is opened once, admitted and hashed through a
  bounded descriptor, consumed by native code through `/proc/self/fd`, and
  revalidated afterward. This change still requires a new disposable-copy
  Nomad collector gate before it may be treated as working hardware evidence.
- The final unsigned APK is inspected both through its permission table and
  binary manifest; every `uses-permission` element suffix fails closed.
- Isolated Bionic ownership, malformed section-name constructor sentinels,
  valid/malformed inventory-v3 classifications, forged closure, live owner
  recapture, Java byte bounds, and packaged permission mutations close the P3
  proof gaps.

Windows parser-enabled suites cover 68 cases: 66 pass and only the two explicit
POSIX process-group cases skip there; those same two pass under WSL. The full
host gate passes 280 viewport assertions, 45,459 display assertions, the real
Java saved-ink budget executable, 88 Python cases (21 optional parser/POSIX
skips covered by the explicit runs), and 34 Node cases. Integrated repository
gates pass 85,407 v2 assertions, all 271 mutations, Native Reader v2, renderer,
and Native Spread invariants, build provenance, fail-closed packaging, and the
trace-helper suite. The Linux harness passes 5,704 loader-report checks, 51
loader cases, and 102 filter runs / 1,428 checks. The unsigned display-host APK
builds with no permission element in either packaged inspection surface.
The historical local inventory is v1 and remains evidence only; current v3
consumers reject it rather than silently upgrading it. No new ADB capture,
firmware load, native start, device mutation, package, push, PR, or merge follows
from this batch. A fresh exact-source Ultra confirmation review remains required.

## Observed runtime, not APK guesses

Nomad `SN078C10015092`, firmware build 20260616, DrawPath PID 1425/starttime
2642 remained unchanged before/after both captures. Root system-library bytes
matched their remote hashes, and selected mapped device/inode/ranges matched
before/after. No debugger attachment, native invocation, process stop, raw input,
document launch, file mutation, package install or module enablement occurred.

Local-only evidence is `../../loader-inventory-20260907c/`. Do not commit or
upload its ELFs, memory-pointer data, or raw process maps to a review service.
The earlier partial `build/loader-inventory-20260907a` and `...b` captures are
preserved: parser access and Windows path-length failures, not completed gates.

- `inventory.json`: 202 candidate libraries / 76,823,616 bytes, 1,841 dependency
  edges. 595 edges have multiple mapped namespace candidates. Candidate closure
  is deliberately **not** loaded-binding or safe-initializer authority.
- `bindings.json`: 5,057 GLOB_DAT/JUMP_SLOT slots in five modules. Each bounded
  run was read twice and required identical bytes (43,312 bytes per capture).
  Before/after process and mapped-file checks passed. 4,825 target pointers are
  inside exactly one recognized file-backed library; 232 are unresolved by that
  classifier, mostly objects in anonymous BSS. No BSS contents were read.
- 4,339 slots have function symbol type. All except one resolve into recognized
  library mappings. OpenMP's `sigaction` points to the mapped executable
  `/system/bin/app_process64`, not the libc implementation. Raw map inspection
  confirms the address range; this is an executable-interposition observation,
  not permission to invoke it from another process.
- `runtime-images.json`: separately pinned mapped linker and app executable.
  The linker's real SONAME is `ld-android.so`; that explains the three edges
  called "missing" by the basename-only candidate tool. Do not edit the original
  inventory to pretend its heuristic established this runtime alias.

The root pen library's `defaultServiceManager` pointer resolves into
`/system/lib64/libbinder.so`, SHA-256
`758f29a75b164e4669b89d120a4a5ecedeee783c29a6b22ca3847b99360d6895`.
The APK's bundled Binder (SHA-256 beginning `92255144`) is not that runtime
authority. Binder in turn has nine inspected C++ function/vtable imports
interposed by `/system/lib64/libandroid_runtime.so`. OpenCV, libc++_shared and
the root engine also interpose some symbols across each other's mappings.

Pinned runtime linker SHA-256:
`b2c0fe187aa60162665f5b30768b78e4aa5e09e1d5c6d22ee549c97ffbe7800d`.
Pinned app_process64 SHA-256:
`c60a4f4a4eb176c7bdf0bbee18bbe6fd010025fdbbd320aebd4ab9396ab84c87`.
Neither executable was run by the capture.

## Parser checks

`inspect_loader_dependencies.py` is a bounded, read-only candidate collector.
`inspect_loader_bindings.py` reads only ELF-derived pointer intervals; it never
dereferences their target pointers. Unsupported formats fail explicitly.
Android APS2 RELA is decoded with bounds/overflow/group checks; RELATIVE data
and RELR blocks are not live-read as import pointers.

Host tests: 15 inventory cases and 17 binding/parser cases pass. The dedicated
inventory command requires `--python-path` and fails if the ELF parser is absent.
Generic unittest discovery explicitly skips three parser-dependent cases when
the optional dependency is absent; that is not the dedicated loader test gate.

An independent `llvm-readobj` comparison matched **48,764 relocation records**
across all five pinned libraries, including offsets, symbol/type info and
addends. This validates the host decoder against another implementation, not
the safety of loading those libraries. Result: `llvm-comparison.json`.

## Consequence for the initializer-only experiment

Do not fork the running app/DrawPath or reproduce its entire Java process to
inherit its interposition. That would carry live engine state and ownership
into the proposed test. Do not select APK duplicates as substitutes either.

The next executable must be a separate, bounded supervisor/child loader probe:

1. Use a versioned immutable local manifest of exact file hashes and load paths.
   Preserve namespaces/paths rather than flattening duplicate SONAMEs. The
   inventory above is input to that manifest, not an automatic load permit.
2. Establish child-only private mounts/root, no inherited outside descriptors,
   dropped credentials/capabilities, no-new-privileges, parent-death protection
   and bounded supervisor recovery **before** any selected library initializer.
   Only reviewed copied library files may exist in that root. No actual Binder,
   input/EBC nodes, property sockets, annotations, personal directories or procfs.
3. Add a separately tested loader-specific syscall policy, not an expansion of
   the already hardware-tested mechanism filter. Read-only file opening,
   private mappings/protection and runtime queries need precise rules. No shared
   output mapping, global IPC, ioctl, thread/process creation, new executable,
   signal/watchdog reconfiguration or privilege/mount changes. Unsupported
   initialization must produce an explicit failure, not a fabricated I/O result.
4. Test the policy/loader first with our own tiny constructor fixtures that
   deliberately try forbidden operations and timeouts. Review exact integrated
   source and host/kernel evidence before running any new executable on Nomad.
5. Only then attempt the pinned engine's initializers under the same boundary.
   Do NOT invoke JNI_OnLoad, startDraw, initBinderServer, worker/painter startup,
   onTransact or a Document page during this gate. Missing dependency, unexpected
   symbol binding, disallowed syscall, crash or uncertain cleanup is a failure.
6. A successful isolated load would prove only constructor/loader feasibility
   in the new environment. Its bindings must be recorded independently; they
   cannot be assumed to match app_process64. Private dispatch, owned background
   and output planes, pen admission and saved-native geometry remain later gates.

Keep the existing stock reader untouched and the companion disabled. Reuse the
tested isolation supervisor and display/geometry substrate; no second page,
tool-specific remapping, annotation conversion or production release is added.

## Constructor-policy preparation (host only)

`native/loader_filter.h` is a NEW policy candidate, separate from the previously
hardware-tested isolation filter. The new Android wrapper is fixture-only and
has not run on the Nomad. Its host
interpreter tests argument/architecture/unknown-syscall behavior and decision
mutations. It admits read-only opens, private non-W+X mapping requests, exact
report-FD writes and a minimal runtime-query set; disallowed requests TRAP.

`run-loader-linux-tests.sh` runs our own `loader_fixture.c`, not Supernote code,
in disposable unprivileged x86-64 children with the translated policy installed
in the actual Linux kernel. Three rounds of 17 cases PASS (51 total): positive
load/memory/random constructors, trapped write/create/socket/ioctl/clone/exec/
signal/prctl/futex/remap/W+X/shared-mapping requests, and bounded stall recovery.
This host harness does NOT use a private filesystem/mount namespace, nor claim
that arbitrary firmware is safe to load there. It may load ONLY authored fixtures.

The first positive load correctly exposed the Linux loader's legacy
`MAP_DENYWRITE` flag. Its documented ignored bit is now admitted; private mapping
and protection restrictions remain. See [Linux mmap flags](https://man7.org/linux/man-pages/man2/mmap.2.html).

Before any real Android constructor loading, the wrapper must prove all earlier
root/FD/credential/namespace requirements, plus runtime mapping and personality
preconditions (no inherited external shared writable mapping or implicit-exec
personality). A filter checks syscall requests; it cannot establish filesystem
authority, arbitrary code integrity, actual effective W^X by itself, constructor
semantics, or faithful app-runtime behavior. Firmware library publication and
the real engine worker are still unimplemented. Do not combine this policy and
firmware on the Nomad without that implementation, evidence and exact review.

## Review-fix batch and authored Android loader — 2026-09-07

The approved 52-file review of `9e2441f`/code `8480054` returned NOT CLEAN with
four actionable host-evidence findings. All were accepted in this batch:

- Inventory v2 opens `/proc/<pid>/map_files/<range>` and compares the **open
  descriptor's** device/inode with the process mappings. Both bounded captures
  and before/after descriptor stat records must match. No pathname in adb's
  different mount namespace is treated as equivalent. Lack of map_files access
  fails explicitly. The existing inventory-v1 evidence remains preserved, not
  retroactively upgraded; the live binding collector now rejects it.
- Import slots must agree with both PT_LOAD file offsets and the readable
  process mapping's file offsets. BSS-only/ambiguous storage is rejected.
- Dynamic-table addresses/sizes, allocated section coverage and symbol-table
  identity replace name-based `.rela.*` selection. A renamed packed-table
  synthetic ELF proves imports cannot silently disappear. RELR relative entries
  are covered separately and never read as symbolic import pointers.
- Local reads validate the opened descriptor and read at most its prechecked
  size plus one. Remote stdout is capped while reading; the mapped transfer has
  an explicit dd block count. LLVM consumes an exclusive bounded-byte copy,
  not a potentially replaced source pathname.

The revised independent LLVM comparison matches **49,594** records: the earlier
48,764 RELA/APS2 records plus 830 RELR entries. This does not change the earlier
observed pointer values or grant new live-memory authority. Local evidence:
`../../loader-inventory-20260907c/llvm-comparison-v2.json` (no ADB run).

The first Android compilation caught an architecture-specific open-flag error:
the AArch64 allowed mask is `0xac800`, not x86-64's `0xb8800`. The target ABI is
now compiler-asserted; host tests translate those flag semantics explicitly.
174,795 policy vectors / 124 decision mutations pass. New constructor markers
distinguish loader-ready, constructor-entered, operation-returned and completed
dlclose. 5,704 report checks reject missing/reordered/wrong/truncated evidence;
the 51 Linux kernel/own-constructor cases pass again with these markers.

`build-loader-probe.ps1` builds `loader_android_probe.c` with the compiled bytes
of our own small `loader_fixture.c` embedded. There is no arbitrary DSO argument
or firmware payload. It reuses the tested isolation sequence/supervisor, creates
a child-only private tmpfs, seeds only that fixture and makes the root read-only,
rejects inherited shared/W+X mappings and implicit-exec personality, closes all
outside descriptors, chroots, drops credentials/capabilities and installs the
constructor filter before dlopen. SIGSYS reports use the exact report pipe.
Seventeen constructor cases plus five isolated crash boundaries are prepared.
The parent checks bounded exact-child cleanup and unchanged namespace/root/device
node identity; it never opens pen/EBC nodes. Unknown cleanup preserves evidence.

The Android build and Clang analysis pass. This is **BUILD ONLY**, not 22 device
passes. No new helper was staged, installed or executed; the companion remains
disabled. Exact integrated source review and owned-device preflight are required
before this test. A fixture pass would still not authorize JNI_OnLoad/startDraw,
Binder service creation, engine threads, Document admission or real pen input.

Prepared artifact: `build/loader-probe-8e207c0811ac402fb154a0bd281ef8ca/`
`loader-android-probe` SHA-256
`5c0059935ea71788e9f8a740b03918df8b1e4fb81de994a3841e7afcc2b6e889`;
embedded authored DSO SHA-256
`6a1418ef3517ca03124e5082c8c274603b39b4464a063962cd615b80c5703663`.
All 54 Python cases pass with the ELF parser enabled (zero skips), alongside
280 viewport, 45,459 display assertions and 34 closed observer cases. The generic
check script's five optional-parser skips are covered by that explicit run.

The integrated Ultra r2 review of `56de162` reviewed all 56 files and found one
additional P2: section-selected symbol/string bytes were not tied completely
to DT_SYMTAB/DT_STRTAB. This is fixed by checking their PT_LOAD file offsets,
dynamic string address/size, symbol extents and each name's in-table terminator.
Tests displace both `.dynsym` and `.dynstr`, change string geometry, exceed the
name offset and remove the terminator. All 56 parser-enabled Python tests pass;
all 49,594 offline LLVM records still agree (`llvm-comparison-v3.json`). The C
loader, binary hash and previously run kernel/policy tests are unchanged. The
review established no further loader/cleanup/geometry finding, but the combined
subset still requires the final updated-head confirmation before a device run.

The retained-context r3 review then identified the upstream PT_DYNAMIC offset
gap. Both tools now share a bounded raw dynamic-entry reader: validate program
segment extents/alignment, require exactly one readable PT_LOAD backing and exact
PT_DYNAMIC file-offset correspondence, and require DT_NULL inside its declared
extent. Dependency names use DT_STRTAB/DT_STRSZ directly, never a section-link
fallback. Symbol records are parsed without automatic string resolution; mapped
tables cannot use compressed-section reinterpretation. Added displaced-dynamic,
missing-terminator, partial/truncated/unreadable/overlapping-segment, alignment
and compressed-table regressions. All 59 parser-enabled Python tests pass. The
firmware fixture, C wrapper, policy and device state remain unchanged; another
confirmation is required for this updated host-evidence reader.

The preserved r4 review was later resumed under Daybreak Blue and completed
**NOT CLEAN** with three additional P2 evidence-tool findings. Inventory v3 now
binds the complete filtered library-map set and the live binding reader requires
that full set to remain identical. Target classification is restricted to the
inventoried dependency graph, so a newly mapped allowed-path library cannot
become an unreviewed `unique_mapped_target`. ELF correspondence now follows the
effective ordered page mappings created by `PT_LOAD`, rather than merely testing
nominal segment ranges; later page-rounded replacement and BSS/anonymous tails
fail closed. Finally, fixed budgets precede program/section/dynamic/string/
symbol/relocation/import-slot/map/graph expansion and inventory JSON is parsed
with duplicate-key and non-finite-number rejection.

The focused parser-enabled suite now has 52 passing cases with zero skips. The
new cases independently exercise page ownership replacement, complete map-set
mutation, extended/count/byte limits, slot-result limits and strict JSON. The
full generic host gate also passes; its optional ELF skips are covered by that
explicit run. This remains local host evidence only. A clean exact-current-source
Daybreak confirmation review is still required before the Android fixture gate.
