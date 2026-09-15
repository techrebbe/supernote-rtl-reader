# Overnight checkpoint — 2026-09-06/07

## Current status — no-bootstrap SavedInk collector hardware gate PASS; reviews CLEAN

On 2026-09-11 the corrected collector passed its bounded Nomad gate on
`SN078C10015092`. The generated DEX no longer contains invoke-custom or method-
handle bootstrap sections (`0x0007`/`0x0008`); the only dynamic JVM bootstrap in
the prior build came from `Comparator.comparing(Field::getName)` and was replaced
with a bounded manual field sort. The deployable JAR is 37,578 bytes with
SHA-256
`fe0d42d26a8f2a21ee0a14cb88f0f57bee8cd98d5e3abfeaf8e75da4391e09b2`;
its embedded 31,108-byte DEX has SHA-256
`ede82ef546ac99cc0a4489fb1b78909ecd3f5d440ff34322cb0cf5677034c097`,
and its embedded artifact authority has SHA-256
`c6d449a492d8b4f99c79608a80be01d3de14ec6f98ad1ca39a3c0b8e9381586c`.
Two clean builds were byte-identical and all 12 artifact mutation tests passed,
including count-stable DEX map mutations to both forbidden bootstrap types.

The helper ran through ordinary ADB-shell `app_process` as exact UID/GID 2000,
never as root. Root was limited to preparing and rechecking the protected,
read-only disposable input file. Two independent frames were byte-identical:
15,866 bytes each, SHA-256
`19ad6004ada5e8a92b994f0b9f3b5fbd78ccc4aa18b06907d29321820464892a`,
with exactly one `NATIVE_VIEWPORT_INK_EVIDENCE` record and no failure record.
The authenticated oracle returned PASS with two unchanged native records and no
added, removed or changed record. The live PDF and `.mark`, disposable source,
protected input, firmware libraries, Document PID/starttime and collector bytes
all remained unchanged, and no `SavedInkReader` process remained.

The complete host matrices also pass on these exact sources: Windows ran 234
tests with 20 expected skips; WSL ran 222 tests with 9 expected skips. Current
fifteen-source authority is
`07e205bc314fc1cdbbc23fa58391b2f5450cdda791d83c08e32651a74f8e300b`
and launcher-gate authority is
`ff7021874c16321f71b4309e131d78061d0d71c4cd6d14743574fc4eb229cd2f`.
This proves only the independent saved-ink collector boundary. It does not yet
prove an arbitrary native viewport, a pen engine, annotation mutation or two
simultaneous page contexts. Three independent current-state read-only reviews
returned CLEAN, so the bounded one-page viewport experiment is the next gate.
Nothing was installed, enabled, pushed or merged during the collector gate.
The bounded machine-readable checkpoint is
[HARDWARE_SAVED_INK_GATE_20260911.json](HARDWARE_SAVED_INK_GATE_20260911.json);
raw frames and native stderr remain local evidence and are intentionally not
committed as source or annotation fixtures.

## Pre-hardware host checkpoint — superseded by the hardware result above

At this pre-hardware checkpoint, the repair candidate passed the complete Windows and WSL
matrices. Windows ran 234 authenticated tests: the 222-test core plus the
12-test generated-device-artifact lane, with 20 expected platform-only skips.
WSL ran the 222-test core with 9 expected skips. The Linux native harness passed
6,439 report checks, 57 loader cases and 102 filter runs / 1,428 checks. Earlier
focused reviews remain **CLEAN** for the unchanged native-containment and
complete SavedInk-wire slices. Focused exact-source reviews of the repaired
publication-state, gate-provenance, production-launch and artifact slices also
returned **CLEAN**. One combined exact-head review remains pending.

The terminal-publication P1 is repaired: the successful no-replace link/rename
is the logical commit; private, outcome-unknown, published and collision states
are explicit; published or uncertain output is preserved; and collision,
relocation and post-commit uncertainty are nonretryable exit 2. A follow-on
gate-provenance P1 is also repaired. A reused gate's complete executable
namespace must match the exact captured and pinned gate bytes, and the accepted
authority/method/source/loader/finder identities are retained and revalidated.
The current authorities are gate SHA-256
`8f961715c251e4a80207dc656ecac3ca0a9dd890de10d459236390eed66e133c`
and fifteen-source SHA-256
`c6bfd63eccfbb716e8fad91346cd7bbf69198c82855d2cc5418071fc0840e9cb`.
The trust boundary is a fresh launcher process using `-I -S -E -s`, exact
captured and pinned gate/probe bytes, and a trusted unmodified CPython runtime
whose canonical builtins, standard-library module identities, `sys.modules` and
`sys.meta_path` remain quiescent through validation and invocation. Regressions
reject inert matching-path aliases, ordinary/custom loader substitution,
altered helpers, post-first-use replacement, ABC virtual-subclass tricks,
hostile container equality and callback-bearing source/root path objects. This
does not defend a process whose interpreter, builtins, standard library or
import state was already poisoned or is concurrently mutated by arbitrary
same-process code, nor a hostile CPython executable. The existing launcher-
isolation tests retain that explicit boundary. The passing focused reviews do
not replace the pending combined current-head review.

Authorities at that checkpoint:

- probe-source SHA-256:
  `c6bfd63eccfbb716e8fad91346cd7bbf69198c82855d2cc5418071fc0840e9cb`;
- gate SHA-256:
  `8f961715c251e4a80207dc656ecac3ca0a9dd890de10d459236390eed66e133c`;
- runner SHA-256:
  `b5b643c035114b503952ccf45363d07dbcc3c6f31b119ae3c9c95f719a61d288`;
- pinned parser-tree SHA-256:
  `09679ad9ea7781df8fe3ef1d39b2189261f57967e06c549ce2891b977018382a`;
- SavedInk payload: 2,532 bytes with SHA-256
  `20a179534dfce744b9be97e8e40c1ab07ef19e1c1ddb618ed38f58002e648158`,
  inside a 2,562-byte exact frame.
- deployable SavedInk reader JAR: 37,810 bytes with SHA-256
  `9204fb1a8e2230527af4bad314e6f52c430c6e94f28020a1251ffc26ef6767c9`;
- embedded `classes.dex`: 31,340 bytes with SHA-256
  `d49bda671c7a16350d35b26a5f0883b4058d938cbc463e0e5f3aee04c6976df9`;
- embedded artifact-authority SHA-256:
  `4230ab7067aaa7fe8658c176fb0db65cfac6f9f7760efcf7348b8e75a7e2e296`.

The final repair batch includes descriptor-authenticated launchers and captured
child source; exact EOF/framing; inventory-v4 raw-map authority and terminal
publication; immutable package evidence; the exact 62-field firmware annotation
grammar; and resource-bounded native loading. `loader_resource.h` is now in the
explicit native source inventory. The loader child closes inherited descriptors
before applying exact 256 MiB address-space and 32-descriptor caps, preventing a
dense inherited descriptor table from defeating its own setup.

The SavedInk oracle accepts exactly one complete raw before/after path pair or
one explicit framed pair, never a mixed or autodetected mode. Its production
wrappers preserve stdout and stderr independently and retain exact 0/1/2/126
exits. The Windows-configured artifact lane performs two clean builds, verifies
their actual JAR, DEX and provenance, and runs all 12 artifact mutation tests.
The collector uses `native-viewport-ink-evidence-v2`; the stale
`native-viewport-ink-evidence-v1` DEX is rejected. The WSL gate covers the
222-test core and does not claim an Android artifact build without the configured
Android build inputs.

This checkpoint does not certify a hardware collector, native viewport or pen
engine. The next gate is one fresh ordinary-ADB-shell capture as exact UID/GID
2000 from a disposable copy of a saved Nomad `.mark`, followed by an exact
repeat capture, unchanged copy/live-reader fingerprints and proof that no helper
remains. No firmware was loaded, native engine started, device mutated, package
installed, or code pushed/merged during the host validation.

## Prior checkpoint — r11 historical record; repair/pass claims withdrawn

All dated sections below this point are contemporaneous historical records.
Words such as "current", schema-v2/v3 requirements, old counts, and old pass
claims describe only their recorded snapshot; they do not override the current
repaired status, inventory-v4 contract, or pending Nomad gate above.

Ultra r11 returned **NOT CLEAN** on the immutable 56-file snapshot with
manifest
`6816acb7724e7f9a8450e44e2b49adf58e10e56248f1d94818c25c4889873d06`.
The exact seal passed before and after review, with no missing, extra, reparse,
alternate-stream or modified file.

The contemporaneous checkpoint then described the r11 findings as repaired and
recorded a 103-case Python run plus broader host/repository passes. **Those
mechanism and pass claims are withdrawn:** immutable r12 review subsequently
identified still-live defects in process cleanup/supervision, evidence and path
authority, exact raw wires, report publication, SavedInk bounds, APK snapshot
immutability, serialized sizing, and the claimed production test coverage. In
particular, the former claims about exact POSIX signal/subreaper restoration,
owned-descendant reaping, durable publication, and one pinned immutable APK
snapshot are not current implementation evidence. The r11 seal and verdict are
retained as history; its old counts, hashes, and pass output do not attest the
current tree.

Only the repaired status above is current. The r12 verdict and r11 claims below
remain historical evidence superseded by the current host matrix and focused
confirmation reviews. A fresh disposable-copy Nomad collector gate is still
required. No device operation, firmware load, native start, installation, push,
PR, merge, or readiness claim is authorized by the historical records.

## 2026-09-09: GPT-5.6 Sol Ultra r10 findings repaired; confirmation pending

Ultra r10 (`01a084c5-703e-7a61-9411-4e150cfce4e0`) returned **NOT CLEAN** on
the immutable 56-file snapshot with manifest
`f27db9368f401b54e774a0662818fcd647e8c35bfe20d2c8e13d051d4fbb707f`.
The snapshot passed the exact seal before and after review and was untouched.
All eight P2 boundary groups and three P3 proof/documentation gaps are accepted
and repaired locally: one-deadline process-tree ownership, descriptor-first
local evidence, effective `PT_LOAD` anchor identity, precharged aggregate work
and atomic capped publication, final-map recapture bracketing, bounded streaming
saved-ink JSON, final named-source revalidation, exact bounded packaged-manifest
inspection, and the requested behavioral regressions.

The complete local matrix passes. The parser-enabled Python run has 95 cases:
91 applicable Windows cases pass and the four Linux-only cases pass under WSL.
The Linux harness passes 5,704 report checks, 51 loader cases, 102 filter runs /
1,428 checks, and all four process/seal boundary tests. The real Android/Java
host gate passes 280 viewport assertions, 45,459 display assertions, executable
saved-ink budget and Java-to-Python envelope parity, and 34 Node cases. The
unsigned display-only APK builds and its actual permission/XML inspection passes
the exact bounded verifier. Integrated repository gates pass 85,407 v2 core
assertions, all 271 mutations, all Native Reader/renderer/Native Spread
invariants, deterministic provenance, fail-closed packaging and trace-helper
tests. `git diff --check` passes.

A fresh immutable Ultra confirmation remains pending. No Nomad operation,
firmware load, native start, installation, push, PR or merge is authorized by
this checkpoint.

## 2026-09-09: GPT-5.6 Sol Ultra r9 findings repaired; confirmation pending

Ultra r9 (`01a0848c-2908-7e83-87d5-a784593d495d`) returned **NOT CLEAN** on
the immutable 56-file snapshot with manifest
`5c4c795037c7f8a613987a24b3f66e797cfdab0602e7a43f1e2f9adee8ea0b08`.
The snapshot passed the full manifest check before and after review and was not
modified. All findings are accepted in the current local batch: waitable POSIX
process-group ownership; suspended pre-Job Windows startup; effective-load-bias
authority; genuinely aggregate binding budgets; exact Java/Python structural
and UTF-8 admission; sealed immutable `.mark` snapshots; authenticated bounded
permission-tool evidence; exact JSON types; and independent boundary tests.

Focused Windows/parser/APK and WSL suites pass. The full integrated repository
matrix passes 85,407 v2 core assertions, all 271 mutations, all three invariant
suites, deterministic build provenance, fail-closed packaging, and the
trace-helper adversarial suite. The host gate passes 280 viewport assertions,
45,459 display assertions, the real Java encoder/budget executable, 88 Python
cases, and 34 Node cases. A clean immutable Ultra confirmation remains pending.
No Nomad operation, firmware load, native start, installation, push, PR, or
merge is authorized by this checkpoint.

## 2026-09-09: GPT-5.6 Sol Ultra r8 findings fixed; confirmation pending

The independent Ultra r8 review (`01a082b9-0d3d-7ca2-a75c-e3e544fa8b18`)
completed **NOT CLEAN** against an immutable 56-file snapshot whose manifest
remained exactly
`b908071c8441ceacaad576e91f67f549e9b2aae60f89af532acbd718842caea5`.
It found seven P2 groups and four P3 proof gaps. All are accepted and repaired
locally: bounded POSIX pipe/process-group cleanup; reparsed and live-recaptured
binding-owner closure; indexed aggregate-bounded binding planning; absolute
native wait deadlines with late-exit provenance; exact Java/Python saved-ink
wire admission; descriptor-backed bounded `.mark` authority; complete packaged
permission-element inspection; and the requested independent edge fixtures.

The repair matrix is clean. Windows parser-enabled runs cover 68 cases (66 pass
and two POSIX-only cases skip); those two cases pass under WSL. The host gate
passes 280 viewport assertions, 45,459 display assertions, the executable Java
budget test, 88 Python cases (the optional parser/POSIX skips are covered by the
explicit runs), and 34 Node cases. The Linux harness passes 5,704 report checks,
51 loader cases, and 102 filter runs / 1,428 checks. Integrated repository gates
pass 85,407 v2 assertions, 271 mutations, all three invariant suites, build
provenance, fail-closed packaging, and trace-helper tests. The unsigned APK has
no permission element in either packaged inspection surface.

The descriptor-backed saved-ink reader still needs a fresh disposable-copy
Nomad hardware revalidation before it becomes collector evidence. No ADB,
firmware load, native start, device mutation, installation, push, PR, or merge
occurred in this repair. The next action is one clean exact-source Ultra
confirmation review of the same approved 56-file boundary.

## 2026-09-08: Daybreak r7 findings fixed locally; Ultra confirmation pending

The previously interrupted 56-file source-only review was resumed in its exact
session using the user's newly approved Daybreak Blue access. The original r4
manifest still matched before and after review. Daybreak completed normally and
returned **NOT CLEAN** with three P2 host-evidence findings; it did not find a
new Android fixture, cleanup, filter, geometry or isolation defect.

The first three findings were fixed in r5. Its exact confirmation review
(`01a08231-0430-7610-b6a0-508010f0f36a`, manifest
`8fe68f4b379a7a8d785bfff7409a21f6eb85a4136397cc6b29148dd7c55d8c3e`)
completed **NOT CLEAN** with six further P2 evidence-tool findings. It found no
additional geometry, display, isolation, supervisor, pen or fixture-loader
defect. All six are accepted and fixed together in the current worktree:

- Ordered `PT_LOAD` authority now distinguishes file mapping, complete final-file-
  page zero fill, and anonymous mapping. Disjoint same-page replacement, short
  BSS, and unaligned zero-file loads have independent regressions.
- One exact inventory-v3 validator is shared by both consumers. Each library's
  mapping copy must equal the authenticated complete map set; pointer planning
  and target classification consume only that same stable authority.
- Raw ELF preflight rejects malformed RELA entry sizes before pyelftools can
  construct a section. Dynamic authority and the matched runtime section must
  both specify 24-byte RELA records.
- The remaining aggregate byte allowance reaches the device capture. The opened
  remote descriptor's size is rejected before `dd`, and library bytes are not
  published until their metadata and aggregate allowance are admitted.
- The LLVM oracle preflights the ELF, examines only dynamically authenticated
  runtime tables, and bounds aggregate observed/reference records. It consumes
  the same exact inventory-v3 validator as the binding collector.
- Strict inventory JSON rejects every floating token, including finite decimal
  syntax and overflowing exponents, as well as duplicate/non-finite constants.
- Daybreak r6 then found four remaining admission gaps: exact device spelling,
  the file-backed prefix of unaligned zero-file loads, pre-parser section-name
  bounds, and root-reachable candidate closure. All four now fail closed with
  independent regressions. Its exact session was
  `01a08250-77a3-7e51-9a26-b3d261e49031`; its immutable manifest remained
  `3fddb24637566e5918301fbac0cd1de9241e96a6530f821af88f61edce5105d8`
  before and after review. r6 itself remains **NOT CLEAN** pending confirmation.

Daybreak r7 reviewed the resulting immutable 56-file snapshot (manifest
`5aa7e692f0005339480045b2c9e3f47f9736dac84477f1baba7788a07e71119a`)
and found six P2 plus two P3 issues. All are fixed together in the current
worktree: Bionic writable-page zeroing, root-closure-only pointer ownership,
bounded descendant-pipe lifetime, exact supervisor timeout/error provenance,
one producer/oracle saved-ink budget, permission-tag and final-APK inspection,
pre-parser section-name proof/direct inventory-v3 edge tests, and the stale
README paragraph. The Windows timeout path assigns a bootstrap process to a
kill-on-close Job Object before it may launch the target, eliminating the child-
assignment race; POSIX uses a private session/process group.

The explicit parser-enabled suites now pass 78 tests with zero skips. The full
host gate passes 280 viewport assertions, 45,459 display assertions and 34 Node
cases. All five repository baselines pass, including 85,407 v2 assertions, 271
mutations, both invariant suites and fail-closed packaging. The Linux harness
passes 51 loader cases and 102 filter runs / 1,428 checks. The unsigned Android
display-host package builds and its final permission dump is empty. `git diff
--check` passes. Historical inventory-v1 evidence remains rejected by current
v3 consumers. No firmware, device, package install, push, PR or merge occurred.
A fresh exact-current-source GPT-5.6 Sol Ultra confirmation is required before
device execution.

## 2026-09-08: independent offline validation preparation

Added the separate `offline-validation/` folder without changing the existing
oracle, collector, loader, display host, reader, or immutable r4 review snapshot.
It batches pinned archived saved-ink captures across declared pages, rejects
missing/invalid evidence, reports protected-page changes, and compares Undo/Redo
results to explicit saved references. It does not operate ADB or load native
code. Eraser/lasso changes remain observations requiring interpretation, not
automatic successes; absent saved records are never fabricated as empty ink.

Validation: 26 new host tests plus 13 existing ink-oracle tests pass, including
omission mutations of all 62 native fields. The pinned archived r3 three-capture
example matches both declared comparisons. Report is in the ignored local
`build/offline-validation-20260908/archived-r3.report.json`; its hardware gate is
explicitly NOT_EVALUATED. No new physical test was performed. Usage and the
short-batch protocol are in `offline-validation/README.md`.

This local-only preparation is not part of the pending independent source
review and has not received one. The service restriction and next-device gate
below remain unresolved. No review retry, upload, device action, package build,
push, PR or merge occurred. No background task was started.

## Current handoff: approved r4 review interrupted by service restriction

The user explicitly approved sending the 56 authored source/design-note files
to OpenAI's Codex review service, excluding PDFs, annotations, firmware binaries,
raw captures and credentials. That disclosure approval was accepted. Do not ask
for the same upload approval again; the earlier disclosure blocker below is
historical, not the current blocker.

The resumed independent Ultra review of source head
`dbe3e782ecb00b5f78a2acd7f59afb30e525589e` ran against the exact source-only snapshot
`../../reviews/native-viewport-loader-dbe3e78-approved-r4`. Its manifest SHA-256 is
`def20df7f989cce35d9e7ff5befcf2281731d0c578c23d8e50256b783af3e5ef`.
All 56 hashes still match after execution. The reviewer reported 56 selected
Python tests passing with zero skips and 34/34 Node tests passing. Three Python
tests needing temporary files were excluded from that read-only run; the full
59-case host result below remains separate evidence.

At 2026-09-07 17:18 local time, the review log ended with a service-side
"flagged for possible cybersecurity risk" error. No final result file exists;
the execution session is no longer available. This is an interrupted review,
NOT a clean verdict or a new code finding. Do not bypass the restriction through
rephrasing, a different agent, or another submission route. Any service access
resolution must use its supported authorization/support process. Preserve the
snapshot, review log and previous findings. No new Android probe, firmware load,
device action, GitHub push, PR or merge occurred. The Nomad remains released.
No reviewer or background device operation is running at this checkpoint.

## Historical handoff: source-review disclosure blocked before execution

Current tested code head: `005845c2d4243cbd5ebce11108f2079bc08b41e9`.
All accepted r1/r2/r3 findings are implemented; 59 parser-enabled Python cases
pass with zero skips and 49,594 LLVM records match (`llvm-comparison-v5.json`).
The Android authored-fixture diagnostic remains build-only, unchanged SHA-256
`5c0059935ea71788e9f8a740b03918df8b1e4fb81de994a3841e7afcc2b6e889`.

The prepared r4 snapshot `../../reviews/native-viewport-loader-005845c-confirmation-r4`
contains exactly the same 56 paths as r3. Only three Python files and two notes
changed. Its manifest SHA-256 is
`8cb50aac403ca51b45ebee04326e3b85e87586aa7f5208f7ca47ed8999522c3a`.
The OpenAI review invocation was REJECTED BEFORE EXECUTION: the approval system
requires explicit authorization for exporting this source to that destination,
despite earlier reviews being allowed and the user's broad project approval.
No r4 reviewer is running; r3 ended NOT CLEAN before this last fix. Do not claim
a clean integrated head, bypass the rejection, or execute the new Android probe.

Ask for explicit approval to send the 56 authored source/design-note files to
OpenAI's Codex review service, excluding PDFs, ink, firmware binaries, raw
captures and credentials. After approval, refresh the same source-only snapshot
for the latest documentation head and resume reviewer session
`01a07b19-1e04-7ad3-9d43-54e8161991b6` with its retained analysis. The exact public
pyelftools directory is `../../tools/_vendor`; no private evidence reads are
needed for its synthetic tests. Do not redo completed hardware work. Device is
still released and untouched; no background device operation or automation is
running. No GitHub push, PR, installation or merge occurred in this continuation.

## Latest continuation: approval received, review fixes implemented

Latest after r3: one upstream PT_DYNAMIC-to-PT_LOAD correspondence gap was
accepted and fixed as a shared bounded raw tag/string reader in both tools.
This removes section-string fallback and unbounded terminator scanning as well.
Program extents/alignment and dynamic offset/termination, symbol/string bounds
and compressed-table rejection are covered by 59 passing Python cases. The C
fixture loader remains byte-for-byte unchanged; no new device commands. Final
retained-context confirmation must complete before the next device experiment.

Update after integrated Ultra r2: `56de162` passed the full source review except
one dynamic symbol/string-table correspondence finding. The fix and targeted
rejections now pass 56 Python cases with zero skips, and LLVM still matches
49,594 records. C loader/build source is unchanged from that reviewed head.
All five repository baseline gates passed, including 85,407 core assertions,
271 mutations and fail-closed packaging. Shared isolation tests passed again:
16 core cases, 56,376/50 filter vectors/mutations and 102 Linux kernel runs with
1,428 checks, zero descriptor leaks and bounded watchdog/reaper recovery.
The final exact-head confirmation is next; no device work or firmware loading.

The user explicitly approved project-related work after the source-disclosure
question. The source/notes-only review now ran; do not treat the historical
rejection below as an active blocker. `native-viewport-loader-9e2441f-approved-r1`
reviewed all 52 exact files and returned four P2 evidence-tool findings. This
batch addresses descriptor/mapping identity, mapped file offsets, dynamic-table
coverage and bounded reads; see `LOADER_ADMISSION.md`. Raw ELFs/maps/pointers,
PDFs, ink data and credentials were NOT included in the uploaded snapshot.

Also prepared a fixture-only Android loader with an embedded authored DSO and
private read-only child root. No Supernote firmware load or device execution.
The initial Android compile caught incorrect cross-architecture open flags;
target compiler assertions and semantic host translation now cover this.
Constructor-phase markers prevent an early loader trap/stall from passing a
constructor test. Host policy/report and Linux kernel fixture tests pass; the
Android build/Clang analysis pass. Full integrated confirmation review is NEXT,
including the new wrapper and the complete shared isolation/supervisor code.

Offline LLVM now agrees on all 49,594 RELA/APS2/RELR records across the five
preserved libraries. Inventory v1 is historical only; future live slot reads
require descriptor-bound inventory v2 and current process/mapping evidence.
Do not redo the completed stock/display/isolation gates to manufacture progress.

The device remains released, untouched by this continuation. No package,
annotation, production setting, GitHub branch/PR or merge changed. The overnight
heartbeat is PAUSED; no new overnight duration was inferred. Preserve every
prior branch/evidence artifact. Gate B real native page viewport is NOT READY;
full/left/right genuine pen tests remain after the missing engine boundary.

## Continued host preparation — 2026-09-07 morning

### Historical review approval boundary (superseded above)

Tested source is committed locally as
`84800544e711e9a5a7973f5dc5db00453da67986`. A complete 52-file source-only snapshot
was prepared at `../../reviews/native-viewport-loader-8480054-r1`, with a hash
manifest and without firmware, raw maps/pointers, PDFs, ink data or credentials.
The OpenAI Codex CLI review command was rejected BEFORE execution: the approval
system requires explicit disclosure approval for this new snapshot/destination.
No reviewer is running and no clean-review claim applies to this new subset.
Do not retry or route the same payload through another tool/agent without that
approval. Prior approval/reviews remain historical; they do not clear this new
blocking decision. Ask for the 52-file authored source/design-note upload only.
Local checks/builds are complete; no device command, transfer or helper remains.
The existing overnight automation stays PAUSED. After approval, refresh the
source-only snapshot to include this documentation update and perform the full
integrated subset review; do not repeat completed device captures or stock tests.

- Read-only library/relocation capture completed. Exact process/mapping checks
  passed; 202 candidate ELFs remain local-only in `../../loader-inventory-20260907c`.
  System Binder, runtime linker alias and app-process interposition findings are
  recorded in `LOADER_ADMISSION.md`. No native methods were invoked.
- 15 dedicated inventory tests and 17 binding/parser tests PASS. LLVM independently
  matches 48,764 relocation records from the five captured core libraries.
- New constructor-policy candidate: 169,654 interpreter vectors / 124 decision
  mutations PASS; 51 unprivileged Linux kernel/own-constructor cases PASS.
  Android interpreter build/static analysis PASS, binary SHA-256
  `f38819c83a338311cec1beccadc8d93318509562681470fbabd56ac659f9958f`.
  This is a data interpreter, not an installed policy or native loader.
- Generic Python discovery: 47 tests, 3 explicitly skipped optional parser cases;
  those same three passed in the separate parser-enabled 15-case run above.
- Native firmware loading, immutable library-root publication, Android SIGSYS
  reporting and the real offscreen adapter remain UNIMPLEMENTED / NOT admitted.
  Full/left/right genuine pen gates remain pending; do not repeat prior stock
  or display-only hardware tests to claim progress on that missing boundary.
- User asked whether the Nomad is needed and was told it can safely disconnect:
  all device reads finished, no device helper or transfer is running. Do not
  reconnect/use it implicitly during host work; revalidate before the next gate.
- Next: independent review of the complete updated source subset, then a bounded
  immutable-root/constructor-loader implementation with own-fixture adversarial
  evidence before any new device executable. No PR, push, install or merge here.

User authorized autonomous testing/fixes while sleeping, approximately through
2026-09-07 05:30 Asia/Jerusalem. No physical-action requests or audible pings.
The overnight heartbeat was paused at approximately 05:25 local while closing
the final segment, within the original 02:30 UTC deadline. The product update
confirmed PAUSED. It will not continue unattended beyond this window.
The user has explicitly approved the source/notes-only OpenAI review; this
continuation resumed directly. Do not send PDFs, annotations, firmware binaries
or credentials. Temporary device helpers from the prior segment are gone.
Do not merge or claim physical-pen validation.

## Final local-only segment — approximately 05:15 through 05:25 local

- Started from clean `104f2515c806564057701d2d4a4ea90e70e49824`.
  No completed hardware gate was repeated and no device operation was made.
- Pinned disassembly proves seven named BnMyService tool methods are RET stubs;
  actual Parcel/onTransact dispatch contains the native tool/queue/output work.
  A future private adapter cannot call those stubs and claim native behavior.
- Distinguished the Nomad e-ink-manager refresh path from the older Java
  SurfaceFlinger transaction branch. Native SFCommunicate control methods are
  no-ops, but sync_pw_buffer retains/fills a draw-buffer Mat and can lazily
  construct the physical output owner. It is not a proved offscreen output API.
- Inventoried six packaged arm64 libraries without extracting/loading them:
  hashes, dependencies and 87 initializer entries outside librecgnition itself.
  Packaged contents are NOT proof of the running linker's dependency selection.
- Authored findings and the next bounded initializer-only/private-dispatch
  proof are in `NATIVE_ENGINE_STARTUP.md` / `OFFSCREEN_ENGINE_EXPERIMENT.md`.
  This is documentation-only static evidence. It adds no runtime code and does
  not extend the exact-source clean review of the earlier isolation executable.
- Minimum validation: inspected the complete documentation diff and ran
  `git diff --check`. Existing executable sources/tests/builds are unchanged;
  no reason to rerun stock hardware or claim new behavioral coverage.
- No push, PR advancement, merge, package installation, module enablement,
  live mapping change, firmware startup or annotation mutation. The latest
  actual device ownership/hash/cleanup evidence remains the 04:38 mechanism run.
- Automation `prepare-next-native-viewport-tests` is PAUSED. No background
  command/reviewer/test was started during this final segment.

### Resume point, not a request for more pen actions yet

The isolated native loader/IPC/background-output adapter is still unimplemented.
Continue the bounded dependency/initializer admission proof described in the
experiment, with deterministic tests and independent exact-source review before
any new executable runs on the Nomad. Revalidate exclusive Nomad ownership,
process/firmware identity and 0700 staging before a future device operation.
Do not launch Document in a half viewport based on the isolation mechanism
pass. Genuine native write/erase/history/lasso/text-selection and canonical
saved-geometry checks in full/left/right frames remain pending. No second live
page can be admitted until that first genuine native viewport gate passes.

## Resumed after explicit review approval — approximately 04:30 local

### Latest completed boundary — approximately 04:40 local

- Code commit `e2a27320e6a5d56c60798663cc1ec0973b822bf3`; full updated
  39-file source review CLEAN. Both earlier supervisor findings closed.
- Exact binary `4775fe42b615970ece06ef49131d440a7fefc0043e432ef9411473438f67099c`
  ran on the verified Nomad: all five isolation cases PASS; core/filter tests
  also PASS as ordinary adb UID 2000. No firmware loaded or writer admitted.
- Parent namespace/node identities, Document/DrawPath PID/starttime, foreground
  File Manager and both stock hashes unchanged. All three staged tools, their
  directory and all child roots removed. No helper/reviewer/test remains running.
- Evidence: `build/isolation-hardware-20260907/`; scope and limitations in
  `ISOLATION_PROBE.md`. Do not repeat completed gates for duplicate evidence.
- The existing overnight heartbeat is ACTIVE again through 02:30 UTC, with the
  resolved review approval, completed mechanism gate and remaining boundaries
  in its updated prompt. No new or standalone task was created.
- Future executable staging: explicitly CREATE 0700 and verify before copying;
  Android shell mkdir inherited 0777 in this cooperative run. All executable
  hashes were rechecked unchanged and the directory restricted then removed.
- Actual Android parent-death delivery is NOT tested; denied-kill watchdog is
  Linux-host-tested only. No genuine native pen viewport is ready.
- New static-only finding: unwind FDEs bound all 28 top-level native initializers;
  direct dependency list and caveats recorded in `NATIVE_ENGINE_STARTUP.md`.
- Next bounded work is native startup/private IPC/background/output feasibility,
  plus parent-death recovery proof if extending the worker. Do not start firmware
  or touch the live DrawPath mapping under this mechanism's authority.

### Earlier in this resumed turn

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
