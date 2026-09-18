# Native-page viewport alpha

Status: **runnable visual diagnostic; not a formal admission, release gate, or
pen build.** The coordinator is intentionally smaller than the formal session
harness so the native-page/display idea can be tried before production
hardening is complete.

## What this alpha does

On Nomad `SN078C10015092` and the pinned 2026-06-16 firmware only, the runner:

1. requires the stock Document task, any BOOX planner task, and any earlier
   native-page host process/task/display to be absent. An otherwise idle stock
   Document process is allowed only when every one of its PDF/mark descriptors
   is a duplicate descriptor for the one authenticated parking PDF described
   below; a target, `.mark`, or unexpected document descriptor fails closed;
2. verifies the exact stock Document APK, then requires independent literal
   pins for the alpha package/version, signed APK, signer, reviewed unsigned
   APK, unsigned-source authority, and embedded `classes.dex`; it hashes the
   actual APK and CRC-reads the one exact embedded DEX instead of trusting the
   adjacent metadata to define those values;
3. authenticates the pinned source identities, generates both fixed disposable
   obligations and every random staging/quarantine path, and durably publishes
   their never-reused local mutation journal **before** parking provisioning or
   any fixture mutation. The append-only, hash-chained journal fsyncs every
   mutation intent before dispatch and records its settled evidence afterward;
   crash recovery uses its exact known path and never a directory scan. The
   runner then authenticates or no-clobber-provisions the persistent parking PDF
   and proves absence of its `.mark`. Each 128-bit-random staging leaf is
   proved absent twice and rechecked immediately before the pinned firmware's
   exact `toybox cp -n -T -v` no-clobber copy. A staged copy is owned only when
   the command exits zero, emits the exact raw ASCII/LF `cp 'SOURCE'\n` receipt
   with empty stderr, and its complete post-copy identity/size/hash passes. The
   same staged inode/device/UID/GID/size/hash is revalidated, then published by
   one non-retried `toybox mv -n -T -v` into the fixed target. Publication is
   admitted only when staging is absent and the fixed target contains that same
   renamed object. A skip, timeout, malformed/control-mutated receipt, raced-in
   identical-hash replacement, or mismatched target remains unowned and is
   never overwritten or deleted. The established source PDF and `.pdf.mark`
   are never opened for writing or changed;
4. creates one `1404 x 1872` host display with the host package's existing
   `PUBLIC | OWN_CONTENT_ONLY | DESTROY_CONTENT_ON_REMOVAL` policy;
5. immediately before launch, proves the owned display is empty, Document is
   absent globally, any idle Document process is either descriptor-free or
   retains only authenticated duplicate parking-PDF descriptors, and both
   staged file identities are unchanged; because the pinned firmware's stock
   `DocumentActivity` is non-exported, it then uses Magisk root to launch only
   that explicit activity, exact disposable file URI, PDF MIME type, owner user
   0, and returned bounded positive display ID. The root shell receives one
   generated, exact `am start` string; it accepts no caller command text,
   quoting, metacharacters, alternate path, component, action, MIME, or user;
6. treats every post-launch task observation as an unowned diagnostic candidate
   until Activity Manager proves one live Document task on that display, no
   sibling root task exists, the task/root-task contains one child only, the
   one strictly parsed retained `intent={...}` envelope co-scopes the exact
   VIEW action, disposable URI, PDF MIME, and DocumentActivity component with
   no duplicate fields or second intent, the stock process has only that
   fixture in its PDF/mark descriptors, and the PID/start time stays stable;
   an unowned candidate is never sent `BEGIN_CLOSE` and is never removed;
7. accepts the launcher's strict portrait presentation, starts the
   orientation-responsive visual host, authenticates and attaches the disposable
   Document task on the fixed virtual display, and only then requires a physical
   landscape presentation. This avoids spending the host's bounded attach
   watchdog on a human rotation;
8. captures FULL, LEFT, RIGHT, and FULL-return images in landscape, with the
   exact fixture/task/process/display identity checked both before and after
   every physical screenshot; every PNG must have complete chunk framing,
   valid CRCs, contiguous IDAT data, an exact bounded zlib decode, valid scanline
   filters, the expected RGB/RGBA encoding and dimensions, and no trailing data;
9. derives physical orientation only from one uniquely scoped display-0
   WindowManager record whose header has one canonical nonnegative `stacks`
   count: fixed `1404x1872 300dpi` initial metrics,
   current/app/frame dimensions, `DisplayInfo` rotation, frame rotation, and
   `mRotation` must all agree. The rotation line may carry only the observed
   stable `mDeferredRotationPauseCount=0` suffix; an in-progress/nonzero or
   malformed suffix is rejected. It waits for `1404x1872` rotation 0/2 in
   portrait, captures portrait FULL, then requires the exact starting
   `1872x1404` rotation 1/3 and captures FULL again;
10. starts the host's authenticated `BEGIN_CLOSE` handshake and revalidates the
    exact task/activity/display/PID/start-time/token/fixture scope. It then
    dispatches one non-retried, generated root `ACTION_VIEW` for the exact
    parking PDF on the same retained display. This is a normal close path only:
    it is never used to acquire or recover an ambiguous or unowned launch;
11. proves that the switch retained the same task, activity, display, PID,
    start time, and token while the exact native UI filename/page witness now
    identifies the parking document through exactly one displayed, on-screen
    filename node owned by the correct package, every process descriptor is
    parking-only, the authenticated parking file still has its pinned identity,
    and no parking `.mark` exists. On this firmware Android's task-level
    retained intent remains the stale disposable-target intent after the
    in-place switch, so that retained intent is recorded but is not treated as
    the post-switch document authority;
12. removes the one exact retained task, never retries that mutation, proves the
    task/component/token and every Document task/window absent globally, proves
    the owned display empty, acknowledges destruction, and releases the exact
    session display. It then repeatedly proves that the same still-live stock
    process holds only duplicate parking-PDF descriptors and no target,
    parking-mark, or unexpected descriptor before resolving the preregistered
    obligations. Any exact owned staging leftover is first removed once under
    the documented random-capability boundary; ambiguous or replaced staging
    paths are preserved. Each owned target is moved exactly once with
    `toybox mv -n -T -v` to its pre-generated hidden, 128-bit-random quarantine
    leaf in the same Download directory. Because this firmware emits no move
    receipt, authority comes only from the original path being absent and the
    quarantine retaining the exact device/inode/UID/GID/size/hash. A skipped,
    mismatched, replaced, or uncertain move is never retried or deleted. After
    one final identity revalidation the verified random quarantine is unlinked
    once, then proved absent twice. Clean completion also requires two fresh
    joint observations proving both disposable targets, both staging leaves,
    and both quarantine leaves absent. The authenticated parking PDF persists
    for the next run. Report fields for source and parking modification remain
    `null` until their independent final revalidations complete.

There is no touch, key, pen, accessibility, settings, orientation-setting,
writer, force-stop, process-kill, package-clear, task wildcard, or caller shell
command path. The two mutating root commands are a closed, generated launch
and a closed, generated parking switch, both required only because this exact
firmware does not export `DocumentActivity`; existing root reads plus those two
mutations are the only reviewed `su -c` strings. Absolute/case
aliases for `su` or a shell, alternate shell interpreters, `toybox sh`, and
extra root-command arguments fail closed. This alpha is
therefore explicitly rooted-Nomad/firmware-specific, not a portable or
production launch mechanism. The default `manual-physical-v1` rotation
authority requires physical rotation. The host itself continues to swallow
stylus/eraser events.

## Before running

- Connect only the authorized Nomad and authorize ADB.
- Close the stock Document reader normally.
- Leave the Nomad awake. The launcher may remain visibly portrait; after the
  disposable page opens, hold the Nomad physically in landscape. The alpha host
  follows the sensor and the runner verifies landscape before its first capture.
- Do not touch the page or use the pen during the run.

The preflight accepts either internally consistent portrait or landscape on
display 0. It stops without launching anything if a Document/BOOX task, a
Document descriptor other than duplicate descriptors for the authenticated
parking PDF, a prior host process/task/display, wrong firmware, wrong APK,
changed source fixture, or existing fixed disposable Download target is found.
It also refuses a missing, duplicated, malformed, or internally inconsistent
display-0 WindowManager record, including a missing/duplicate/malformed
`stacks` header suffix. InputManager's repeated
`SurfaceOrientation` value is not consulted. It does not guess how to clean an
earlier run.

Document-task absence is derived from canonical Activity Manager task records,
not from an unscoped package-name search. The only post-boundary supervisor
reference that may be ignored is the exact recognized stale, non-visible,
zero-sized target-task ghost left by this firmware after task removal. A
visible or nonzero target reference, or any target-bearing suffix that is not
that exact recognized ghost dialect, blocks absence and therefore blocks
cleanup.

Before it builds or installs anything, the one-click coordinator independently
requires one exact response for online state, serial, Nomad model, Android 30,
the full pinned firmware fingerprint, and owner user 0. It also holds one
exclusive per-device file lock from before that gate through install, capture,
cleanup, and any package rollback. A concurrent alpha transaction is refused.

## Run

From `native-viewport-probe`, run the closed one-click coordinator:

```powershell
.\run-native-page-alpha.ps1
```

It builds the byte-reproducible locally signed host from the frozen checkpoint,
requires the independently fixed artifact/signing tuple, verifies the actual
APK and DEX, installs that exact artifact while holding the device-session lock,
runs the capture session, and interprets the installer's prior-package receipt.
If the host was absent before the run, the
coordinator uninstalls only that newly installed package after the runner has
proved the exact task and display clean. If the identical host was already
present, it is left unchanged. A different compatible host is refused, and a
newly installed host is deliberately retained if cleanup is uncertain.

For unattended exploratory capture only, the wrapper exposes one additional,
closed rotation authority:

```powershell
.\run-native-page-alpha.ps1 -RotationAuthority adb-system-settings-v1
```

In this mode the wrapper launches
`native_page_alpha_rotation_controller.py`, not the runner directly. The
controller exclusively creates a hash-chained journal, proves the original
persisted settings `1/2`, locks portrait before starting the unbuffered child,
and consumes three exact, nonce-bound, flushed phase records. It maps only
`START_LANDSCAPE`, `PORTRAIT`, and `RETURN_LANDSCAPE` to the closed literal
rotation commands. Every mutation has a durable intent and two independent
post-command proofs. Before each mutation it revalidates the retained journal
path/descriptor, pinned tools, exact serial/model/SDK/firmware, and owner user.
After the child exits, including diagnostic-clean exit 3,
the controller always attempts literal `lock 2` followed by `free` and proves
the original persisted settings twice. It will not report a clean controller
transaction without that restoration proof.

The runner itself still never writes Android settings; it only emits a phase
after reaching the corresponding safe wait and then observes the same strict
WindowManager evidence. The controller's never-reused journal and evidence
files are written under `build/native-page-alpha-runs` with a random name.
If the controller process is interrupted after a durable rotation intent, its
`--restore-only` mode validates that exact journal and may execute only the
idempotent `lock 2` / `free` restoration sequence—never the child or an
intermediate test rotation.

Consequently the report has `rotationAuthority` set to
`adb-system-settings-v1`, `manualPhysicalRotation` set to `false`, and a clean
result named `ALPHA_ADB_ROTATION_CAPTURED_CLEAN`. Its `rotationController`
record binds the controller run ID and the three ordered phases. It is
exploratory evidence, not proof that the physical orientation sensor produced
the transition, and it can never establish formal admission. Omitting the
switch preserves the manual alpha and its `ALPHA_VISUAL_CAPTURED_CLEAN` result
unchanged.

There is no skip-build route: every one-click run reproduces the exact pinned
APK before install. The direct diagnostic runner remains available for
investigation, but it still requires the exact Nomad serial and independently
pinned metadata/APK pair:

```powershell
& 'C:\Users\mmkap\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' `
  -u `
  .\native_page_alpha_runner.py `
  --adb "$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe" `
  --serial SN078C10015092 `
  --host-metadata .\build\native-page-host-alpha\native-page-host-alpha.json `
  --output-root .\build\native-page-alpha-runs
```

That direct command is manual mode. Automated rotation is intentionally
available only through the wrapper/controller transaction; supplying
`adb-system-settings-v1` directly also requires the controller's unpredictable
`--rotation-controller-run-id` and a live controller consuming its phase
stream.

After the host first proves physical landscape and the four landscape images
are captured, the console asks for a physical portrait
rotation and then a return to the exact starting landscape rotation. The runner
only reads WindowManager's display-0 dimensions and agreeing rotation fields;
it never changes the device setting.

Each run creates a new local directory containing the durable
`mutation-authority.jsonl`, six unmodified physical-screen PNGs, and
`report.json`. A clean diagnostic result is exactly
`ALPHA_VISUAL_CAPTURED_CLEAN`. This name means only that the requested images
were captured and this alpha proved its narrow cleanup postconditions. It does
not establish visual correctness, formal harness admission, native pen routing,
writing safety, or release readiness.

The explicit ADB-controlled exploratory mode instead reports
`ALPHA_ADB_ROTATION_CAPTURED_CLEAN`; it carries the same limitations plus no
final physical-sensor proof.

A visual or preflight problem with completely proved cleanup is reported as
`ALPHA_DIAGNOSTIC_FAILED_CLEAN` (exit 3). The one-click coordinator may then
restore an initially absent host package before returning the failure. An
unresolved task, display, process, file, command sequence, or cleanup proof is
instead `ALPHA_FAILED_OR_CLEANUP_UNCERTAIN` (exit 2); an initially absent host
is retained for inspection in that case.

## Failure behavior

An ordinary failure triggers only cleanup for exact session-created identities
and preregistered copy obligations. If task launch may have happened but no
exact fixture-bound ownership can be derived, the observed candidate is never
parked, closed, or removed. The runner instead requires repeated global
 Document absence and repeated closure of all target/unexpected descriptors
 before it may quarantine any exact staged target. Parking is available only after
authenticated `BEGIN_CLOSE` for the already owned task; it is not an escape
hatch for uncertain ownership. If those proofs fail—or an attempted host
command leaves its sequence ambiguous—the runner does not invent an ID, send a
different command at that sequence, retry the document switch, delete an open
file or a replacement, directly close MuPDF, kill a process, or force-stop the
stock Document package. The report is marked
`ALPHA_FAILED_OR_CLEANUP_UNCERTAIN`; unresolved files and any newly installed
host are retained for operator inspection.

## Durable pre-mutation journal

After the pinned source PDF and `.mark` identities are retained, but before the
parking provisioner or any disposable-file mutation can run, the coordinator
creates the exclusive, externally known active receipt
`<output-root>/.native-page-alpha-active.jsonl`. The output root must already
exist and be a real directory. The fixed receipt is therefore recoverable
without listing or guessing a random run directory. A later run refuses to
start while this receipt remains unresolved. Its initial manifest binds the
never-reused run output directory, both source and fixed target identities,
both independent random staging paths, both independent random quarantine
paths, and every expected content hash. The file is fsynced and its entry in
the preexisting output root is durably published (POSIX link plus parent
directory fsync, or the pinned Windows `MOVEFILE_WRITE_THROUGH` equivalent)
before the first device mutation is eligible. The run directory is not relied
on as the discovery root or as cleanup authority.

Every record is byte-canonical ASCII/LF JSON with a sequence number, journal
UUID, previous-record SHA-256, current parking-provisioning state, complete
cleanup-obligation snapshot, and its own SHA-256. Recovery validates the closed
field types, initial defaults, immutable source/capability identities, unique
path relationships, event/detail grammar, and legal monotonic transition order;
freshly rehashed type changes, reordered keys, alternate whitespace, CRLF, and
illegal transitions are rejected. Successful copy/publish/quarantine/removal
settlements must also bind the exact retained identity, source/destination
observations, terminal postcondition, and coherent command reply or transport
error; a validly rehashed but semantically inconsistent settlement is rejected.
Each copy, publish, staging-removal, quarantine-move, and quarantine-removal
intent record is likewise restricted to its exact pre-dispatch state delta: it
cannot carry reply, postcondition, retention, or resolution evidence learned
after dispatch. A final `DEVICE_MUTATIONS_SETTLED` record is invalid if any
recorded attempt lacks its applicable terminal settlement event. Cleanup that
proves a staging or quarantine name absent twice without ever attempting a
mutation remains valid and does not invent an attempt/settlement pair.
Publication and quarantine-move terminal records also bind a coherent command
reply/transport-error pair. Their recorded postcondition must equal both the
event detail and the state derived from the retained source/destination
observations. A source-absent destination that is the exact renamed retained
object is a settled outcome and cannot be relabeled `UNSETTLED`; an ambiguous
postcondition record cannot carry invented observations.
`FIXTURE_STAGED` is an exact post-publication, pre-cleanup checkpoint for both
fixture members; it cannot claim staging, quarantine, or final absence before
those observations occur. Every event also constrains the other member's state.
The only cross-member deltas admitted are the runner's fixed batch operations:
both pre-copy absence digests, already-absent staging evidence while visiting
MARK before PDF, both quarantine preproofs, and no-attempt double-absence
evidence at the applicable cleanup/final boundary. A target-specific event
cannot replay or inject cleanup authority for the other member.
When a target was already absent and no quarantine move was attempted, final
quarantine absence is valid only with that target's canonical, durable
pre-quarantine double-absence digest. Removing either batch preproof invalidates
the final settlement even if all later records are freshly rehashed.
A copy, publish, parking provision, staging
removal, quarantine move, or quarantine removal is dispatched only after its
intent record is fsynced. Settlement evidence is appended and fsynced
afterward.

If power loss tears exactly the final append, strict recovery retains only the
prior complete canonical record as cleanup authority and reports the partial
tail separately. A live run never continues or claims rollback safety with a
torn tail. The coordinator binds the exact local file device/inode/size,
refuses replacement or symlink recovery, never overwrites or reuses a journal,
and reports its exact path and current head hash. A crash leaves the cleanup
capabilities recoverable from the fixed active path; recovery never discovers
names by scanning either the local run directory or device storage. Only after
all rollback predicates are proved does the runner exclusively move the exact
active receipt to that run's `mutation-authority.jsonl`, retaining the same
inode and bytes. A failed or uncertain run leaves the fixed active receipt in
place.

The record SHA-256 chain detects accidental corruption and inconsistent local
state only under the explicit non-hostile local-filesystem model. It is an
integrity chain, **not authentication** against an attacker able to rewrite and
rehash the local journal.

## Random staging boundary

Before any fixture copy, the runner generates independent cryptographically
random 128-bit PDF and mark staging capabilities in the same Download directory
and registers both alongside every cleanup obligation. It never scans for a
staging name. Both leaves must be absent twice, and the relevant leaf is checked
again immediately before its no-clobber copy. Copy authority requires the exact
raw LF receipt; text-line normalization is deliberately forbidden. After the
copy is fully identified, that identity is checked again immediately before a
single no-clobber rename into the fixed reader path. A lost rename reply is
settled only from staging absence plus the same exact renamed identity at the
target; the rename is never retried.

The first post-receipt identity observation has an explicit capability
assumption: the cryptographically random, never-scanned staging name remains
unguessable from the exact copy receipt through that immediate observation.
Thereafter, an identical-hash replacement with a different inode/device is
detected by the mandatory pre-publication revalidation and cannot be published.

If publication fails before moving an exact staged object, cleanup may remove
that leftover once after exact identity revalidation. POSIX has no
unlink-by-inode primitive, so this has the same explicit residual assumption as
quarantine removal: the independently random, never-scanned leaf remains an
unguessable capability between revalidation and the immediate fixed-argv
unlink. An ambiguous receipt, collision, replacement, or remaining object is
preserved. The report records every staging path, identity, mutation attempt,
transport result, and repeated absence proof.

## Random quarantine boundary

The runner generates independent cryptographically random 128-bit PDF and mark
quarantine leaves before any fixture mutation. It never discovers quarantine
authority by listing or scanning a directory. Both names must be observed
absent twice before the first rename.
The no-clobber move is issued at most once, and a lost reply is settled only by
the full source/destination identity matrix. The report preserves the generated
paths, pre-absence digest, retained identities, every move/remove attempt and
reply/transport state, and final absence state.

POSIX provides no unlink-by-inode primitive. The final unlink therefore has one
explicit residual assumption: after exact identity revalidation, the hidden
128-bit leaf remains an unguessable capability until the immediate fixed-argv
`toybox rm -f` executes. This does not authorize deletion of a fixed name, a
directory-discovered name, a mismatched object, or a replacement. If the name
exists after the single attempt, changes identity, or reappears during either
absence proof, cleanup fails closed and the remaining object is retained.

## Authenticated parking cleanup

The fixed parking authority is
`/storage/emulated/0/Download/.NativeViewportParking-Alpha-2eeadd7.pdf`.
It is a persistent hidden test artifact whose bytes must match the pinned
source-PDF SHA-256
`e470c33c6525e02acf88e51352d73b7ed8b6c1591be8d40629a42c708484e720`.
Its sibling `.mark` must be absent. If the PDF is missing, the runner records and
fsyncs the provisioning attempt first, then performs one exact no-clobber copy
from the pinned source and never retries it. A lost reply is settled only by a
fresh exact regular-file/hash observation plus a fresh absent-`.mark`
observation. Hash/size/type drift, an existing `.mark`, or ambiguous post-copy
observation fails closed; the runner never repairs, overwrites, or deletes
drifted parking state. Once provisioning is reached, neither rollback-safe nor
diagnostic-clean may be reported until the retained parking identity and absent
`.mark` have been freshly revalidated at final cleanup and the parking
unchanged tri-state is known true. The parking PDF itself is not a disposable
copy obligation and remains after a clean run.

The pinned firmware keeps its stock Document process alive and may retain the
last opened PDF descriptor after a task is removed. Clean teardown therefore
uses an authenticated in-place parking transition instead of requiring the
stock process to close every PDF descriptor. After authenticated
`BEGIN_CLOSE`, and only while the original task is still fully owned, the
runner sends exactly one non-retried explicit root `ACTION_VIEW` for the fixed
parking PDF to the same retained display. Success requires continuity of the
same task/activity/PID/start-time/display/token plus all of the following
independent evidence:

- exactly one displayed, on-screen filename node from the correct package, plus
  the exact native page witness, identifies the parking PDF;
- all PDF descriptors refer to the exact authenticated parking file (duplicate
  descriptors are allowed);
- the disposable target has zero open PDF/mark descriptors, including no
  deleted-path descriptor alias;
- the parking `.mark` remains absent; and
- the source fixture, disposable target, and parking authorities revalidate.

Android's retained task intent is known to remain the old disposable-target
intent across this same-activity switch on the pinned firmware. It is not
silently rewritten or used as the post-switch authority; the stale value is
required to be internally well formed and is preserved as explicit diagnostic
evidence while the identity, UI, descriptor, and on-disk witnesses above prove
the active parking document.

Supernote may atomically replace or recreate the disposable target `.mark`
during the authenticated parking switch. That narrow transition is accepted
only after the target has no open descriptor, only for the exact registered
cleanup path, and only when the resulting object is a regular file whose
size and SHA-256 still match the pinned staged `.mark` (SHA-256
`b95c02b05abd9a4f5a3106ffbe442f1f893256a66f8cac3628f04d300992ffd6`).
An inode change is evidence to record, not permission to accept different
content. Replacement at any earlier/later boundary, any unexpected path, or
any size/hash/type mismatch fails closed. Once that one authorized recreated
object is accepted, its exact device/inode/size/hash identity becomes retained
authority and must remain stable on every subsequent revalidation.

Only after parking is proved does the runner remove the exact retained task,
release the authenticated host/display, prove global Document task/window
absence, and repeatedly prove that the same stock process has parking-only
descriptors. It may then delete the exact closed disposable PDF and `.mark`.
Neither deletion mutation is retried, and clean completion requires two new
joint observations that both disposable names are absent after deletion.
It never force-stops stock Document, directly closes MuPDF, retries a parking
switch, deletes an open file, or uses parking to recover an ambiguous/unowned
launch.

The hardware microtest establishing this firmware-specific behavior retained
PID `2140`, task `4634`, and the task/token identity through the switch. The
native UI showed the parking document; the target descriptor count was `0`,
the parking descriptor count was `2`, and no parking `.mark` appeared. The
retained task intent still named the disposable target. The target `.mark`
kept its exact pinned content hash while its inode changed during the switch.
Those observations define the narrow accepted dialect; they do not authorize
a looser cleanup path.

ADB-controlled rotation remains diagnostic-only and is independent of parking
cleanup. Any controller that changes rotation must maintain a separate durable
pre-mutation journal and restore and verify the original settings after every
success or failure; the parking protocol does not replace or weaken that
obligation.

The one-click coordinator manages only its own newly installed host package.
Do not manually uninstall or replace it while a host task or display remains
live.

## Focused host-only checks

```powershell
& 'C:\Users\mmkap\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' `
  -m unittest -v test_native_page_alpha_runner `
  test_native_page_alpha_rotation_controller
```

These tests exercise the closed command set, exact serial, wrapper device gate
and lock lifetime, byte-exact LF copy receipts, random staging registration,
fixed-path durable pre-mutation receipt publication, refusal of unresolved
prior receipts, strict canonical/schema/state-machine recovery, one-torn-tail
recovery at copy/publish crash boundaries, clean archival, symlink/tamper
refusal, ambiguous parking settlement,
identical-hash replacement races, staging/target/quarantine collisions,
publish/move/remove timeouts and no-retry settlement, leftover-stage cleanup,
source/parking report tri-states, replacement refusal, joint
target/staging/quarantine absence, global descriptor closure,
fixture/FD and one-child root-task gates, unowned-candidate refusal, host
envelope fields, strict PNG decoding, fixed actual APK/DEX authority, the exact
real Nomad WindowManager display dialect, authenticated parking-only teardown,
duplicate/deleted/unexpected descriptor failures, and the permanent
diagnostic-only label. They do not contact or claim a pass on hardware.
