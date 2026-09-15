# Native Page Host — visual-only diagnostic

This is a separate, bounded Android package for proving one genuine native
Document page inside a rectangular viewport. It is **not** RTL Reader, Native
Spread, a PDF renderer, or a pen engine.

Safety boundary:

- fixed `1404 × 1872` VirtualDisplay at the physical display density;
- `PUBLIC | OWN_CONTENT_ONLY | DESTROY_CONTENT_ON_REMOVAL` flags;
- no requested permissions, storage access, network access, root execution,
  accessibility, LSPosed hooks, input injection, or Document launch code;
- stylus and eraser MotionEvents received by the host are swallowed;
- fresh random UUID capability and monotonic generation for every host instance;
- authenticated commands carry a strictly monotonic sequence number; an exact
  retry is idempotent in every later phase, while gaps, reordering, and sequence
  equivocation are sticky authenticated contradictions;
- the host Activity itself must be resumed, visible, focused, and attached to
  Android's `DEFAULT_DISPLAY` at its admitted density before display creation;
  while the lifecycle is still `STARTABLE`, a dedicated pre-allocation check
  revalidates that physical host plus the already measured canonical frame
  without inventing a display ID or display ownership. Only after that exact
  check does display creation begin. Once allocation returns a positive ID, the
  stricter allocated-display authority replaces the pre-allocation check;
  this authority is continuously rechecked with virtual-display metrics and the
  exact physical SurfaceView frame;
- Android may briefly pause/refocus the `singleTask` host while delivering any
  command through `onNewIntent`. That transition has one 1.5-second fail-closed
  suspension: live host authority is explicitly withdrawn and at most one exact,
  already-authenticated next attach, placement, close, or destroy command may be
  retained as immutable typed values. It is revalidated and applied only after
  resumed, visible, focused default-display and physical-frame authority return.
  The first suspension establishes one absolute deadline; reacquisition,
  undrainable layout, another pause, or repeated configuration/geometry churn
  cannot renew it. A configuration callback stops the display watchdog and
  explicitly suspends frame authority before Android changes the layout. The
  callback also binds the pending frame to the exact portrait (`1404x1872`) or
  landscape (`1872x1404`) configuration. The old orientation's otherwise-valid
  rectangle stays transitional and cannot complete the handoff. The watchdog
  resumes only after the expected canonical frame and runtime authority are
  measured again within that original deadline.
  A second, equivocated, invalid-phase, expired, or persistently paused delivery
  triggers emergency cleanup; presentation commands never mutate lifecycle state
  while host authority is suspended. Exact already-accepted presentation replays
  remain observational. Exact absence acknowledgments are cleanup-only and may
  authorize terminal release while paused without reacquiring presentation
  authority;
- a foreign Document task must be launched and verified by an external root/ADB
  coordinator, then acknowledged with its exact component, task ID, PID, UID
  `1000`, process start ticks, and SHA-256 of the coordinator's exact verified
  attachment evidence before placement is accepted;
- the only admitted foreign component is
  `com.supernote.document/com.supernote.document.document.DocumentActivity`;
- normal display release requires an exact acknowledgment that the same foreign
  task has already been destroyed, and that acknowledgment is ineligible until
  `BEGIN_CLOSE` (or an already-established unexpected-loss cleanup path);
  an independently proved empty display instead uses the distinct healthy
  pre-attach abort or existing failed-session absence acknowledgment;
- `RELEASED` is terminal for Android layout and display-allocation callbacks.
  A queued `SurfaceView` or layout callback delivered after acknowledged
  release is ignored before authority revalidation and cannot allocate another
  display; failed release remains `FAILED`, so this guard does not suppress its
  exact retry/cleanup authority;
- unauthenticated, stale, null, and unknown command traffic is ignored without
  changing the live session; exact authenticated retries are idempotent;
- placement is a two-phase operation: the authenticated sequence records a
  pending request, but it is not committed or reported ready until Android's
  measured SurfaceView bounds exactly match the sequence-bound target. During
  the bounded transition only the exact old or target frame is admissible;
- authenticated contradictions, internal faults, and protocol timeouts are
  sticky protocol/operational failures, but do not fabricate a physical host
  loss. They keep ordinary commands closed while the unchanged physical frame,
  resumed/visible/focused default-display identity, density, surface, and
  VirtualDisplay metrics remain continuously enforced so an exact foreign-task
  cleanup handshake can complete. Actual physical-density drift, unexpected
  surface/display loss, or a failed bounded host transition is host-authority
  loss and releases with destroy-content semantics; it never migrates the
  foreign task. A `VirtualDisplay.release()`
  exception never claims removal. While the Activity remains alive it retains
  the exact object for an authenticated retry. If release also fails during
  `onDestroy`, the dead Activity does not claim a fictional retry route: it
  terminates its own exact app process and Android becomes the cleanup owner for
  that process's Binder/display resources. No static session, PID, or
  cross-session cleanup authority is retained;
- display readiness is not published until the fixed buffer, canonical physical
  SurfaceView rectangle, and actual VirtualDisplay width, height, and density all
  match. The actual positive display ID is admitted into lifecycle authority
  immediately after allocation and before the first fallible metrics query, so
  a metrics error plus release error still leaves the exact failed-session
  cleanup envelope addressable. Those display metrics and physical density are
  rechecked continuously. The allocated display ID is read exactly once from
  the first returned `Display` and retained before later checks. If the returned
  VirtualDisplay cannot yield a positive ID and its emergency release
  also throws, no externally addressable retry key exists, so the host escalates
  immediately to the same self-process-death cleanup owner instead of retaining
  an unreachable object.

The package never launches `com.supernote.document`. The coordinator must use a
firmware-pinned launch route and independently verify the resulting task/display
identity before sending `ACK_FOREIGN_ATTACHED`.

The Python `HostAuthority` retains the exact process-authority and provider
objects supplied at construction, in addition to leaving its public slots
available for inspection. Every provider or retained-process callback is made
only through the private retained reference. Public-slot identity is checked
before and after every callback, including exceptional returns. A replacement
is rejected even when it offers equivalent behavior or the same monotonic
domain. In particular, substitution during `now_ns()` or `verify()` fails
before any host command reaches either the original or replacement provider.

## Exact presentation rectangles

The canonical display buffer never changes. Only its physical SurfaceView frame
changes:

| Placement | Physical orientation | Rectangle `(left, top, width, height)` |
| --- | --- | --- |
| FULL | portrait | `0, 0, 1404, 1872` |
| LEFT | landscape | `0, 78, 936, 1248` |
| RIGHT | landscape | `936, 78, 936, 1248` |
| FULL | landscape | `409, 0, 1053, 1404` |

Portrait always presents FULL, even when LEFT or RIGHT remains the requested
landscape placement.

## External command protocol

All commands are explicit starts of the already-running `singleTask` activity,
so Android delivers them through `onNewIntent`. Starting a command action as a
fresh activity fails closed. Every command includes the exact values printed by
the `DISPLAY_READY` log:

```text
--es session <UUID> --el generation <N> --ei display <ID> --el sequence <N>
```

Attach and destroy acknowledgments also include:

```text
--es foreignPackage com.supernote.document
--es foreignComponent <flattened exact component>
--ei foreignTask <positive task ID>
--ei foreignPid <positive PID>
--ei foreignUid 1000
--es foreignStartTicks <canonical /proc PID stat start ticks>
--es foreignEvidenceSha256 <64 lowercase hex characters>
```

Only a newly accepted attach whose lifecycle is exactly `ACTIVE` emits `READY`
and cancels the attach timeout. An exact replay of that attach is always logged
as neutral `ATTACH_REPLAY state=<actual-state>`—including after placement,
close, or a sticky/release failure—and never republishes ACTIVE readiness or
changes cleanup/timeouts. A failed-session replay bypasses live display/frame
admission only far enough for the lifecycle to prove that it is the exact
already-accepted command; a new or equivocated attach remains rejected.

The sole exception before ordinary command admission is the bounded Android
pause/refocus transition described above. It does not accept a command while
paused: it reserves one exact next envelope and only the typed payload required
by that action (the independently checked foreign-task identity for attach or
destroy). Existing attach, placement, and destroy timeouts continue to run. The
host either applies that reservation after full authority reacquisition or
destroys the visual-only display when the 1.5-second boundary expires. Exact
already-committed replays remain neutral and cannot create a pending command.
`ACK_NO_FOREIGN_AFTER_FAILURE` is never deferred: it exists only after a sticky
failure and uses the narrow failed-session cleanup path.
`ACK_NO_FOREIGN_PRE_ATTACH_ABORT` is also never deferred. After the exact live
envelope is authenticated, this cleanup-only command goes directly to the
healthy-empty lifecycle gate, including while the host is paused. It neither
reacquires presentation authority nor waits for a presentation deadline/frame.
An existing deferred command makes this healthy-empty gate ineligible.

Likewise, only a newly accepted `BEGIN_CLOSE` emits `WAIT_FOREIGN_DESTROY`,
cancels a pending placement timeout, and arms the destruction timeout. An exact
close replay emits neutral `CLOSE_REPLAY state=<actual-state>` and does not
change any timer, state, or release-retry authority—even after destroy
authorization or a `VirtualDisplay.release()` failure. Placement replays are
also observational only. Exact destroy/empty-abort replays are labeled as
replays and may retry only an already-authorized failed display release.

Actions:

```text
com.techrebbe.supernote.nativepagehost.ACK_FOREIGN_ATTACHED
com.techrebbe.supernote.nativepagehost.PLACE_FULL
com.techrebbe.supernote.nativepagehost.PLACE_LEFT
com.techrebbe.supernote.nativepagehost.PLACE_RIGHT
com.techrebbe.supernote.nativepagehost.BEGIN_CLOSE
com.techrebbe.supernote.nativepagehost.ACK_FOREIGN_DESTROYED
com.techrebbe.supernote.nativepagehost.ACK_NO_FOREIGN_AFTER_FAILURE
com.techrebbe.supernote.nativepagehost.ACK_NO_FOREIGN_PRE_ATTACH_ABORT
```

Before any foreign task is admitted or deferred, a healthy host in exactly
`DISPLAY_ALLOCATED` or `WAITING_FOR_FOREIGN_ATTACH` may be terminated without
manufacturing a timeout or protocol failure. The external coordinator must
independently preserve exact, display/session-bound evidence that no foreign
task exists, then send `ACK_NO_FOREIGN_PRE_ATTACH_ABORT` with the current
session/generation/positive display ID, next sequence, and
`--es absenceEvidenceSha256 <64 lowercase hex>`. The host accepts only an exact
String with that lowercase digest format; it does not collect or interpret the
external proof. Payload access happens only after envelope authentication.

First acceptance emits `EMPTY_PRE_ATTACH_ABORT`, authorizes normal terminal
release, and preserves a healthy status unless the release actually fails. An
identical replay emits `EMPTY_PRE_ATTACH_ABORT_REPLAY`, never a fresh abort or
`READY`. If release throws, only the same healthy-abort action, sequence, and
evidence digest may retry that authorization; a new healthy-abort sequence,
changed digest, or fresh `ACK_NO_FOREIGN_AFTER_FAILURE` substitution is rejected.
Fresh healthy-abort commands after attach, during close, after failure or
release, without a retained positive display, or with a deferred command are
ineligible. Existing failed-session cleanup remains distinct and unchanged for
sessions that never accepted a healthy abort.

`BEGIN_CLOSE` does not release the display. The coordinator first destroys and
verifies absence of the exact acknowledged foreign task, then sends
`ACK_FOREIGN_DESTROYED` with the same task identity. Only then does the host
release and finish. If a destruction acknowledgment times out, the failure stays
visible and exact late acknowledgment remains the only normal cleanup route.

If any sticky failure occurs before a foreign task was admitted, the external
coordinator may perform and preserve an exact no-foreign-task proof, then send
`ACK_NO_FOREIGN_AFTER_FAILURE` with the next expected sequence and
`--es absenceEvidenceSha256 <64 lowercase hex>`. If failure occurs after attach,
`BEGIN_CLOSE` remains reachable, followed by destruction and the exact task ACK.
After emergency display destruction, these exact cleanup handshakes remain
reachable without reopening general command admission. Thus neither a pre- nor
post-attach contradiction can strand an acknowledged task or retained display.

Back exits only before display authority exists or after emergency destruction
when no foreign task was ever acknowledged. Once an exact foreign task has been
acknowledged, Back stays blocked until its exact destruction is acknowledged.

## Build evidence

The deterministic build first rejects inherited JVM option/classpath hooks and
every nonempty `PYTHON*` environment variable. It does not execute the installed
Python interpreter at all. Before the first interpreter launch, the build copies
the allowlisted interpreter, runtime DLLs, standard library, and extension
modules into a private retained snapshot, excludes `site-packages` and bytecode
caches, rejects the runtime root or any descendant file/directory reparse point,
and authenticates a fixed 838-record namespace: 783 exact files and 55 exact
directories, with every file name, length, and digest bound. The private
interpreter version is checked inside every authenticated bootstrap after that
complete admission. Two of those files are a raw deterministic stored ZIP of
the exact encoding package and an adjacent locked `python312._pth` whose sole
entry is that ZIP; no mutable filesystem directory is searchable at startup.

The reviewed runtime is the official bundled dependency version `26.909.12148`
(Python `3.12.14`). A bundle upgrade changed the executable/DLL bytes; the old
closure failed admission before any Python launch. The refreshed closure was
independently recomputed from that official bundle: the same 783-file/55-directory
topology, now SHA-256
`3aa15c911493f4107b5860a9bccd9107781fe63efb56e07f83a72078c6d49f57`.
The build does not discover or accept a new expected digest from its own output.

Python then runs only with `-I -S -B` through a frozen-module bootstrap. Before
reviewed code runs, the bootstrap strictly parses the retained namespace
manifest, independently enumerates the actual runtime tree, rejects every
unexpected package-shadow file/directory and reparse alias, and installs a
process-lifetime audit hook. It replaces ordinary path search with only builtin,
frozen, and an exact manifest-backed source/extension finder, then empties
`sys.path`, `sys.path_hooks`, and the importer cache. The hook fails any unlisted
runtime/review-root open or import origin, any protected-tree mutation, or any
path drift, so a transient insertion between the PowerShell check and import is
never a candidate and cannot execute. Adversarial checks cover an extra file, an
`argparse` package-shadow directory, a directory junction, synthetic transient
open/import/mutation attempts, and retained-handle writer denial. The entire
file/directory inventory is reauthenticated before and after every reviewed
Python invocation. In addition, the three executable Python helpers and the
inline bootstrap have explicit, review-maintained SHA-256 pins. Helper snapshots
are retained against replacement and checked before compilation by the exact
source loader as well as before and after every invocation. The build also
tests retained hostile substitutes for all three helpers and a changed inline
bootstrap against the actual pre-execution gate before launching Python; none
of those changed bytes is executed. The running build script is deliberately
not allowed to self-authenticate: its exact-head review
and caller are the outer trust root, while its retained snapshot is the one
immutable policy used by the build's internal tests.
That snapshot must equal the already-parsed root script text, catching disk
replacement after parsing; this is an integrity comparison, not self-authentication.
The build opens
retained deny-write/delete handles for the pinned
JDK 17, Android 35 platform/build-tools, and Python 3.12 executable/runtime DLL, then
verifies their SHA-256 authority before the first execution. It copies every
source through one descriptor into continuously retained private input
authority, then compiles and packages twice from only that snapshot. Fixed,
reviewed source/class/DEX/APK hashes bind each raw compiler output to those exact
retained inputs before the raw path is reopened; the build never derives its
expected compiler output from the output under test. Every generated class,
DEX, intermediate APK, `javap` record, and final APK is then captured into a
retained authority before the next phase consumes it.
`javap` stdout is captured as raw bytes rather than serialized by the invoking
PowerShell engine. It is strictly decoded as UTF-8, rejects a BOM, embedded NUL,
lone CR, and mixed newline forms, then is written as BOM-free UTF-8 with LF and
exactly one terminal newline. An independent regression invokes this exact
retained policy through both required, explicit Windows PowerShell 5.1 and
PowerShell 7 launcher authorities and requires identical fixed bytes and
SHA-256 before packaging proceeds. `PATH` is never used to select them. Each
launcher has a fixed path/role/hash and single-link, non-reparse descriptor
identity retained against write/delete for the complete child lifetime; the
child image is checked against that admitted launcher. The exact policy bytes
are streamed over stdin, so neither engine reopens a mutable policy path.
Both evidence-only children use `-NoProfile -NonInteractive -NoLogo`, no visible
window, and a newly created private working directory. Inherited `DOTNET_`,
`COREHOST_`, `CORECLR_`, `COMPlus_`, `COR_`, and PowerShell startup/module-path
variables are removed, including case variants and unknown future suffixes.
Hostile-PATH, role substitution, hardlink/reparse, live write/delete denial,
and disposable engine/policy write/rename/replacement regressions guard this
boundary. This authenticates the launcher and
policy boundary, not the complete Windows/.NET runtime closure: WinPS system
CLR/GAC components and PowerShell 7's adjacent CoreCLR assemblies remain part
of the trusted platform runtime for this cross-engine serialization check.
Inspection reads each APK through a regular-file descriptor and runs every
`aapt` query only while the parent-retained APK, DEX, and tool handles are
proven to deny both write and delete/replacement access before and after the
queries. The packaged DEX must be byte-for-byte identical to the reviewed
compiler output and must contain exactly the allowed class topology;
header-shaped or substituted DEX files fail closed. Final APK/DEX hashes are
cross-checked against `package-authority.json`. Inspector evidence is returned
as one bounded canonical authenticated stdout bundle and decoded directly into
retained output handles, so there is no post-inspector evidence path to replace.
Every evidence record is independently size/hash checked, both builds must
produce the same authority bytes, and retained tool
hashes are rechecked after both passes.

The reproducible package produced here is intentionally unsigned. Runtime
authority treats it separately from the installable signed image: the reviewed
unsigned APK, installed signed `base.apk`, packaged DEX, signer-certificate
SHA-256, version code, and version name are all independent exact pins. A
matching DEX or package name cannot substitute for the exact installed APK and
signer, and the signed image cannot become the reviewed compiler-output
authority merely because Android accepts its signature.
All retained build, snapshot, artifact, and launcher handles are released from
a script-level `finally` boundary on both success and failure.
Evidence records that descriptor identities were revalidated and publishes only
stable names, sizes, and hashes, plus toolchain authority and executable class
inventory. `DisplayProbeLayout`, its `Placement` enum, exact
source, bytecode, and mutation tests are inside this same authority surface. The
package gate checks an exact manifest
topology/attribute allowlist and Java bytecode semantics for stylus/eraser
swallowing, the `1404 x 1872` fixed buffer, exact display flags, authenticated
lifecycle calls, density teardown, and Back cleanup authority.

The package intentionally contains no coordinator script: foreign task launch,
verification, and destruction must remain a separately reviewed root boundary.
