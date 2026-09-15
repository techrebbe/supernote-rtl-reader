# Native page external authority v2 — frozen integration boundary

Status: **design only; hardware admission remains blocked**.

This document fixes the ownership boundary between the nested native-page
observer, Android system state, the diagnostic display host, and immutable file
evidence.  It is deliberately narrower than a production RTL spread: the first
gate is visual-only and must not publish writer authority or mutate the stock
reader.

## Bounded claim

One exact, already-running stock `DocumentActivity` may be observed while its
outer Android task is placed FULL -> LEFT -> RIGHT -> FULL.  A passing record
proves only that the same authenticated native page graph and raw page geometry
survived those presentation changes.  It does not prove annotation-coordinate
semantics, safe pen routing, saving, or two simultaneous writable pages.

## Independent authorities

The observer owns only a stable double-read of the direct, pinned in-process
object graph described by `NATIVE_PAGE_GRAPH_SNAPSHOT_V2_DESIGN.md`.

The external coordinator owns and independently revalidates:

- the authorized ADB serial and device state;
- target package, process ID, `/proc/<pid>/stat` start time, and exact command
  line;
- the one Android task/activity token, its display, resumed/visible state, and
  the diagnostic host's authenticated session and display generation;
- exact firmware APK/framework/native-module byte authorities;
- exact original-PDF, nullable `.mark`, and URI-resolution authorities;
- the requested FULL/LEFT/RIGHT host rectangle and its acknowledged applied
  generation;
- the hard deadline, Frida lifecycle, callback quiescence, and target liveness;
- complete before/after evidence equality.

No in-process object field may authorize task ID, display ID, host generation,
file identity, or a physical-input lease.  No manifest-selected class or field
name is allowed.

The v2 manifest uses exactly these coordinator authorities:

```text
coordinator.authority = rtl-reader-native-page-graph-coordinator-v2
coordinator.observerSessionId = 16..128 [A-Za-z0-9._:-] characters
coordinator.absoluteMonotonicDeadlineNs = canonical decimal string
coordinator.hardDeadlineMs = integer 250..10000
coordinator.maxJavaChooseWalks = 1
coordinator.retainedRootSamples = 2
coordinator.detachOnDeadline = true
coordinator.abortOnAnyError = true
coordinator.verifyTargetLivenessAfter = true
coordinator.noRetry = true

externalSession.authority = rtl-reader-native-page-external-session-v2
externalSession.authorizedSerial = SN078C10015092
externalSession.taskId = nonnegative integer
externalSession.displayId = integer 1..1024 (the visual gate never admits display 0)
externalSession.hostSessionId = 16..128 [A-Za-z0-9._:-] characters
externalSession.displayGeneration = positive safe integer
```

The absolute deadline is authenticated in the manifest, but the observer only
validates and echoes that external binding.  The runner is the sole monotonic
clock and hard-timeout authority.  No clock callback is injected into the
target: an in-process clock would require either a non-monotonic JavaScript
wall clock or a forbidden framework/native call.  A manifest-only deadline is
not sufficient; the runner starts the timer before attach, rejects late
callbacks, and independently forces unload/detach on expiry.

## Host-side executable authority

The production coordinator must not hash one `adb.exe` and later execute a
replaceable pathname.  On Windows it must retain no-write/no-delete handles to
the exact `adb.exe`, `AdbWinApi.dll`, and `AdbWinUsbApi.dll` identities for the
entire run, hash the bytes through those handles, and revalidate the retained
handles after the final command.  Process creation must use the locked adjacent
triple. Each executable/DLL must be one non-reparse file with exactly one hard
link. Unsupported handle or sharing semantics fail closed.

All ADB calls use a fixed argv vector with `-s SN078C10015092`; there is no
shell string, implicit device selection, environment-selected serial, or
automatic retry.  Output and time are bounded per command.

The retained client/DLL triple alone does not authenticate an already-running
ADB server.  Production admission therefore also requires a separately
authenticated server boundary: launch the retained `adb.exe` on a private,
fixed-for-the-run TCP port under a fixed minimal environment, prove that the
server process image is the same retained executable authority, pass that port
and the explicit serial on every command, and terminate only that exact server
during cleanup.  Ambient `ADB_SERVER_SOCKET`, `ANDROID_ADB_SERVER_PORT`,
`ANDROID_SERIAL`, vendor-key, or other ADB-routing overrides are rejected or
removed before launch.  Reusing the default shared ADB server is not admitted.

The locally validated bundle on 2026-09-11 is Android platform-tools 37.0.1
(`adb` protocol version 1.0.41):

```text
adb.exe         b4a6b455702684652cccf7b46258b29e653538904359a58fd4931cf3ef286b3f
AdbWinApi.dll   c1d653030b4bde65d3e07e4d0b0979e17be56df1436cdd15528630f27808050d
AdbWinUsbApi.dll 0710e894d9b40f71a670c13c694079d564c92c1279da382cfe4850983aaebe1b
```

These are explicit build-host pins, not a general endorsement of every binary
with the same version string.

## Frida executable authority

Frida has the same executable-boundary requirement. The coordinator must bind
the exact local Python runtime, Frida Python package/native extension and their
loaded native dependencies, plus the exact device-side `frida-server` bytes,
path, UID, PID/start time and command line. The temporary root server is
started only from an exact verified staging path, its version/protocol handshake
must match the retained client authority, and the coordinator retains enough
process authority to terminate only that instance after callback quiescence.
An ambient Frida service, unpinned Python environment or path-resolved module
import is not admitted.

## Android task/display evidence

ActivityManager evidence is captured before and after every observer sample and
at every host placement acknowledgement.  Admission requires exactly one live
`com.supernote.document.document.DocumentActivity` belonging to the pinned
target PID and task.  The activity must be resumed and visible on the exact
expected display during the sample.  A background/paused activity is not an
observation target.

The host session is a separate authenticated record containing at least:

- host package/APK identity;
- unguessable run ID;
- monotonically increasing session and placement generations;
- requested and measured display width, height, density, and rectangle;
- host task/activity token and display ID;
- applied-state acknowledgement emitted only after the measured state matches.

Any task, activity-token, display, lifecycle, bounds, density, or generation
drift rejects the sample.  The current physical-display state observed on
2026-09-11 — task 4538 paused behind File Manager — is useful calibration
evidence but is intentionally inadmissible for a live sample.

## File and URI evidence

The provider captures bytes and metadata independently rather than echoing the
manifest.  It emits canonical JSON plus a detached SHA-256.  Every present file
record binds path, size, SHA-256, device/inode/mode/UID/GID, and nanosecond
timestamps.  The original PDF must be present.  A missing `.mark` is a valid,
explicit nullable state; it must not be treated as unsaved or corrupt ink.

The ordinary collector runs as Android UID/GID 2000 (`shell`).  Root may be
used only for a separately reviewed, exact protected-file staging/read step
whose target and destination are fixed and whose ownership/mode/size/digest are
verified before use.  Root is never used to run the SavedInk collector or to
broaden a path search.

For `file://`, the normalized URI and exact resolved path are bound together.
For `content://`, the provider package and exact provider APK must also be
bound.  Unsupported or ambiguous resolution fails explicitly.  Absolute host
paths are diagnostic only and never device authority.

Firmware byte pins are captured from the device and compared with the reviewed
host copies.  For the currently pinned firmware the reviewed calibration
evidence is:

- `SupernoteDocument.apk` SHA-256
  `f008c86ddc42008c36b431410cbc3b29057b4aad9bc26c3577ee13b39b230482`;
- `framework.jar` SHA-256
  `c3a525a7ef16363a93412182cce693f46dfa1395a570e9620da0d4e27a59631d`.

These hashes do not by themselves admit a run; path, stat, package/process, and
before/after evidence must agree as well.

## Capture order

For each FULL/LEFT/RIGHT/FULL stage:

1. authenticate the device, target process, task/display, host session, files,
   URI resolution, firmware, and exact tooling;
2. verify that the pen lease is held and no document input can reach the stock
   writer;
3. wait for the host's exact applied-placement acknowledgement;
4. capture external evidence `before`;
5. attach once, execute one bounded nested-graph walk and double sample, unload,
   detach, and seal the callback channel;
6. capture external evidence `after` and require exact stability;
7. revalidate process liveness and every retained host/tool authority;
8. append one canonical stage record to the run ledger.

The run has no automatic retry.  A failed or timed-out stage aborts the visual
gate and begins reviewed cleanup; it does not continue to the next placement.

## Cleanup order

Cleanup is transactional and fail closed:

1. detach/seal Frida;
2. restore FULL placement if the authenticated foreign task still exists;
3. destroy only the exact foreign host task/session;
4. destroy its exact VirtualDisplay;
5. verify the stock task/process is still live and no foreign surface remains;
6. release the pen lease last;
7. reopen/foreground the untouched stock reader only through a separately
   authenticated route;
8. prove original PDF and nullable `.mark` evidence are unchanged.

If ownership is uncertain, do not issue a broad task, display, process, or file
cleanup command.  Preserve the ledger and require manual review.

The host's exact empty/destroyed acknowledgement action is
`ACK_NO_FOREIGN_AFTER_FAILURE`. It is available after any authenticated
pre-attach or post-attach failure, not only an attach timeout, and carries the
failed session/generation identity. It never authorizes cleanup by itself; the
external coordinator first proves the exact foreign task is absent.

## Required deterministic checks

Before device use, tests must cover:

- multiple/zero/background/destroyed activities, PID reuse, task-token reuse,
  display drift, and stale host-generation replay;
- malformed or ambiguous ActivityManager/window records and oversized output;
- executable/DLL substitution, symlink/reparse replacement, sharing/handle
  loss, byte mutation, hostile ADB environment overrides, pre-existing/shared
  ADB-server substitution, private-server lifecycle, and post-run
  revalidation;
- local Python/Frida dependency substitution, ambient or replaced device Frida
  server, server PID reuse, protocol/version mismatch, and exact server
  teardown;
- present/absent/replaced PDF and `.mark`, content/file URI disagreement,
  provider replacement, and exact before/after mismatch;
- shell-UID enforcement and rejection of a root SavedInk collector;
- timeout and failure at every capture/attach/load/sample/unload/detach/cleanup
  boundary;
- callback-after-terminal and partial/duplicate/out-of-order observer records;
- FULL/LEFT/RIGHT/FULL stage ordering and exact restoration;
- proof that no mutating page, writer, geometry, tool, save, or input method is
  reachable from the visual-gate path.

Hardware admission requires all subsystem checks, independent subsystem
reviews, one integrated exact-head review, and a reboot-planned pen-grab release
test.  Until then no host package or observer is installed or injected.
