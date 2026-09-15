# Native-page visual platform inventory authority

Status: **strict adapter/parser complete; current production backend admission
blocked.**

`native_page_visual_platform_authority.py` is the read-only platform adapter
for `native_page_visual_session_harness.PlatformAuthority`. It returns that
harness's exact `PlatformCapture` type and constructs its exact
`native_page_host_authority.Snapshot` type. Importing it performs no I/O.

The component never discovers an ADB executable, reads `PATH`, opens a socket,
starts a process, chooses a document, sends input, launches an activity, changes
a display, removes a task, or writes to Android. Its only device-facing
dependency is an injected, already-retained `RetainedPrivateAdbBackend`.

## Admission state

The reviewed `native_page_private_adb.PrivateAdbServer` cannot yet implement
the required backend contract. Its frozen registry exposes separate
`get_state`, `wm_size`, `wm_density`, `dumpsys_window`, and `dumpsys_activity`
operations. It does not expose:

- complete PID/start-ticks/UID/package evidence;
- complete DisplayManager evidence;
- one operation/receipt binding all four raw captures to the same serial, boot,
  request scope, capture ID, and monotonic bracket.

Calling `admit_existing_private_adb` therefore always raises
`PlatformAdmissionBlocked` with blocker
`REVIEWED_PRIVATE_ADB_COMPLETE_PLATFORM_CAPTURE_BACKEND_REQUIRED`. It does not
inspect or invoke the supplied object. There is no ambient ADB, command-line,
multi-call, or caller-boolean fallback. `production_backend_status()` exposes
the same decision as bounded data.

A future production bridge must add one separately reviewed, frozen, read-only
complete-capture service to the retained private ADB boundary. It must not
construct authority by making the currently available commands sequentially:
that would leave process/display completeness and cross-command coherence
unproved.

## Retained backend contract

The injected backend has five operations:

- `verify()` revalidates its retained transport/tool/process identity;
- `canonical_bytes()` returns its bounded immutable authority;
- `identity()` returns the exact serial, canonical boot UUID, generation,
  authority digest, and closed capability claims;
- `now_ns()` returns the trusted monotonic nanosecond domain shared with the
  harness;
- `capture_complete(request, deadline_ns)` returns one `RawPlatformBundle`.

Construction pins the backend identity and canonical bytes. They are checked
before and after every capture. The backend must declare exactly read-only,
complete capture with ambient discovery false. A reboot, transport generation
change, canonical-byte change, or verification failure rejects the adapter.
Public verification and capture entry points are mutually exclusive; a
concurrent or reentrant call is rejected before a second backend dispatch.

For each call the adapter creates a scope containing only the label, authorized
serial, retained boot ID, nullable positive display ID, and nullable digest of
the exact `ForeignIdentity`. No file path or URI enters this boundary. The
adapter reads trusted time immediately before and after the one backend call.
The receipt's start, capture and finish timestamps must be ordered inside that
independent bracket; its capture timestamp must be strictly newer than the
prior capture and associated with a never-reused canonical capture UUID. A
rejected capture seals the adapter; there is no retry or scope borrowing.

## Raw evidence and coherence

All four raw members are retained unchanged in the returned `PlatformCapture`:

1. `ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)`;
2. `WINDOW MANAGER WINDOWS (dumpsys window windows)`;
3. `NATIVE PAGE PROCESS INVENTORY (visual-platform-v1)`;
4. `DISPLAY MANAGER DISPLAYS (dumpsys display)`.

Every wire is bounded, strict UTF-8, uniformly LF or CRLF, newline-terminated,
NUL-free, and free of alternate control/line-separator characters. Structural
headers, field order, canonical decimal/boolean spelling, row order, unique
identities, and terminal counts are exact. Unknown sections or fields fail.
This deliberately means a new pinned-firmware text variation requires a new
literal fixture and review; the parser does not guess.

The process wire is the complete-capture receipt. Its exact lines bind:

- backend capture authority, canonical capture UUID, label, serial, canonical
  boot UUID, and ordered start/capture/finish monotonic nanoseconds;
- nullable display scope and nullable SHA-256 of the exact foreign identity;
- exact byte lengths and SHA-256 digests of the ActivityManager,
  WindowManager, and DisplayManager wires;
- `complete=true`, `readOnly=true`, zero mutations, zero user-document
  selections, and the closed host/stock package scope;
- the pinned host package/version, installed signed APK, reviewed reproducible
  unsigned APK, packaged DEX, and signer-certificate record;
- sorted, uniquely keyed relevant process PID/start-ticks/UID/package rows;
- exact process and package terminal counts.

The process wire's own SHA-256 becomes `Snapshot.process_sha256`; the other
three raw SHA-256 values become their corresponding snapshot digests. Thus all
typed rows and all four retained artifacts are members of the same checked
capture. Changing and re-signing one subordinate raw wire still requires it to
pass its literal parser and every cross-inventory check.

The `ForeignIdentity.evidence_sha256` binds the canonical stable Android task
authority created at launch, not the SHA-256 of that one ActivityManager dump.
Every later ActivityManager dump retains its own exact raw digest and may differ
in nonsemantic counters, but its freshly parsed stable task authority must hash
to the launch value. Task, token, PID, UID, component, display, configuration,
or other semantic drift therefore fails without falsely demanding byte-identical
independent observations.

## Typed snapshot invariants

The ActivityManager parser accepts both pinned header forms already admitted by
`native_page_android_authority`:

- a display header immediately after the ActivityManager title;
- the exact `Display areas in focus order:` preamble followed immediately by
  the first display header.

Malformed/misplaced preambles, malformed display/stack/task/history headers,
later top-level sections, and field borrowing across block boundaries fail.
Every relevant task has one complete activity block and one exact process.
Short Android component spelling is normalized to the full component used by
`host.Snapshot`. For a live stock task, the unchanged ActivityManager bytes are
also parsed by `native_page_android_authority.parse_document_task_authority`
with `require_live=True`.

The WindowManager parser requires exact window block ordinals, process/UID/
package ownership, task/activity/display identity, geometry, visibility and
per-display focus rows. No orphan window or focus row is accepted. Every AM
activity must have exactly one identical typed window and vice versa.

The DisplayManager parser requires exact ordered display blocks, unique display
and unique-device IDs, process-bound ownership, metrics, sorted unique flags,
ON state, and a matching terminal count. The admitted set is exactly display 0
plus the requested owned virtual display, or only display 0 for final absence.
Each display ID's native unique ID is pinned on first observation and must stay
identical for the session, so destroy/recreate ID reuse cannot masquerade as the
retained display.
Display 0 is the unowned 300-dpi `Built-in Screen` at one canonical physical
orientation. The virtual display has the exact retained host owner, session/
generation name, 1404 x 1872 metrics, 300 dpi, and exact
`PUBLIC|OWN_CONTENT_ONLY|DESTROY_CONTENT_ON_REMOVAL` flags.

When a positive display is requested, the one live host activity/window must
match the retained host PID/start/UID/package, task, token, physical frame,
fixed 1404 x 1872 buffer and one reviewed FULL/LEFT/RIGHT surface frame. With
`foreign=None`, that owned display is empty and no stock activity/window may
exist. With a foreign identity, exactly one live stock task/window exists on
that display, matches the stable semantic ActivityManager task authority, and
occupies the complete
1404 x 1872 frame, surface frame, and buffer. Its native task configuration is
also exactly 1404 x 1872 at 300 dpi and rotation zero, matching the fixed
virtual display. Its orientation token must be portrait and its one exact
`mAppBounds` must cover that same complete viewport. The complete foreign
configuration uses one exact firmware-pinned grammar: locale, density,
orientation, `winConfig`, ordered `mBounds`, ordered `mAppBounds`, rotation,
and configuration sequence. Unknown, reordered, duplicated, shadowed, or
contradictory window-mode fields cannot supply authority. A future literal
firmware variation requires a newly retained fixture and explicit review.
Relevant tasks/stacks must be non-translucent
standard/fullscreen presentation. With `display_id=None`, both host and stock
tasks/windows are absent and only display 0 remains. The relevant stock process may remain alive;
once observed, its full process identity is pinned across later captures.

## Offline verification

`test_native_page_visual_platform_authority.py` uses only literal in-memory
wires and a retained fake backend. It covers:

- live, prelaunch, and final nullable-foreign scopes;
- both currently admitted multi-display ActivityManager header forms;
- exact `PlatformCapture`/`Snapshot` construction and raw digests;
- stable adapter authority and backend byte/identity pinning;
- concurrent/reentrant capture rejection before a second backend dispatch;
- stale/future/nonincreasing timestamps and replayed capture UUIDs;
- serial, boot, label, display and foreign scope borrowing;
- package, process start identity, counts, ordering and policy drift;
- display unique-ID continuity, exact task/stack presentation, and native
  configuration/surface/buffer geometry coherence;
- re-signed ActivityManager, WindowManager and DisplayManager structural
  mutations, cross-inventory task/token/component/display/geometry drift, and
  un-re-signed raw mutations;
- uniform CRLF acceptance and mixed-ending rejection;
- line-wise mutation of every process-receipt structural line;
- the no-touch production admission blocker and pre-dispatch type/bound checks.

The test does not instantiate the Windows runtime, access hardware or network,
or create a subprocess.

Run with the repository's Python runtime:

```text
python -m py_compile native_page_visual_platform_authority.py test_native_page_visual_platform_authority.py
python -m unittest -v test_native_page_visual_platform_authority
python -m unittest -v test_native_page_android_authority test_native_page_host_authority test_native_page_private_adb test_native_page_windows_tool_authority
```

Passing these host-only tests validates the strict adapter/parser and its
failure boundaries. It does not clear the production backend blocker, approve a
hardware run, or change the visual harness's status-only CLI.
