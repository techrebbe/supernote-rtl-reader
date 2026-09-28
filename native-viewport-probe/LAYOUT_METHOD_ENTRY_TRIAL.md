# Disposable layout-entry trial card (2026-09-28)

Status: **emulator-only test design**. No stock-reader method hook, Nomad
installation, visual-child insertion, PDF access, or pen input follows from
this card. `FRAMEWORK_WRITE_EDGE_AUDIT.md` supplies the candidate Android 11
ordering; the hash-pinned OEM method bodies are not yet proven equivalent.

## Question and authority

Can one process-scoped observation of `ViewGroup.layout(int,int,int,int)`
run before the first framework write for an **exact synthetic root** while
forwarding the original call exactly once? This is a feasibility test for one
edge, not proof of complete mutation coverage. The nine-child disposable app
owns every test mutation and restoration. A Frida host may observe and
record, but must not own the restore timer or mutate the view hierarchy.

Only `emulator-5554` with `ro.kernel.qemu=1` and API 30 is eligible. Pin the
APK hash/signature, package, PID and process incarnation, Activity/root
identity, main Looper, initial bounds, ordered nine original references, and
a fresh completed nine-child paint before an attempt. Keep each variant in a
fresh app process. An ambiguous provider response or expired start witness
consumes that incarnation; do not retry it in place. Never discover a target
by selecting the first attached Android device.

## One-variable variants

| Variant | Controlled action | Required observation |
| --- | --- | --- |
| Positive control | Sole parent increments its own revision, then invokes exact-root `layout` for a one-pixel width change. | Hook records old/proposed rect and already-incremented revision before the original call; original call count rises exactly once; `onLayout` and a new nine-child paint follow. |
| No-op control | Parent requests identical bounds. | Exactly one forwarded call; no false claim that an unchanged rect establishes complete coverage. |
| Direct-layout bypass | App calls the root's layout without the parent's pre-bump. | Hook may see method entry, but the missing parent authority is explicit and the coverage claim is rejected. |
| Direct-setter bypass | App uses a bounds-offset/setter path outside `layout`. | Missing layout entry is detected as a coverage gap, not a PASS. |
| Away/back ABA | App makes two distinct one-pixel changes returning to initial bounds. | Distinct pre-write observations/revisions for both changes; equal final bounds alone never count as coverage. |

The observer must compare the retained Java object reference for the exact
root, not an ID or identity hash. It captures data before forwarding, catches
its own logging errors, and invokes the original method once on **all**
paths, including non-target views, without arbitrary callback or logging
reentry. Its process-wide replacement is temporary and remains potentially
hazardous; unloading it is not rollback authority. Host and app evidence
must agree on event order and call counts. A scripting error, duplicate or
skipped forward, wrong root, wrong thread, unexpected setter, or missing
event ends that variant without reclassification as success.

## Restoration and verdict

The app arms a short monotonic deadline before each layout mutation. On
explicit stop, expiry, activity loss, or error, its main-Looper owner restores
the initial geometry **only on the exact original root while it is still
owned and safe**; a detached/replaced root is UNKNOWN, never reattached or
repaired by guessing. The owner checks all nine exact original references,
order, parents, scene stamp, and a fresh completed paint. A separate bounded
watchdog independent of both the main Looper and Frida host/session must
handle a main-Looper stall or lost host: classify UNKNOWN and terminate only
the exact disposable app process/incarnation rather than claim a live
restore. Host disconnect is not a pass or an automatic retry.

On normal paths, take two spaced matching postflight samples with the same
PID/incarnation/root, unload instrumentation promptly, verify the hook is
gone, and take one final exact post-unload state/paint sample. If unload or
that final check fails while the host is alive, stop only the disposable app
as UNKNOWN. A process death destroys the hierarchy but is **not** live
restoration. Do not leave the process-wide hook installed while waiting
indefinitely for a second sample.

PASS is narrow: one exact emulator call path had a pre-write observation,
single original forwarding, and independently witnessed restoration. FAIL
is a counterexample with safely restored app state. UNKNOWN covers crash,
timeout, disconnect, missing events, stale paint, or uncertain cleanup;
stop that process and report it, with no automatic repair/retry. All variants
must keep the Port's complete-coverage flag false and its uncertified
revision at `-1`. Any later production mechanism requires its own durable
target-process ownership and OEM-specific review; this experiment is not it.
