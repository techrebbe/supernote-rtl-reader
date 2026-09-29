# Native writer authority: bounded static audit (2026-09-29)

This note is a **NO-GO for live writer admission**, not a firmware modification or
Nomad hardware pass. The final bounded architecture decision is in
[NATIVE_VIEWPORT_FINAL_VIABILITY.md](NATIVE_VIEWPORT_FINAL_VIABILITY.md);
earlier gate proposals below are preserved as history, not authorization for
another Nomad trace. This note explains why the offline `PageWriterWitness` contract in
`TargetOwnedVisualLeaseCore` remains unavailable in `AndroidLeasePort`. The
original PDF, `.mark`, native reader, and DrawPath service remain authoritative.

## Pinned inputs and observed route

- The inspected DrawPath `librecgnition.so` has SHA-256
  `3ce8bcf151e92899cb06c64e529723c560718aea36f070761c4ee9fe99bd57e2`.
  These offsets are specific to that binary, not portable firmware APIs.
- `HandWriteClient.sendWriteInfo` sends page/layer through `service_myservice`
  Binder transaction 0. `sendDisableAreaInfo` and `sendWritable` send disabled
  rectangles or the `18888`/`19999` pseudo-rectangles through transaction 1.
  The Java client logs a reply string but does not parse an applied-state
  acknowledgment. `sendDisableAreaInfo` updates its local `tempList` before
  IPC and can return `true` after `transact(1)` returns `false`.
- Document JNI can obtain the same service independently through
  `JniHandWriteClient`; observing or redirecting one Java Binder cache does not
  cover all native tool paths. The Activity's writable/ready booleans are local
  UI or preparation state, not a service-side writer witness.
- Bounded disassembly found the real `BnMyService::onTransact` at RVA `0x6cc40`.
  Its transaction-0 route reaches `ThreadDrawPath::setAppInfo` and stores
  page/layer at `+0x1098/+0x109c`. Transaction 1 reaches
  `setWritableAndNonWritableRegion`; the ordinary region vector is at `+0x10a0`
  while the `18888`/`19999` sentinels toggle a separate flag at `+0x10d1`.
  The pen worker consults the region vector and copies page/layer into a trail
  at pen-up. These are static data-flow observations, not a runtime assertion
  that a particular contact was routed correctly.

## Why this is not yet a witness

The pinned client exposes no non-mutating read of the service's combined
page/region/writable state. The observed transaction/setter paths do not share
one atomic page/region/writable lock; the pen worker consumes state separately.
A synchronous Binder reply therefore
does not establish an atomic state snapshot or fence an in-flight pen contact.
The setters also update a `system_clock::now` value, which is a wall-clock
timestamp, **not** a strictly monotonic page/writer mutation generation. The
named `BnMyService` typed methods examined in the engine audit are RET stubs;
their names are not evidence of a safe getter.

Consequently, the following are insufficient to populate `PageWriterWitness`:
`HandWritePresenter.currentPage`, `sendWriteInfo`/`sendWritable` calls or their
return values, `HandWriteClient.tempList`, cached Binder pointers, UI readiness
flags, screenshots, pen-up trail metadata, or two matching un-fenced memory
samples. Keep `pageWriterMutationRevision()` at `-1` and
`pageWriterWitness()` at `null` until an independently reviewed, target-owned
authority can prove exact page and writer identity, effective writable state,
and a non-reusable pre-change generation. The current Android Port therefore
must continue to reject visual-child admission.

## Historical bounded-gate proposal (superseded by final NO-GO)

1. Continue an **offline** audit of the pinned service's transaction and dump
   surface for a genuinely read-only page/region query and a pre-write
   generation, including the separate JNI client and pen-worker ordering.
2. If such an endpoint exists, specify one externally bound, read-only
   disposable-PDF Nomad trial with exact device/process and PDF/`.mark`
   preflight/postflight, two page/service samples, timeout, detach, and
   independent cleanup evidence. Obtain a fresh device reservation first.
3. Record `UNKNOWN` and do not insert a view or draw if the endpoint is absent,
   asynchronous, or cannot atomically bind page, writable state, and contact
   ordering. Do not infer success from a Java call, a Binder pointer, or a
   completed screenshot.

Existing context: `NATIVE_ENGINE_STARTUP.md`, `NATIVE_PEN_BOUNDARY.md`,
`NATIVE_PAGE_FIRMWARE_FIELD_MAP.md`, the pinned decompiled
`HandWriteClient.java` and `JniHandWriteClient.java`, and the disposable
stock-reader baseline. No device operation was performed for this audit.

### Bounded transaction-surface follow-up

The pinned `onTransact` jump table covers codes 0–21. A bounded static pass
verified that code 1 mutates writable-region state and code 4 waits to remove
trail data from a queue; neither is the required non-mutating combined getter.
Another reply path increments a counter *after* a queue pop, not before page
and region writes. The pass did not establish a page/region/writable getter or
pre-write fence, but it was not an exhaustive proof that no such path exists.
The result remains **UNKNOWN / NO-GO**, with no Nomad trial authorized by this
finding.

### Shared-gate cross-check in the pinned binary

A separate bounded instruction-level pass found different service mutexes for
Binder transactions 0 (`+0x28`) and 1 (`+0x50`). `setAppInfo` at RVA `0xb5f00`
writes page/layer at `+0x1098/+0x109c` without its own lock. The region setter
at RVA `0xb5a70` uses a native `+0x1048` lock for the ordinary vector at
`+0x10a0` and the writable sentinel flag at `+0x10d1`; the derived write-area
vector at `+0x10b8` is written under a separate `+0x10fc` lock. The pen worker
reads/copies these fields around RVAs `0xaf068`, `0xaf190`, and `0xafd70`
without the region-setter lock. At pen-up, `penUpPushTrail` (`0xba2ac`) copies
the write-area vector and page/layer around `0xba318`–`0xba34c` without a
surrounding common mutex. Its later use of `+0x1048` protects a different
metadata section. These observations rule out treating the **observed** setter
entry points or Binder replies as one atomic writer witness; they do not prove
there is no unexamined endpoint or viable replacement boundary.

### Disposable offline boundary probes

`writer-witness-fake/` models the proposed pre-write generation, process/service
incarnation, partial page/region/writable updates, pen-effect ordering, and
detach cleanup under deterministic host concurrency. `frida-fake-service/`
checks the pinned Frida runtime against an executable that this project owns,
including a post-detach original-call sentinel. These are **mechanism checks**,
not observations of Supernote's service. Neither proves that every stock setter
and pen worker uses a common gate, or that a live hook can be installed and
removed quiescently. The Android Port remains fail-closed until those facts and
the exact disposable-PDF hardware rollback are independently verified.

### Pen-worker lock is not a page/writer fence

A further bounded inspection of the same pinned ELF found that
`ThreadDrawPath::run` receives points through the queue at RVA `0xae650` and
holds its `this+0x1c` mutex across the `penUpPushTrail(true)` call at
`0xb0c44`. Neither `setAppInfo` (`0xb5f00`) nor the writable-region setter
(`0xb5a70`) takes that mutex. The region setter instead uses `this+0x1048`,
and the worker's derived write-area update (`0xb8f14`) uses `this+0x10fc`.
`penUpPushTrail` copies the derived area and page/layer around
`0xba318`–`0xba34c` without a mutex shared by both setters.

Consequently, queue-pop and pen-up are possible **observation points**, not a
quiescent admission gate or an atomic combined page/region/writable witness.
More observation of setter and pen-up ordering would not satisfy the required
pre-write authority. Making the state atomic would require a separately
reviewed service-owned synchronization and contact-order fence spanning both
setters and the worker, with reversible deployment and independent hardware
rollback proof. Under the final bounded decision, no further speculative
Nomad trace is proposed. No service hook or device action was performed for
this inspection.
