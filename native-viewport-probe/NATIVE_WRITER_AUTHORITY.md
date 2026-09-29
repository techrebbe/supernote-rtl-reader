# Native writer authority: bounded static audit (2026-09-29)

This note is a **NO-GO for live writer admission**, not a firmware modification or
Nomad hardware pass. It explains why the offline `PageWriterWitness` contract in
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

## Next bounded gate

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
