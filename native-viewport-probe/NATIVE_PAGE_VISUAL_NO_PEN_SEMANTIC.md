# Observation-only semantic capture adapter

## Status

`native_page_visual_no_pen_semantic.py` is a production-shaped implementation
of `native_page_visual_session_harness.SemanticAuthority` for visual-session
semantic sampling **without pen authority**.  It is intentionally not admitted
for live hardware yet:

- `REAL_FIXED_BACKEND_IMPLEMENTED` is `False`;
- `HARDWARE_EVIDENCE_COMPLETE` is `False`;
- `admission_status()["admitted"]` is always `False`;
- no fixed backend/bootstrap, pinned backend executable, or exact-head hardware
  evidence is supplied by this module.

The code is therefore an interface, validation, and evidence boundary.  It is
not permission to substitute a generic shell/ADB/Frida runner.

## Authority boundary

The adapter accepts one immutable `NoPenSemanticPlan`, one retained fixed
backend, one retained monotonic clock authority, and a 32-byte receipt key.  It
has no filesystem, subprocess, socket, ADB, Frida, device-discovery, input,
writer, event-device, or pen-lease implementation.  It also accepts no sample,
observer-session, or nonce factory.  A private retained `SystemRandom`
authority created inside the adapter supplies one non-retried 256-bit draw for
each identity.  Its fixed policy record is bound into the adapter authority;
callers cannot supply a callable or backend command that chooses those values.
An entropy-provider exception, malformed draw, or repeated draw permanently
seals the adapter before any backend dispatch.  It cannot be treated as a
recoverable operation failure or retried with the same authority instance.

The fixed backend protocol exposes only:

1. retained identity verification;
2. canonical identity retrieval;
3. the single `capture_no_pen` operation; and
4. a quiescence barrier.

Its admitted identity must explicitly deny input, writer, pen-operation,
pen-lease acquisition, pen-lease touch, generic-command, caller-argv, and
user-selected-document capabilities.  The adapter additionally requires zero
counts in the transport result, both external authority records, the
transcript, and the authenticated aggregate receipt.

The legacy `SemanticCapture` result field names are compatibility fields only.
This adapter does not call `native_page_graph_v2_runner.run_one_stage`, because
that runner requires a live pen lease.

## Monotonic clock authority

A bare callback or ambient `time.monotonic_ns` default is not accepted.  The
clock must be a retained authority implementing:

```text
verify()
canonical_bytes()
monotonic_domain_identity()
now_ns()
```

The provider authority and monotonic-domain identity are separate, strict,
canonical records.  Their SHA-256 digests are pinned in the immutable semantic
plan and in the backend identity.  Every clock read re-verifies both records
before and after `now_ns()`.  Identity substitution, provider drift, domain
drift, verification failure, regression, or a stalled clock around a dispatched
external capture seals the adapter.

Production bootstrap must pass the exact same retained monotonic provider and
domain used by `HostAuthority`.  It must derive the two canonical records from
that retained provider.  A caller-supplied boolean such as `sameClockDomain`
is neither accepted nor sufficient evidence.

The adapter implements the harness `monotonic_domain_identity()` method as the
SHA-256 identity of that retained, plan-pinned domain record.  Each call
revalidates the retained record and fails closed on substitution or drift, so
the harness can require exact equality among HostAuthority, task authority,
and semantic authority.

Backend transport timestamps, capture deadlines, external records, and receipt
authentication are bound to the same two digests through the request.  A fixed
backend cannot silently substitute a different timestamp domain.

## Capture evidence

For each of the two harness samples, the adapter independently constructs the
strict graph-v2 manifest and binds it to:

- the exact harness phase and ordinal;
- retained foreign process/task/activity identity;
- exact applied host placement and measured rectangle;
- raw and stable Android task authority digests;
- the disposable fixture URI and PDF SHA-256;
- exact before/after file evidence;
- framework, observer, module, backend, clock, and domain pins;
- one fresh sample ID, observer session ID, and 256-bit nonce; and
- a bounded absolute operation deadline.

The backend returns one `NPSEM001` aggregate containing exactly six ordered
members:

1. manifest;
2. independent external authority before capture;
3. graph-v2 snapshot;
4. independent external authority after capture;
5. no-pen transcript; and
6. authenticated aggregate receipt.

Every member has a length bound and SHA-256 digest, and the complete aggregate
has a terminal digest.  Missing, reordered, oversized, malformed, duplicate-key,
noncanonical, NaN, or trailing data is rejected.

Both external authority records must independently reproduce the exact target,
host, task, files, request, manifest, backend, clock, and monotonic-domain
bindings.  Apart from phase, capture ID, and capture time, their semantic
content must be identical.  Their capture IDs must be fresh and distinct.

The snapshot is validated by the existing strict graph-v2 canonical validators.
The before/after records have chained HMAC-SHA256 stage receipts, followed by a
separate authenticated aggregate receipt binding every member and transport
timestamp.  Sample IDs, observer sessions, nonces, capture IDs, stage receipt
IDs, stage receipt digests, and aggregate receipt digests cannot be reused.

## Failure and concurrency policy

- Entry is nonblocking and nonreentrant.  Concurrent or reentrant use
  permanently seals the adapter.
- A capture is dispatched only after a successful quiescence barrier, an
  immediate authenticated-clock deadline check, and fresh dependency
  verification.  A barrier that returns at or after its deadline results in
  zero capture dispatches and seals the adapter.
- Any uncertainty after the backend is touched seals the adapter and attempts
  one best-effort quiescence check within the caller's existing deadline.
- No retry is authorized.
- Results are published only after post-capture quiescence and its immediate
  clock deadline check, retained backend and clock re-verification, strict
  decoding, graph-v2 validation, receipt authentication, freshness checks, and
  a final deadline check.
- Public quiescence checks bracket the backend return and subsequent retained
  identity verification with authenticated clock reads.  A backend that
  returns or completes verification late is rejected and permanently seals the
  adapter.  The post-barrier identity must be an exact
  `NoPenBackendIdentity`, pass its complete plan/capability validation, and
  match both the retained canonical bytes and digest.  An equality-spoofing
  wrapper is not identity authority.
- A sealed adapter never becomes authoritative again.

## Synthetic verification

`test_native_page_visual_no_pen_semantic.py` uses only in-memory fakes.  Socket
and process creation are patched to fail, demonstrating that the high-level
adapter has no ambient device route.  The suite covers:

- successful harness-compatible capture with five independent no-pen
  attestations;
- two semantically equal but independently identified samples;
- fail-closed live admission;
- backend capabilities, retained identity, receipt key, and canonical drift;
- exact task, foreign process, host placement, target, URI, PDF hash, file, and
  graph-v2 bindings;
- strict manifest construction and snapshot validation;
- capture/deadline ordering and before/after timestamp brackets;
- internally generated 256-bit sample, observer-session, and nonce shape and
  freshness, entropy collision/exception permanent sealing with zero dispatch,
  absence of caller identity-factory seams, and capture/receipt ID and
  receipt-digest reuse;
- transcript, receipt, HMAC chain, and transport counter tampering;
- malformed, duplicate-key, NaN, reordered, oversized, and trailing wire data;
- backend failure, uncertain quiescence, equality-spoofed retained identity,
  zero-dispatch late pre-capture quiescence, late public quiescence, and late
  publication;
- reentrancy and permanent sealing; and
- retained clock plan/backend/harness-domain binding, strict canonical topology,
  forbidden caller boolean claims, substitution, provider/domain drift,
  verification failure, regression, and stall.

This synthetic suite is necessary but not sufficient for admission.  A reviewed
fixed backend/bootstrap and exact-head hardware evidence must be implemented in
separate work before the status constants can change.

## Production blockers

1. Implement and independently review a fixed no-pen backend and bootstrap with
   a retained private transport and retained worker/process identity.
2. Pin the worker image, tool bundle, observer, device boot, serial, receipt
   capability, retained clock authority, and HostAuthority monotonic domain.
3. Demonstrate that the backend has no generic command, input, writer, pen, or
   pen-lease surface and returns only after exact quiescence.
4. Integrate the adapter into the harness without using the pen-lease graph-v2
   stage runner.
5. Run the two-sample exact-head hardware gate and preserve independently
   reviewable evidence for identity freshness, semantic equality, timing,
   quiescence, and zero operations.
6. Obtain a clean integrated review before changing either admission constant.
