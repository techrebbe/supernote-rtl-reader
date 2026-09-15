# Native-page visual/session evidence harness

Status: **host-side implementation complete; hardware admission blocked.**

`native_page_visual_session_harness.py` is the deterministic evidence binder
for the next visual-only Nomad rerun.  It is deliberately not a device runner.
Its CLI only prints the closed admission record and exits 2.  The module has no
ADB, Frida, shell, input, process-launch, path-discovery, or retry
implementation.  The seven device-facing authorities are injected protocols,
and every missing production implementation remains an explicit blocker.

This is not a pen milestone.  It must not generate pen, touch, or key input,
acquire a pen/event-device lease, call a writer/save method, select a user
document, address BOOX, or use broad process/task cleanup.  The sole document
scope is a uniquely named disposable fixture under
`/storage/emulated/0/Download/NativeViewportVisualOnly-*.pdf`, bound to its
predeclared SHA-256.

## Files

- `native_page_visual_session_harness.py` — status-only CLI, strict injected
  adapter contracts, transaction coordinator, evidence validators, immutable
  artifact references, append-only journal, cleanup, terminal manifest, and
  replay verifier.
- `test_native_page_visual_session_harness.py` — host-only deterministic fakes
  and normal/fault-path tests.  Network sockets and child-process creation are
  patched to fail.  These tests do not contact a device.
- `NATIVE_PAGE_VISUAL_SESSION_HARNESS.md` — this contract and readiness map.

The implementation composes the existing reviewed
`native_page_host_authority.HostAuthority`, the strict
`native_page_android_authority` parser, graph-v2 canonical/snapshot validators,
and `native_page_cleanup_store.WindowsCleanupStore`.  It does not modify or
replace those authorities.

## Fixed evidence transaction

The plan contains one canonical UUID, the exact fixture URI and SHA-256, one
absolute monotonic deadline, mandatory physical-rotation acknowledgement, and
exactly seven adapter digests. A plan that omits the portrait/landscape return
is rejected. The exact `Adapters` container and each of its seven adapter
objects are retained at construction. Object identity and canonical bytes are
checked before and after every verification and call, including exceptional
returns, and again during cleanup. A same-canonical replacement is not retained
authority and is never invoked. A caller-provided digest only detects drift
relative to that plan; it is **not independent review authority** and cannot
clear the exact-head blocker.

The mandatory phase order is:

1. `LANDSCAPE_FULL_INITIAL`
2. `LANDSCAPE_LEFT`
3. `LANDSCAPE_RIGHT`
4. `LANDSCAPE_FULL_PLACEMENT_RETURN`
5. `PORTRAIT_FULL`
6. `LANDSCAPE_FULL_ROTATION_RETURN`

For each phase the coordinator obtains an observation-only physical orientation
record, applies the exact reviewed host placement, and collects this order:

1. complete platform inventory before semantic sample 1;
2. independent semantic sample 1;
3. complete platform inventory after sample 1;
4. one read-only PNG bound to the exact task, display, placement sequence, and
   physical dimensions;
5. complete platform inventory before semantic sample 2;
6. independent semantic sample 2;
7. complete platform inventory after sample 2;
8. one phase-complete record binding both semantic projections, all four
   inventory hashes, the PNG hash, and the applied placement.

The two samples must have globally distinct sample IDs, observer-session IDs,
and 256-bit run nonces.  Their page lifecycle, document, pageInfo, presenter,
view, and layer projections must be identical within a phase and across every
completed phase.  Both samples are bound to the exact host session/generation,
host task/token/APK, foreign task/process, requested and measured rectangle,
file authority, and strict ActivityManager task authority.  Any input, writer,
or pen-operation count other than zero is rejected both live and on replay.

The session plan pins one cryptographic monotonic-domain identity. At
construction the harness requires the retained HostAuthority provider, exact
task adapter, and no-pen semantic adapter to report that same domain through
`monotonic_domain_identity()`; no same-domain boolean is accepted. Host capture
brackets and task/semantic adapter rechecks fail closed if the identity changes.
The harness also retains the exact `HostAuthority`, its process authority, and
its `HostProviders` object. Every host/provider call uses those retained
references and checks object identity before and after the call; a substitute
provider is rejected even when it reports the pinned clock domain. The composed
`HostAuthority` independently enforces the same rule internally, so mutable
public dependency slots can neither redirect its callbacks nor receive a host
command.

Each platform capture retains the complete raw ActivityManager, WindowManager,
process, and display wires.  Its typed snapshot must match all four raw
digests.  The selected stock task must be the sole resumed/visible task and
window with the exact task/token/PID/start-ticks/UID on the exact owned PUBLIC
display.  The display owner, name, flags, 1404 x 1872 metrics, and density are
exact.  Capture timestamps are bracketed by the retained host provider's
monotonic clock and are nondecreasing in the journal.  PNG timestamps use the
same independent bracket.  This catches stale/future replay envelopes, but the
future reviewed adapters must still bind their raw captures to that time; a
self-reported integer is not sufficient authority.

The PNG validator checks the signature, exact chunk framing, CRCs, a single
IHDR/IEND, legal bit-depth/color-type combinations, contiguous IDAT data,
critical chunks, bounded zlib expansion, exact decoded row geometry, and legal
filter bytes.  A PNG signature or dimensions alone do not pass.

Before host startup and after teardown, the file authority must independently
return exact stat and SHA-256 evidence for the PDF and nullable `.mark`, exact
file-URI resolution, collector UID 2000, the collector artifact hash, and a
canonical SavedInk record bound to the `.mark` hash.  The before/after core
records must be byte-semantically identical.

## Append-only binding and terminal decision

Every external or host operation has a durable intent record before dispatch
and exactly one result record afterward.  Journal records are canonical strict
JSON in a SHA-256 chain.  Each record is created under the existing retained
Windows store, fully written, file-flushed, renamed without replacement,
directory-flushed, and checked against the separate checkpoint authority before
the next operation begins.

Artifacts are retained before their references are journaled.  Every reference
contains logical name, media type, byte count, content hash, producer-authority
hash, immutable-store identity, and the immutable flag.  References are read
back after retention and all are reverified at cleanup.  Evidence rows may only
refer to journaled artifact references.  Reused logical names, mixed store
identities, missing readback, or a non-quiescent artifact store quarantine the
session.

The replay verifier recomputes the chain and validates exact opening admission
and ledger identity, adapter set, plan-derived operation names/order/owners,
intent/result pairing, capture-time order, semantic identities and
zero-operation counters, phase order/cardinality, evidence-to-artifact links,
artifact-owner producer pins, before/after files, exact cleanup sequence,
policy, complete provenance, and terminal prefix hash/count.  A complete run
must have the exact full artifact order.  Semantic or visual rows after phase
completion or cleanup start are invalid.  A terminal manifest/quarantine is the
final record; no post-terminal append is possible.

Host provenance independently binds the signed APK installed on Android, the
reviewed reproducible unsigned APK, its exact packaged DEX, and the signing
certificate. The installed package hash is never reused as compiler-output
authority, and the unsigned artifact is never accepted as installed identity.

Possible outcomes are:

- `VISUAL_EVIDENCE_COMPLETE_DIAGNOSTIC` — every requested phase and cleanup
  postcondition passed.  `hardwareAdmission` remains false.
- `FAILED_CLEAN` — a primary evidence failure occurred, but every exact cleanup
  and final evidence postcondition passed.
- quarantine — cleanup, final inventory, file equality, adapter pinning,
  artifact identity/quiescence, or journal durability is unresolved.  Retry is
  false and recovery is required.

A journal publication fault seals the journal permanently.  Later cleanup
actions still run in their fixed order, but the run cannot claim clean success;
the in-memory quarantine retains a `session_log` obligation and the first
publication failure.  No replacement journal or retry is attempted.

## Cleanup contract

Cleanup always attempts semantic-sampler quiescence first.  For an acknowledged
foreign task it restores FULL, begins the reviewed host close, destroys only
the retained exact task, independently proves that task absent while the stock
process remains alive, acknowledges that exact proof, verifies task authority
quiescence, and then verifies host quiescence.  A lost destroy receipt does not
suppress the independent absence proof.

If an exact task is known before host attach acknowledgement, its exact task
destruction is attempted and task-authority quiescence is required before an
empty-display proof. `host_begin_close` succeeds as `notApplicable` only when
host attach was never attempted. An attempted attach with an uncertain or
failed acknowledgement retains failure evidence and quarantine. A healthy host in `DISPLAY_ALLOCATED`
or `WAITING_FOR_FOREIGN_ACK`, with no foreign identity or pending command, uses
`prove_pre_attach_empty`/`abort_pre_attach_empty`. This route checks the exact
owned display and independent AM/window absence, then independently recaptures
them immediately before sending `ACK_NO_FOREIGN_PRE_ATTACH_ABORT`. Its
`EMPTY_PRE_ATTACH_ABORT` acknowledgement and `EMPTY_PRE_ATTACH_ABORT_REPLAY`
release retry are distinct from the failed-empty and foreign-destroy routes.
Proofs are session/generation/display-bound and expire after the existing
command interval. Release retry preserves the original command object, bytes,
sequence, and deadline; a separate bounded transport deadline cannot renew
readiness. Late acknowledgements only reconcile cleanup and never clear a
sticky timeout. Successful healthy cleanup does not fabricate host failure.

An ordinary prelaunch coordinator/capture failure uses the same healthy route.
Existing `prove_empty`/`ack_empty` behavior remains the failed-empty route;
it cannot replace an uncertain healthy-abort command. If launch throws without
returning an exact identity, task-creation uncertainty is retained and prevents
both empty-release routes even if the display appears empty. No guessed
task/process cleanup is attempted. Any unresolved identity, absence, release,
or final-inventory obligation remains quarantined.

One narrow typed exception is the only throwing-launch transfer route:
`TaskLaunchOutcomeUncertain`. It owns immutable, bounded canonical evidence and
an optional exact `ForeignIdentity`. The harness catches only that type,
re-verifies the throwing task adapter, validates task/token/PID/start-ticks/UID/
package/component/digest domains, and records exact cleanup ownership before
any uncertainty artifact or operation-result publication. A missing identity,
untyped lookalike, invalid identity, or adapter drift preserves unknown task
creation. Synthetic integration faults also prove that an artifact publication
failure after a valid transfer cannot suppress exact task cleanup. Post-throw
verification includes exact task-adapter object identity: a typed exception
cannot transfer cleanup ownership if the adapter slot was replaced, even by an
object with identical canonical bytes.

After host/task cleanup, the harness independently requires a final complete
platform inventory with the created display, exact host task/window, and exact
foreign task/token absent, while the stock process identity remains present.
It then captures after-file/SavedInk evidence, rechecks every adapter pin and
artifact reference, and only then publishes the terminal record.

## Remaining production blockers and reuse map

| Blocker | Existing reviewed code to reuse | Smallest safe missing piece |
| --- | --- | --- |
| `REVIEWED_COMPLETE_PLATFORM_INVENTORY_ADAPTER_REQUIRED` | `native_page_host_authority.py`: `Snapshot`, `ProcessIdentity`, `ActivityRecord`, `WindowRecord`, `DisplayRecord`, and the `Providers.capture` contract; `native_page_android_authority.py`: `parse_document_task_authority` and `stable_authority`. | Add one retained, private, bounded capture adapter that obtains complete raw ActivityManager, WindowManager, process, and display evidence in one capture, builds the exact typed `Snapshot`, binds it to the trusted host monotonic bracket, and returns both raw and typed evidence. Validate it against a freshly retained Nomad multi-display wire. Do not use ambient ADB output or caller booleans. |
| `REVIEWED_NO_PEN_SEMANTIC_SAMPLE_ADAPTER_REQUIRED` | `native_page_graph_v2_runner.py`: `canonical_bytes`, `load_canonical`, `validate_snapshot`, graph projection schemas, detached task/host/file binding, nonce/receipt patterns, and quiescence design; Android task parsing above. | Add a separately reviewed observation-only semantic capture route that never acquires or touches a pen/event-device lease and attests zero input/writer/pen calls. The current public `run_one_stage` path requires an active `penLease`, even in observation-only mode, so it cannot be used as the hardware authority for this gate and must not be weakened in place. |
| `REVIEWED_EXACT_FIXTURE_TASK_LAUNCH_TEARDOWN_ADAPTER_REQUIRED` | `native_page_host_authority.py`: `ForeignIdentity`, `attach_ack`, `begin_close`, `prove_task_absent`, and `ack_destroyed`; strict Android task parsing. | Add a retained private task adapter that launches only the exact URI/SHA fixture onto the exact display, returns the parser-derived task/token/PID/start-ticks/UID identity, and removes only that retained task ID. Its closure must prove task absence and stock-process liveness and attest that neither broad scope nor process kill was used. |
| `REVIEWED_PRE_ATTACH_DISPLAY_ABORT_AUTHORITY_REQUIRED` | `HostAuthority.prove_pre_attach_empty` and `abort_pre_attach_empty` implement the distinct healthy coordinator-abort path; `prove_empty`/`ack_empty` retain failed-empty cleanup. The matching Java lifecycle/activity route preserves exact replay and release retry. The harness destroys and verifies any known pre-attach task before healthy abort and quarantines unknown effects. | Deterministic Python and Java coverage is complete, and the reproducible unsigned APK, installable signed APK, packaged DEX, signer certificate, and version are distinct pinned authorities. This blocker remains until the integrated exact-head source/binary review confirms the final inspector/build evidence. No real launch is enabled by this implementation. |
| `REVIEWED_SHELL_UID_SAVEDINK_CAPTURE_ADAPTER_REQUIRED` | `native_page_graph_v2_runner.py` file-authority schema/canonical JSON validation and the harness's strict `DeviceFile`/`SavedInkEvidence` cross-checks. | Add a retained UID-2000 collector that resolves the exact file URI, stats and hashes the disposable PDF and nullable `.mark`, emits the raw provider evidence, canonically decodes SavedInk, binds it to the source `.mark` hash, and makes no write. No production SavedInk collector is exposed by the reviewed components composed here. |
| `REVIEWED_IMMUTABLE_ARTIFACT_AUTHORITY_REQUIRED` | `native_page_cleanup_store.WindowsCleanupStore`: retained handles, private authority, exact inventory, `create`, full-progress `write`, `fsync_file`, `rename_no_replace`, `fsync_directory`, readback, and checkpoint identity; `native_page_cleanup_ledger.canonical_json`/`decode_record`. | Build a separate large-artifact authority using the same retained-handle/no-replace/durability principles. It must return one stable store identity, deny logical-name reuse, verify bytes by retained handle, survive partial publication without replacement, and prove quiescence. Do not treat the ignored historical build helper or the journal directory as immutable artifact authority. |
| `REVIEWED_READ_ONLY_VISUAL_CAPTURE_ADAPTER_REQUIRED` | `HostAuthority`'s `ForeignIdentity`/`AppliedPlacement` and exact geometry; the harness's complete `_validate_png` and trusted-time bracket. | Add one retained read-only capture adapter bound to the exact foreign task, display, placement sequence, dimensions, and trusted capture bracket. It must retain the unmodified PNG and an independent zero-input attestation; no key, touch, pen, crop, resize, or display-0 fallback is permitted. |
| `INTEGRATED_HARDWARE_EXACT_HEAD_REVIEW_REQUIRED` | Exact host APK/DEX constants and all authorities/tests above. | Have an independent reviewer issue the immutable plan/allowlist for the exact source and binary hashes of the harness plus every adapter/tool/observer. Replace no authority with caller-selected pins. Only that reviewed integration may expose a hardware entry point; this status-only harness continues to report blocked until then. |

The graph fake in `test_native_page_visual_session_harness.py` exercises result
shape and validation by calling the existing graph-v2 runner with its test-only
observation-mode penLease record.  It performs no device or pen operation, but
it is **not** evidence that the production no-pen adapter exists.

## Smallest safe path to one actual rerun

1. Freeze the exact reviewed source/binary set and reviewer-issued component
   allowlist; generate and hash a new disposable fixture without selecting a
   user document.
2. Implement and fault-test the immutable artifact authority and journal
   recovery first, so every later side effect has durable evidence ownership.
3. Implement the complete platform inventory adapter and validate a newly
   retained real Nomad wire with the strict Android parser.
4. Complete Java/binary integration and independent review of the authenticated
   pre-attach empty-display abort authority. Do not enable task launch until
   the exact rebuilt source/binary set demonstrates safe release and retry.
5. Implement the exact fixture task launch/destroy adapter and exhaust failures
   before return, after task creation, before attach, after attach, after
   destroy, and during release.  Never add process-kill fallback.
6. Implement the shell-UID file/mark/SavedInk adapter and prove identical
   before/after capture on the disposable fixture.
7. Implement the read-only visual adapter with exact task/display/placement and
   trusted-time binding.
8. Implement the separate no-pen semantic adapter last, reusing graph
   validation without acquiring a pen lease or weakening the existing runner.
9. Run all host-only, replay, publication-fault, adapter-drift, cleanup, and
   retained-wire tests; have the independent reviewer pin the resulting exact
   head and binaries.
10. Expose one bounded, one-shot hardware route only after all blockers are
    cleared.  On the Nomad, collect before-file evidence, allocate and inventory
    the display, launch/attach the exact fixture in one bounded operation, run
    FULL/LEFT/RIGHT/FULL plus the physical portrait/landscape round trip,
    teardown exactly, collect final inventory and after-file evidence, and
    accept only a replay-verified immutable terminal bundle.  Any uncertainty
    quarantines the session with no retry and no pen milestone.

## Host-only verification

Latest host-only result on 2026-09-15:

- both new Python files compiled successfully;
- the focused harness suite passed **59 tests in 202.133 seconds**,
  including independently re-signed full-log forgeries for missing operations,
  wrong artifact producer, false admission, wrong ledger identity, and changed
  terminal provenance, plus typed launch-uncertainty transfer/cleanup and exact
  Host/task/semantic monotonic-domain mismatch/drift cases, plus exact-object
  substitution before and during backend, adapter, and host-provider calls;
- the unchanged Android-authority, host-authority, cleanup-store, and
  cleanup-ledger suites passed **137 tests in 1.429 seconds**;
- the status-only CLI printed the complete blocked record and exited exactly 2.

The existing cleanup-store suite reported that its concrete native Windows
smoke path was unavailable under this workspace's access controls and verified
that condition fail-closed; its retained-handle/FakeWin32 publication,
checkpoint, recovery, and fault-boundary tests passed.  No device, network,
Git, subprocess adapter, or production component was changed or exercised.

Run from this directory with the bundled Python runtime:

```text
python -m py_compile native_page_visual_session_harness.py test_native_page_visual_session_harness.py
python -m unittest -v test_native_page_visual_session_harness
python -m unittest -v test_native_page_android_authority test_native_page_host_authority test_native_page_cleanup_store test_native_page_cleanup_ledger
```

The CLI readiness check is intentionally nonzero:

```text
python native_page_visual_session_harness.py --status
```

It prints canonical JSON with `admitted:false`, all blockers, the forbidden
operations, and `noRetry:true`, then exits 2.
