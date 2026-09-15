# Native-page production adapter v2 — corrected adversarial design

Status: **design only, independent review NOT CLEAN, implementation blocked, and
no device or hardware admission**.

This revision batches the second independent review's repairs. It defines an acyclic authority graph,
a separate capability-v2 engine, a single physical orchestration followed by
receipt-only logical facades, implementable transcript and device-file transports,
and three non-overwritable terminal layers. It changes no current source code.

## Identifier and implementation status

The architectural choices in the frozen decision table are fixed for this design
revision. **Every new module API name, class name, state name, method name, factory
identifier, wire field, nested schema, enum value, failure code, authority string,
and domain-separation string in this document is PROPOSED and is not frozen until
independent review.** Tables therefore label wire names and domain strings
`PROPOSED`.

Nothing below is implementation-ready. The explicit freeze checklist near the end
is normative for deciding when implementation may begin.

## Frozen decision table

The decision is frozen; its proposed wire spelling is not.

| ID | FROZEN decision | Required consequence |
|---|---|---|
| D01 | S2b remains the outer OS-control boundary. | Process/job creation, suspended launch, handle identity, containment, deadlines, kill/join, and closure are not delegated to a worker protocol. |
| D02 | V2 uses a separate capability engine and API. | A new `native_page_worker_capability_ipc_v2.py` owns its engine, closed registry, service-plan binding, authenticated bulk support, success close, failure revoke, and detached terminal/quiescence receipts. It shares no engine/session/registry object with capability-v1 and never mutates v1. |
| D03 | Capability-v1 is a pinned, repaired legacy baseline only. | Independent review found the final post-operation-scope-narrowing capability-v1 baseline CLEAN. The SHA-256 pin for `native_page_worker_capability_ipc.py` is `40894D3F1E6BE0AA6A3AA56A18300FEA72C53049BB1A9F514ADD2244C7FF499A`; the pin for `test_native_page_worker_capability_ipc.py` is `E572308A1095334BC31ECAB36C2A83D1C8A1DCFE06CF00F5B364EFE9D9D3D3F5`. V2 implementation may not modify those reviewed bytes, public API, factory registry, or tests after this design freeze. These pins name the newest repaired baseline, not any older worktree. No v2 type is accepted by v1 and no v1 live session/lease crosses into v2. |
| D04 | One OS service brokers two independent v2 lanes. | Authority and Frida have distinct factories, sessions, keys, epochs, endpoints, owners, operation cursors, callback ordinals, bulk cursors, and terminal receipts. |
| D05 | Protocol and OS roles use disjoint terms. | `Parent`/`Child` identify one capability-v2 protocol lane only. `requester`, `settlement verifier`, `supervisor`, and `service` identify OS/process roles only. |
| D06 | The plan authority graph is acyclic. | Canonical `PlanCoreV2` is hashed first. Plan-bound lane envelopes are hashed next. Supervisor/service key attestations and execution binding follow; no object contains or signs its own digest. |
| D07 | Direct context binding is phase-typed. | Static policy/image/scalar types contain neither P nor E; pre-plan outer records bind constructionId with neither P nor E; pre-E construction records bind P without E; every post-E protocol/evidence/receipt/envelope directly includes P and E. Exact exceptions and every wire row are registry-checked; no inference from a nested reference. |
| D08 | One orchestration entry performs all physical work. | It executes BEFORE -> Frida composite -> AFTER -> service terminal/close -> supervisor terminal/close -> requester settlement/bridge. It creates no logical facade before both upper layers close. |
| D09 | `authority_worker-v2` uses one broker-global 0..23 slot cursor and one Frida barrier. | Slots 0..11 precede the barrier; slots 12..23 require a settled Frida receipt. Skip, duplicate, reorder, retry, or barrier substitution is terminal failure. |
| D10 | File bytes use a device-side retained descriptor guardian. | Android descriptors are not inherited or proxied into a Windows Child. A reviewed guardian owns the same device FD and sends end-to-end authenticated/encrypted plaintext only to the authority Child for hashing. |
| D11 | Initial URI support is exactly canonical `file://`. | `content://` and every other scheme fail before a guardian opens a document descriptor. |
| D12 | `frida_worker-v2` owns one physical composite. | Prebound target -> physical attach -> supervisor-attested load-time selector freshness -> load -> exact callbacks -> seal -> unload -> detach -> quiescence happens in one operation. |
| D13 | Every `FridaProviderV2` method is later receipt consumption. | Admission, attach, load, seal, unload, detach, teardown, and quiescence perform zero service, OS, device, Frida, worker, or transcript-transport I/O. |
| D14 | Logical success and failure are explicit receipts. | Each admission/stage/attach/load/seal/unload/detach/quiescence/teardown/closure transition has one exact success or failure receipt, predecessor, global ordinal, facade cursor, projection digest, and null rules. |
| D15 | Transcripts have an implementable per-hop topology. | Each Child->service, service->supervisor, and supervisor->settlement-verifier hop has a named owner, one direction, distinct key/endpoints, exact record chain, close receipts, and crash behavior. |
| D16 | Transcript carrier partition is exact. | Canonical transcripts of 1..65,536 bytes use the authenticated inline carrier; 65,537..4,194,304 bytes use bulk; zero or larger values fail. Normal control messages contain references only. |
| D17 | Raw PDF/APK/framework/module/mark bytes never use control, inline transcript, bulk transcript, log, receipt, or diagnostic paths. | Only the separate guardian-to-authority-Child file stream carries plaintext, and only the Child returns stat/digest evidence. |
| D18 | Service provenance has one closed signature profile. | Ed25519 service signatures are rooted through E and the pinned supervisor trust anchor. No service-provenance MAC fallback, algorithm negotiation, or requester-known provenance key is accepted. Lane/control HMACs remain transport authentication only. |
| D19 | Unsigned bodies precede signed envelopes. | Service and supervisor first canonicalize unsigned terminal bodies, sign exact length-delimited inputs, then create final envelopes whose digests are computed externally. The next layer attests output EOF, signing-handle closure, process join, and handle closure. |
| D20 | Service, supervisor, and requester have separate post-E terminal chains. | Before E, the distinct P-rooted outer construction-settlement union applies. After E, each layer selects one emitted, proved-missing, or unobserved-uncertain arm. Supervisor uncertainty after service success and requester-local failure after both successes never rewrite prior chains. |
| D21 | There is one non-rebasable physical-operation deadline and one precomputed cleanup/settlement deadline. | A success candidate must seal before the first deadline. Only closure, cleanup, verification, and bridge creation may use the grace window. No timeout is recomputed. |
| D22 | Shared cleanup is broker-session scoped. | Exact retained generations are fenced, revoked, killed/joined, closed, and attested. Never-started lanes and pre-resume job assignment receive explicit receipts. No broad process/task/server/file cleanup is allowed. |
| D23 | Current `AuthorityEngine` v1 remains untouched. | V2 lives in new modules and produces v2 projections. There is no v1 schema reinterpretation, monkey patch, registry edit, or import-time replacement. |
| D24 | No automatic retry exists. | A new attempt requires a new PlanCore, nonces, service, lane envelopes, keys, epochs, endpoints, guardian sessions, cursors, and terminal chains. |

## Roles and exact trust boundary

| Role | Exact meaning | Trust/authority |
|---|---|---|
| Application requester | Caller asking for an observation. | Potentially adversarial: it can submit malformed/replayed inputs, know requester transport keys, disconnect, race calls, and lie about local state. It cannot attest service execution. |
| Requester-side settlement verifier | Minimal reviewed v2 adapter component that owns the supervisor output endpoint and validates settlement before exposing facades. | Trusted for canonical validation, pinned-root verification, local handle/process EOF/join observation, bridge construction, and logical receipt consumption. If arbitrary same-process requester memory mutation is in scope, this verifier must be an isolated process; otherwise there is no adversarial-requester claim. |
| OS supervisor | Trusted S2b process outside the contained job. | Owns PlanCore creation, fixed clocks/deadlines, suspended creation/job assignment, root-attested per-run signing key, service-key/process attestation, detached placement/pen/checkpoint/selector attestations, cleanup, and service closure verification. It does not invent device evidence. |
| OS service | The one broker inside the supervisor-owned kill-on-close job. | Owns both protocol Parents, broker-global slot/record cursors, exact orchestration, evidence-chain validation, session cleanup, and the service-only terminal signing key. |
| Capability-v2 Parent A/F | One lane endpoint/session held by the OS service. | Protocol role only. Parent A and Parent F are different live objects and authorities. |
| Capability-v2 Child A | `authority_worker-v2`. | Read-only evidence engine. It receives guardian streams and fixed read/attestation capabilities, but no Frida mutation capability. |
| Capability-v2 Child F | `frida_worker-v2`. | Owns only the pinned physical Frida composite, observer, target/selector oracle, callback sink, and exact teardown authority. It receives no file stream. |
| Device descriptor guardian | Reviewed device-side process instance owning one exact FD or one exact absence directory FD. | Trusted only for its attested binary/process/credential, closed operation set, same-FD stat/read/close receipts, and stream cryptography. Root credential is not general root authority. |
| Stock target, ADB/Frida peers, host app | Evidence subjects. | Untrusted until exact external authorities and before/after stability checks pass. |

```text
untrusted requester / isolated hostile callback worker
                         |
outer S2b owner (surviving OS lifetime + terminal registry + fixed deadline)
       |                 |
       |     isolated reviewed settlement verifier
       |                 | owns supervisor output observation
       +--------- OS supervisor (root-attested; outside contained job)
                         |
           +-- Windows kill-on-close job ----------------------+
           | OS service: Parent A <-> Windows Child A          |
           |             Parent F <-> Windows Child F          |
           +---------------------------------------------------+
                         | ciphertext / fixed authenticated commands
                         | private transport boundary
           Android guardians (NOT members of a Windows job)
           same-FD owners; Android BOOTTIME lease + EOF watchdog
```

`Parent` never means supervisor or application requester. `Child` never means the
OS service or a device guardian.

“Logical requester” below means the reviewed requester-side settlement verifier,
not the adversarial application requester. It alone constructs and independently
validates the bridge after physical settlement. The application receives only the
validated detached facades/result.

## One physical orchestration entry

The only physical entry point is the PROPOSED API
`execute_native_page_production_adapter_v2`. It returns either a settled-success
adapter containing logical facades or a settled failure view. It never returns a
live service, worker, Frida session, callback sink, guardian stream, OS handle,
capability session, operation ticket, start permit, or cleanup owner.

Its order is exact:

1. the outer S2b owner starts and image-verifies the supervisor in a
   construction-only state with no service/worker/device/Frida authority;
2. that supervisor constructs and hashes `PlanCoreV2`;
3. start the service key-only bootstrap and suspended workers; create
   and verify acyclic lane/execution attestations;
4. prove every created worker is assigned to the one exact job before its
   validation-only bootstrap resume; collect its E-validation receipt and open
   the separate supervisor-authenticated work gate only after all validate;
5. after the work gate opens, launch/attest the exact device guardians and execute
   authority slots 0..11 and seal BEFORE;
6. cross the broker-owned Frida barrier with one settled physical composite;
7. execute authority slots 12..23 and seal AFTER;
8. seal an immutable authority snapshot evidence candidate; it is not yet the
   final snapshot receipt because lane terminal/quiescence receipts do not exist;
9. revoke/close both v2 lanes and guardians, finalize the Frida composite-closure
   receipt and exactly one authority snapshot success/failure receipt from the
   sealed candidate, then produce the one service terminal;
10. close service output/signing handles and service process under supervisor proof;
11. produce the one supervisor terminal, then close supervisor output/signing
    handles and process under settlement-verifier proof;
12. verify all signed envelopes, transcript hops, EOFs, joins, and closures;
13. the logical requester constructs and independently validates the requester
    bridge; and
14. only now instantiate receipt-only authority/Frida logical facades.

If any step fails, later physical normal-work steps are forbidden. A physical
failure may still yield a settled failure view after exact closure, but never a
normal facade.

## Acyclic PlanCore, lane envelopes, and execution binding

### Exact construction order

The following order removes every self-reference:

Precondition: the outer S2b owner has image-verified the supervisor in the
construction-only state; that process owns the steps below.

1. Canonicalize unsigned `PlanCoreV2` bytes `C` without any PlanCore digest,
   lane-live identity, public-key attestation, or terminal field.
2. Compute `P = SHA256(LD(D(PlanCoreV2,body-hash), [C]))`. `P` is the
   `planCoreSha256`/service-plan digest used everywhere later.
3. Generate the supervisor per-run signing key. A pinned supervisor trust anchor
   signs an unsigned supervisor-key-attestation body binding `P`, the supervisor
   image/process, and public key. Hash the resulting envelope externally.
4. Start the service and both workers suspended and create their exact
   `JobAssignmentReceiptV2` pre-binding receipts. Each receipt binds `P`, process,
   job, and assignment generation only; none contains or predicts `E`.
5. Permit only the service's pinned key-bootstrap entry to run. It has no lane,
   device, Frida, guardian, transcript, requester, or normal-work handle. It
   generates a nonexportable service signing key, publishes its public key and
   handle identity in `ServiceKeyBootstrapReceiptV2`, and blocks at the one-shot
   execution gate. The workers remain suspended.
6. Create/duplicate the exact endpoint generations for the already-known process
   identities. Construct canonical Authority and Frida lane bodies, each binding
   `P`, then compute lane digests `A` and `F` externally. Neither body contains its
   own digest or the later execution digest.
7. Construct
   unsigned `ExecutionBindingBodyV2` containing `P`, `A`, `F`, the three
   pre-binding job-assignment receipt digests, outer transport bindings, service
   process/public key, and supervisor-key-attestation digest.
8. Compute `E = SHA256(LD(D(ExecutionBindingBodyV2,body-hash), [canonical execution body]))`.
9. The supervisor signs `LD(D(ExecutionAttestationEnvelopeV2,signature),
   [raw(P), raw(E), utf8(supervisorSigningKeyId), raw(E),
    u64be(byteLength(canonical execution body)), canonical execution body])`; the signature is placed in a
   separate envelope. Hash that envelope externally.
10. The supervisor validates E itself, then issues each suspended worker exactly
    one `BootstrapResumeReceiptV2`. The resumed image can only read its sealed
    descriptor, validate P/lane/E, and emit `BootstrapValidationReceiptV2`; it has
    no admitted operation lease, document FD, Frida, or device authority. Pinned
    bootstrap transport handles may exist but their normal ingress is sealed.
11. After the service-specific post-E validation and both worker validation receipts pass, the supervisor issues
    `WorkGateBodyV2` authenticated by its E-rooted key. Only consumption of this
    one-shot gate admits lane epochs and unseals the already-identity-bound normal
    endpoints; device/Frida/file capabilities are provisioned only after that gate.
    Neither resume nor validation alone permits a physical operation.

There is no aggregate object whose digest appears inside itself. Lane IDs are
derived from `P` and lane-local nonces, not from an envelope that contains those
IDs. The service public key is outside PlanCore and is attested by the supervisor's
already-rooted per-run key.

### Bootstrap and pre-E construction settlement

The outer S2b owner is a separately retained reviewed process, not the application,
supervisor, service, or Python watchdog thread. It owns the supervisor/verifier
handles and a durable append-once terminal registry. It never waits on requester
code. Construction reserves each acquisition before its syscall and publishes the
actual retained result before exposing a handle to a child. The closed acquisition
union in **Acquisition and missing-layer algebra** applies at every cursor.

`BootstrapResumeReceiptV2` exact body: `planCoreSha256`,
`executionBindingSha256`, `processRole`, `processIdentity`,
`jobAssignmentReceiptSha256`, `descriptorSha256`, `bootstrapHandleSetSha256`,
`resumeGeneration`, `validationOnly=true`, `workAuthorityGranted=false`,
`supervisorObservedNs`, `outcome`. It is supervisor-signed; a partial resume is
not success. `BootstrapValidationReceiptV2` exact body: `planCoreSha256`,
`executionBindingSha256`, `laneBodySha256`, `processRole` (authority or frida only),
`processIdentity`, `resumeReceiptSha256`, `descriptorSha256`,
`retainedBootstrapHandleSetSha256`, `validationChallenge`, `validated=true`,
`normalWorkCount=0`, `workGateConsumed=false`. In this validation body,
resumeReceiptSha256 names the post-syscall ProcessResumeReceiptV2, whose
bootstrapResumeAuthorizationSha256 names the pre-resume authorization. The pinned bootstrap-auth endpoint
authenticates this receipt; the supervisor attests its exact digest, identity and
challenge, not a self-asserted clock. `WorkGateBodyV2` exact body:
`planCoreSha256`, `executionBindingSha256`, `executionAttestationSha256`,
`validationReceiptDigests` (service,A,F order), `gateId`, `gateGeneration`,
`preGateRetainedHandleRootSha256`, `operationDeadlineNs`,
`supervisorObservedNs`, `disposition=open`. Its signature precedes delivery;
The pre-gate root contains only already acquired sealed bootstrap/transport
objects, not future device/Frida/file acquisitions. Those later acquisitions bind
the gate digest and cannot appear in its root. Gate ID/generation are consumed
once under the same retained dispatch lock as epoch admission. Receipt emission never waits for its own gate or admitted epoch.

The separate `ConstructionSettlementBodyV2` exact body is `planCoreSha256`,
`constructionId`, `constructionCursor`, `executionState`,
`candidateExecutionBodySha256`, `candidateExecutionAttestationSha256`,
`acquisitionSnapshotRef`, `firstFailure`, `outerOwnerIdentity`,
`outerCheckpointSha256`, `settlementDeadlineNs`, `observedNs`, `outcome`.
`executionState` is `not-built|built-unattested|attested-not-published`;
candidate digests obey that exact prefix (null/null, nonnull/null, nonnull/nonnull).
This body has NO `executionBindingSha256` field and never claims an ordinary lane
terminal. It is P-rooted and signed by the independently pinned outer owner; if P
was never computed, the distinct `PrePlanAbortBodyV2` binds only construction ID,
outer image/process, acquisition cursor/states and failure. `constructionCursor`
is exactly the next step in `CORE, ROOT_KEY, SERVICE_CREATE, A_CREATE, F_CREATE,
ASSIGN, SERVICE_KEY_BOOTSTRAP, ENDPOINTS, LANES, EXECUTION_BODY, EXECUTION_SIGN,
EXECUTION_PUBLISH`; every crash preserves the completed prefix and pending
acquisition reservation. `outcome=settled-abort` requires all acquired objects
closed; otherwise `retained-uncertain`, with no invented identity for an unresolved
reservation. Neither arm authorizes retry or a facade.

E becomes externally committed only after durable execution-attestation
publication; a CAS selects either this post-E branch or construction settlement,
never both. Descriptor copy/hash/EOF faults, resume faults, validation receipt
loss/replay, gate delivery/ACK uncertainty and supervisor loss are tested before
and after every step. Before the gate, Children exit on authenticated cancellation,
bootstrap EOF or the original host deadline; the outer owner kills/joins exact
Windows handles if they do not. After committed E these failures use post-E
unquiesced/missing lane arms, even if no normal operation ever started.

### Static-core topological order and live-observation boundary

PlanCore's entire transitive closure is static policy/content/provisioning data.
In particular TargetPolicyV2, HostPolicyV2 and GuardianFilePolicyV2 contain no
ProcessIdentityV2, AcquisitionTokenV2, live task/activity/session/display/generation,
descriptor identity, or observed mark-presence value. reviewedContentSha256 is a
provisioned content pin, not a claim that a path currently exists. Process/image
file pins in this closure are independently provisioned static manifests, not
digests of later P-bound acquisition evidence. A validator recursively enforces
this allowed-type closure before hashing P; a mere opaque hash cannot hide a
forbidden dependency on future P/E.

After P/E and the work gate, the supervisor acquires independent evidence:
LiveTargetBindingV2 (P,E, targetPolicySha256, processIdentity, taskId,
activityTokenSha256, displayId, causalLaunchReceiptSha256,
causalAttachReceiptSha256, forbiddenOwnerSetSha256, challenge,
capturedMonotonicNs, operationDeadlineNs);
LiveHostBindingV2 (P,E,hostPolicySha256,hostSessionId,processIdentity,taskId,
activityTokenSha256,displayId,placementGeneration,packageSha256,
placementReceiptSha256,challenge,capturedMonotonicNs,operationDeadlineNs);
InitialFileObservationV2 (P,E,filePolicySha256,fileRole,presence,
descriptorIdentitySha256,contentSha256,absenceBeforeEvidenceSha256,
challenge,capturedMonotonicNs,operationDeadlineNs).
Presence is present or absent: present requires descriptor/content and null absence;
absent is mark-only and requires BEFORE absence with null descriptor/content.
These are supervisor-attested post-E evidence, not inputs to P or E. Retained
external target/host processes are observed, never implicitly created/disposable.
The physical Frida attach selector must match these authenticated bindings.

The following executable topological fixture is normative about dependency
direction; real validators additionally check every typed reference and object ID:

```python
deps = {
 "static": (), "P": ("static",),
 "outer-observed-supervisor": ("P",),
 "supervisor-key": ("P", "outer-observed-supervisor"),
 "assignments": ("P",),
 "service-bootstrap-resume": ("P", "assignments"),
 "service-bootstrap-effect": ("service-bootstrap-resume",),
 "service-key": ("P", "service-bootstrap-effect"),
 "lanes": ("P", "assignments"),
 "E": ("P", "lanes", "service-key", "supervisor-key"),
 "E-attestation": ("E",),
 "worker-resume": ("E-attestation", "assignments"),
 "worker-validation": ("worker-resume",),
 "service-validation": ("E-attestation", "service-bootstrap-effect", "service-key"),
 "work-gate": ("worker-validation", "service-validation"),
 "live-target-host-files": ("P", "E", "work-gate"),
 "physical-attach": ("live-target-host-files",),
}
done = set()
for node, parents in deps.items():
    assert set(parents) <= done
    done.add(node)
assert "live-target-host-files" not in deps["P"]
```

### Service bootstrap is not worker resume

ServiceBootstrapResumeReceiptV2 is P-rooted/pre-E: planCoreSha256,
constructionId, serviceIdentity, jobAssignmentReceiptSha256,
bootstrapDescriptorSha256, resumeGeneration, preSuspended=true,
authorityClass=key-bootstrap-only, authorizedHostNs, constructionDeadlineNs.
ServiceBootstrapEffectReceiptV2 is P-rooted/pre-E: planCoreSha256, constructionId,
resumeAuthorizationSha256, serviceIdentity, resumeGeneration,
postState=running-waiting-for-execution, actualResumeHostNs,
zeroNormalAuthorityHandleSetSha256, operationCount=0, outcome.
Outcome is resumed or uncertain; uncertain never permits service key admission.
The supervisor observes and signs these under its P-rooted attested key. Neither
has E, an E-shaped null placeholder, or a future work-gate digest.

ServiceKeyBootstrapReceiptV2 additionally includes
serviceBootstrapEffectReceiptSha256. It proves the key was made by that running
key-only bootstrap. After E is committed the already-running service reads it
without another OS resume. ServiceExecutionValidationReceiptV2 is post-E:
planCoreSha256, executionBindingSha256, serviceIdentity,
serviceBootstrapEffectReceiptSha256, serviceKeyBootstrapReceiptSha256,
executionDescriptorSha256, validationChallenge,
observedState=running-waiting-for-work-gate, normalWorkCount=0,
validated=true, workGateConsumed=false. Its pinned bootstrap MAC and supervisor
observation are required. It never has preSuspended=true or names a post-E
ProcessResumeReceiptV2. WorkGate validationReceiptDigests is this service receipt
followed by the two worker BootstrapValidationReceiptV2 digests.
Worker resume/validation receipts apply only to authority and frida roles.
Faults before/after each effect/key/descriptor/receipt remain in their actual
pre-E or post-E acquisition branch; timestamps cannot be backdated.

### Detached acquisition snapshots and bounded enclosure

No wire object embeds a vector of up to 512 AcquisitionStateV2 bodies. Every such
field is replaced by acquisitionSnapshotRef (or allAcquisitionSnapshotRef for the
supervisor's complete owner union), an exact AcquisitionSnapshotRefV2.
A snapshot reference is not a declaration: its detached canonical body must be
received, length/hash/schema validated and owner-authenticated before the enclosing
receipt can be admitted. Missing snapshot delivery is retained uncertainty.

AcquisitionSnapshotBodyV2 has exact fields contextPhase, constructionId,
planCoreSha256, executionBindingSha256, ownerIdentitySha256,
sourceLedgerPrefixSha256, stateCount, states.
contextPhase is pre-plan/pre-E/post-E: both hashes null / P only / P and E.
stateCount is 0..512 and equals len(states); states is the exact acquisition-ID
ordered complete inventory, including pending/unused reservations.
Each AcquisitionStateV2 is at most 4096 canonical bytes. Fixed snapshot metadata
plus array punctuation excluding members is at most 4096+513 bytes, so
snapshot length <= 4096+513+512*4096 = 2,101,761 bytes, strictly below 4,194,304.
This detached LARGE-SNAPSHOT class uses its own 64-chunk bounded channel. The
4MiB bound is not an ordinary control-frame allocation.

AcquisitionSnapshotRefV2 is at most 1024 bytes, exact fields contextPhase,
constructionId, planCoreSha256, executionBindingSha256, snapshotByteLength,
snapshotSha256, stateCount, ownerIdentitySha256, sourceLedgerPrefixSha256.
Byte length is 1..2101761. The context/owner/ledger/count must equal the received
snapshot; its typed digest is D(AcquisitionSnapshotBodyV2,body-hash).
No enclosing receipt's hash appears in the snapshot. Snapshot references in
construction/lane/guardian/transfer/cleanup/missing-layer terminals are prior
evidence, not a future terminal's root. No reference is accepted only by hash.

This replacement bounds former 512-entry enclosures by a <=1024-byte scalar
reference; seven inline acquisition states in a hop body remain <=28672 bytes.
All enclosing CONTROL bodies retain their 65536-byte cap, with actual maximal
fixtures required by the registry; they cannot promote themselves to LARGE.
A failed/not-started hop may reference a snapshot plus typed null observations
instead of manufacturing seven acquired states.

### Length-delimited primitive

All hashes, signatures, and MACs use the same reviewed length delimiter:

```text
LD(domain, parts) =
  u32be(byte_length(domain_utf8)) || domain_utf8 ||
  u32be(part_count) ||
  for each part: u64be(byte_length(part)) || part
```

Lengths are range-checked before conversion. Domain is strict NFC UTF-8. A digest
part is the decoded 32 bytes, never its 64-byte hexadecimal spelling. `u32be` and
`u64be` are unsigned and reject overflow. No concatenated, delimiter-free, or
JSON-string interpolation input is permitted.

### `PlanCoreV2` proposed exact keyset

Every field below is **PROPOSED and not frozen**. Missing/extra keys fail.

| PROPOSED field | Exact requirement |
|---|---|
| `authority` | Proposed PlanCore authority string. |
| `schemaVersion` | Integer `2`. |
| `serviceSessionId` | Fresh lowercase 64-hex broker session. |
| `planNonce` | Independent fresh lowercase 64-hex value. |
| `clockId` | Exact authenticated monotonic-clock incarnation. |
| `createdMonotonicNs` | Canonical positive decimal string in signed-int64 range. |
| `operationDeadlineNs` | One canonical decimal signed-int64 deadline. |
| `cleanupGraceNs` | Canonical positive decimal signed-int64 duration. |
| `cleanupDeadlineNs` | Checked exact sum of operation deadline and grace. |
| `supervisorTrustAnchor` | Exact `TrustAnchorPinV2` nested object. |
| `outerOwnerTrustAnchor` | Exact separately provisioned `TrustAnchorPinV2`; same pin verifies pre-P construction abort. |
| `outerOwnerImage` | Exact `ProcessImagePinV2` for the outer S2b owner. |
| `supervisorImage` | Exact `ProcessImagePinV2` nested object. |
| `serviceImage` | Exact `ProcessImagePinV2` nested object. |
| `authorityWorkerImage` | Exact `WorkerImagePinV2`, including its complete dependency closure. |
| `fridaWorkerImage` | Distinct exact `WorkerImagePinV2`, including its complete dependency closure. |
| `guardianImages` | Exact sorted, nonempty list of `GuardianImagePinV2` roles/credentials/dependency closures. |
| `authorityFactoryPolicySha256` | Digest of the closed v2 authority registry entry. |
| `fridaFactoryPolicySha256` | Digest of the closed v2 Frida registry entry. |
| `targetPolicy` | Exact `TargetPolicyV2` nested object. |
| `hostPolicy` | Exact `HostPolicyV2` nested object. |
| `filePolicy` | Exact `FilePolicyV2` nested object, with `file://` only. |
| `observerSourceSha256` | Exact reviewed observer bytes. |
| `stabilityPolicySha256` | Exact before/after comparison policy digest. |
| `limits` | Exact `AdapterLimitsV2` nested object. |
| `orchestrationPolicy` | Closed booleans/order: visual-only, no retry, one broker, two lanes, 24 slots, one Frida composite, exact closure. |

`WorkerImagePinV2` has the following **PROPOSED exact fields**:
`role`, `factoryId`, `imagePath`, `imageSha256`, `bootstrapSha256`,
`interpreterSha256`, `dependencyManifestSha256`, `dependencies`,
`loadedDependencyClosureSha256`, `mitigationPolicySha256`, and
`environmentPolicySha256`. Each `dependencies` item has proposed exact fields
`ordinal`, `canonicalPath`, `sha256`, `size`, `fileIdentitySha256`, and
`loadDisposition`. Authority and Frida image/dependency closure digests must differ
where their bytes/roles differ; one pin cannot stand in for both.

### Lane body proposed exact keyset

Each canonical `LaneBindingBodyV2` has these **PROPOSED, not frozen** fields:

| PROPOSED field | Exact requirement |
|---|---|
| `authority` | Proposed lane-binding authority. |
| `schemaVersion` | Integer `2`. |
| `planCoreSha256` | Exact `P`. |
| `serviceSessionId` | Exact PlanCore session. |
| `lane` | Proposed exact token `authority` or `frida`. |
| `factoryId` | Exact proposed closed-registry factory. |
| `factoryPolicySha256` | Corresponding PlanCore policy digest. |
| `workerImageManifestSha256` | Corresponding exact worker image/dependency manifest. |
| `laneNonce` | Fresh lane-local lowercase 64-hex value. |
| `sessionId` | Domain-derived from `P`, service session, lane, and lane nonce. |
| `epochId` | Independent fresh lowercase 64-hex epoch. |
| `epochAdmissionId` | Independent fresh one-shot admission. |
| `keyId` | SHA-256 identifier of the lane secret; never the key. |
| `ownerIdentity` | Exact `WindowsObjectIdentityV2`. |
| `controlTransport` | Exact four-endpoint `LaneControlTransportV2`. |
| `callbackDrainIdentity` | Exact retained drain identity. |
| `bulkTransport` | Exact pre-E `HopFactoryBindingV2`, not a future per-transcript endpoint. |
| `resourceBindingSha256` | Closed, ordered retained-resource table digest. |
| `operationCursorInitial` | Integer `0` in this lane namespace. |
| `messageOrdinalInitial` | Integer `0` in this lane namespace. |
| `bulkCursorInitial` | Integer `0` in this lane namespace. |
| `operationDeadlineNs` | Exact PlanCore operation deadline. |

The lane-body digest is external and therefore absent from this keyset.

### Execution binding and supervisor trust

`SupervisorKeyAttestationBodyV2` has these **PROPOSED exact fields**:
`authority`, `schemaVersion`, `planCoreSha256`, `supervisorProcessIdentity`,
`supervisorImageSha256`, `trustAnchorPolicyVersion`, `perRunKeyAlgorithm`,
`perRunSigningPublicKey`, `perRunSigningKeyId`, and `createdMonotonicNs`. It contains
no body/envelope digest or signature. The pinned root signs exactly
`LD(D(SupervisorKeyAttestationEnvelopeV2,signature),
[raw(P), utf8(rootSigningKeyId), raw(bodySha256), u64be(byteLength(body)), body])`; body and final
`SupervisorKeyAttestationEnvelopeV2` digests are external. Thus PlanCore contains
only the root pin/policy, never this later per-run key or attestation.

`ExecutionBindingBodyV2` has these **PROPOSED exact fields**:
`authority`, `schemaVersion`, `planCoreSha256`, `serviceSessionId`,
`authorityLaneBodySha256`, `fridaLaneBodySha256`, `supervisorKeyAttestationSha256`,
`supervisorProcessIdentity`, `serviceProcessIdentity`, `serviceJobIdentity`,
`serviceJobAssignmentReceiptSha256`, `authorityWorkerAssignmentReceiptSha256`,
`fridaWorkerAssignmentReceiptSha256`, `serviceKeyBootstrapReceiptSha256`,
`outerControlBindingSha256`,
`serviceToSupervisorBulkBindingSha256`, `supervisorToVerifierBulkBindingSha256`,
`serviceSigningAlgorithm`, `serviceSigningPublicKey`, `serviceSigningKeyId`, and
`createdMonotonicNs`.

`ExecutionAttestationEnvelopeV2` has these **PROPOSED exact fields**:
`authority`, `schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`executionBodyByteLength`, `executionBodySha256`, `signatureAlgorithm`,
`supervisorSigningKeyId`, `supervisorKeyAttestationSha256`, and `signature`. Its
signature input is the exact construction-order step 9 tuple and its envelope
digest is external; it contains neither the canonical execution body nor its own
digest because validators receive the separately length/digest-checked body.

The supervisor trust anchor is an exact pinned public-key algorithm/key digest and
policy version in PlanCore. It attests a distinct per-run supervisor signing key.
That key attests `E`, the service public key/process, both lane bodies, and job
assignment. Neither service nor requester can replace this chain.

The two outer bulk-binding fields name pre-E endpoint factories, not per-object
dynamic handles. A `HopFactoryBindingV2` has exact fields `planCoreSha256`,
`hopNamespace`, `senderProcessIdentity`, `receiverProcessIdentity`,
`factoryGeneration`, `hopMasterKeyId`, `ackControlBindingSha256`,
`endpointPolicySha256`, `maxObjects=16`, `maxObjectBytes=4194304`.
The supervisor generates four distinct 32-byte hop masters, delivers each only to
that row's two pinned owners through pre-E bootstrap sealed-key descriptors, and
attests their IDs in these factories. E commits the factory hashes, not secret
keys. Key IDs are SHA-256 of the exact key bytes under their key-ID domain.
Dynamic endpoints/derived keys are post-E children of this fixed authority.

## Separate capability-v2 engine

The future `native_page_worker_capability_ipc_v2.py` is a separate module with a
separate API, engine, types, exceptions, codecs, registry, and tests. It may carry
forward independently reviewed invariants, but it does not import a v1 session,
subclass a v1 engine, mutate a v1 registry, accept a v1 receipt, or alias a v1
public type. The two final D03 post-operation-scope-narrowing hashes are the
byte-for-byte regression baseline. V2 work may not edit either reviewed file or
change the reviewed v1 public API/registry; older bytes are not the reference
target.

### Proposed v2 API surface

The exact API names are **PROPOSED, not frozen**:

- `CapabilityEngineV2`, `ParentCapabilitySessionV2`, and
  `ChildCapabilitySessionV2`;
- immutable `FACTORY_POLICIES_V2` with only the two reviewed factories;
- `CapabilityBindingBodyV2`, `OperationLeaseV2`, `DetachedPayloadV2`, and
  `DetachedBulkReferenceV2`;
- `CapabilityTerminalBodyV2`/`CapabilityTerminalEnvelopeV2`;
- `CapabilityQuiescenceBodyV2`/`CapabilityQuiescenceEnvelopeV2`;
- `close_success(deadline)` returning detached success terminal and quiescence
  envelopes; and
- `revoke_failure(first_failure, cleanup_deadline)` returning detached failure or
  uncertain terminal and quiescence envelopes.

The engine uses proposed layer-prefixed states:

```text
CAPV2_NEW -> CAPV2_ADMITTED -> CAPV2_OPEN
          -> CAPV2_ACTIVE -> CAPV2_OPEN (bounded operations)
          -> CAPV2_CLOSING_SUCCESS -> CAPV2_CLOSED_SUCCESS

any nonterminal failure
          -> CAPV2_REVOKING_FAILURE
          -> CAPV2_CLOSED_FAILURE | CAPV2_CLOSED_UNCERTAIN
```

Success close requires: no active operation; exact callback barrier; all inline and
bulk objects terminal; send direction sealed; authenticated EOF; epoch revoked;
owner/transport/drain quiescence; and detached receipts copied away from live
objects. Failure revoke preserves one first failure, forbids new operations,
attempts all fixed sibling cleanup steps, and distinguishes proved failure closure
from uncertainty. A caller cannot turn failure revoke into success close.

`CapabilityTerminalBodyV2` has these **PROPOSED exact fields**:
`authority`, `schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`laneBodySha256`, `lane`, `factoryId`, `sessionId`, `epochId`, `outcome`,
`operationCursorFinal`, `messageOrdinalFinal`, `bulkCursorFinal`,
`lastOperationReceiptSha256`, `firstFailure`, `epochRevocationReceiptSha256`,
`transportTerminalReceiptSha256`, `remainingEmitterStateSha256`, and `terminal=true`.

`CapabilityQuiescenceBodyV2` has these **PROPOSED exact fields**:
`authority`, `schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`laneBodySha256`, `sessionId`, `terminalEnvelopeSha256`,
`activeOperationCount=0`, `inFlightCallbackCount=0`, `openBulkObjectCount=0`,
`openEndpointCount=0`, `ownerQuiescenceSha256`, `transportQuiescenceSha256`,
`callbackDrainQuiescenceSha256`, `remainingEmitterStateSha256`,
`checkedMonotonicNs`, and `quiescent=true`.
The zero activity/endpoint counts cover normal operations and data transports,
excluding exactly the separately named final emission key/output/process slots.
RemainingEmitterStateV2 records those live slots. The service's later LaneClosureRef
requires independent final closure of them before proved-quiescent/success;
neither the lane terminal nor its quiescence body claims its own future exit.

Both are unsigned bodies authenticated by the lane MAC in final envelopes. Their
envelope digests are computed externally and copied into service receipts.

### Capability operation, outcome and barrier receipts

`CapabilityOperationReceiptV2` is a lane-authenticated body with exact fields
`planCoreSha256`, `executionBindingSha256`, `laneBodySha256`, `lane`, `factoryId`,
`sessionId`, `epochId`, `operationId`, `operationToken`, `operationCursorBefore`,
`operationCursorAfter`, `brokerSlot`, `phase`, `requestBodySha256`,
`previousOperationReceiptSha256`, `result`, `callbackCursorBefore`,
`callbackCursorAfter`, `bulkCursorBefore`, `bulkCursorAfter`,
`completedBulkRefDigests`, `operationDeadlineNs`, `supervisorAcceptanceReceiptSha256`,
`outcome`, `firstFailure`. All cursor fields are exact unsigned integers; the
operation cursor advances by one per admitted attempt, never on a rejected frame.
`brokerSlot` is 0..23 for slot tokens and null only for FRIDA_PHYSICAL_COMPOSITE;
`phase` is before/after for slots and none for that Frida operation. Admit, barrier,
close and revoke are forbidden operation-receipt tokens. Barrier acceptance records
its own control cursor; authorityOperationCursorBefore equals
 authorityOperationCursorAfter and does not consume a normal-operation cursor.
The predecessor is the external digest of the prior complete operation receipt,
or the type/lane-specific genesis for cursor zero. `lastOperationReceiptSha256`
in a lane terminal is exactly this final digest, or the genesis if no operation
was admitted. An interrupted admitted attempt has one failure/uncertain outcome
or an explicit missing-operation acquisition state; it is not retried or skipped.

`CapabilityResultRefV2` exact fields: `kind`, `bodySchema`, `bodyByteLength`,
`bodySha256`, `bulkRefDigests`. `kind=none` requires null schema/digest, length 0
and []; `kind=detached` requires the token's registered schema/digest, length
1..its bound and []; `kind=transcript-set` requires schema `TranscriptRefSetV2`,
the exact bounded canonical set digest/length, and 1..16 admitted refs in cursor
order. No arbitrary schema or raw file byte is accepted. `outcome=success`
requires the token's exact result kind and `firstFailure=null`; `failed` or
`uncertain` requires nonnull failure and only complete earlier result references.
`completedBulkRefDigests` is an exact prefix, not attempted/offered transfers.

`AuthorityBarrierAcceptanceV2` exact fields: `planCoreSha256`,
`executionBindingSha256`, `authorityLaneBodySha256`, `fridaLaneBodySha256`,
`authorityOperationCursorBefore`, `authorityOperationCursorAfter`,
`brokerSlotCursor=12`, `beforePhaseRootSha256`,
`fridaPhysicalSettlementEnvelopeSha256`, `fridaOperationReceiptSha256`,
`barrierRecordSha256`, `previousOperationReceiptSha256`,
`supervisorAcceptanceReceiptSha256`, `outcome=accepted`.
The Frida operation receipt and physical settlement exist first; then the service
creates a `FridaBarrierRecordV2`; only then can Authority accept it. The acceptance
receipt contains the prior service barrier digest; the service barrier never
contains this future receipt. Failure leaves slot cursor 12 blocked. Slot 12
requires this exact acceptance receipt and a success settlement; no lane terminal
or future quiescence receipt is a barrier input.

`ActiveOperationCheckpointV2` exact fields: `planCoreSha256`,
`executionBindingSha256`, `laneBodySha256`, `activeOperationId`,
`activeOperationCursor`, `completedOperationPrefixSha256`,
`priorCallbacksDrained=true`, `priorTransfersSettled=true`,
`activeOperationCount=1`, `laneTerminal=false`. This is a checkpoint of earlier
work while the sealing operation is active, not whole-lane quiescence.

### Closed proposed v2 registry

The Authority entry contains 24 distinct slot operations plus engine-level admit,
Frida-barrier acceptance, close, and revoke. The Frida entry contains exactly one
physical observation operation plus engine-level admit, close, and revoke.
Close/revoke are out-of-band control transitions, NOT normal operations or leases:
they never increment operationCursor, never return an operation result containing
a future terminal/quiescence envelope, and never produce CapabilityOperationReceiptV2.
The final lastOperationReceiptSha256 names only the last completed normal operation
(or the typed lane genesis if none). Admit and barrier controls also have their separately named
receipts/cursors. On close: seal normal ingress, settle/reject the active normal
operation, freeze its receipt prefix, then construct terminal and quiescence,
then next-owner closure. On revoke with an unproved active operation, preserve its
reservation/last completed prefix and use terminal-unquiesced/missing-crashed;
never synthesize a completed operation or zero activity. This exact out-of-band
model applies to both factories and all failure paths.
Operation names and resource IDs remain PROPOSED.

`FACTORY_POLICIES_V2` has exactly two **PROPOSED** keys:
`authority-snapshot-v2` and `frida-observation-v2`. The Authority factory's ordered
normal-work operation-token keyset is exactly:

```text
AUTH_SLOT_00_BEFORE_OPEN
AUTH_SLOT_01_BEFORE_DEVICE_STATE
AUTH_SLOT_02_BEFORE_TARGET_PROCESS
AUTH_SLOT_03_BEFORE_TARGET_BASE_APK
AUTH_SLOT_04_BEFORE_FRAMEWORK
AUTH_SLOT_05_BEFORE_NATIVE_MODULE_APK
AUTH_SLOT_06_BEFORE_ORIGINAL_PDF
AUTH_SLOT_07_BEFORE_MARK
AUTH_SLOT_08_BEFORE_ACTIVITY
AUTH_SLOT_09_BEFORE_DISPLAY
AUTH_SLOT_10_BEFORE_WINDOW
AUTH_SLOT_11_BEFORE_SEAL
AUTH_SLOT_12_AFTER_OPEN
AUTH_SLOT_13_AFTER_DEVICE_STATE
AUTH_SLOT_14_AFTER_TARGET_PROCESS
AUTH_SLOT_15_AFTER_TARGET_BASE_APK
AUTH_SLOT_16_AFTER_FRAMEWORK
AUTH_SLOT_17_AFTER_NATIVE_MODULE_APK
AUTH_SLOT_18_AFTER_ORIGINAL_PDF
AUTH_SLOT_19_AFTER_MARK
AUTH_SLOT_20_AFTER_ACTIVITY
AUTH_SLOT_21_AFTER_DISPLAY
AUTH_SLOT_22_AFTER_WINDOW
AUTH_SLOT_23_AFTER_SEAL
```

Its only non-slot protocol tokens are PROPOSED `CAPV2_ADMIT`,
`AUTH_ACCEPT_FRIDA_BARRIER`, `CAPV2_CLOSE_SUCCESS`, and
`CAPV2_REVOKE_FAILURE`. The Frida factory's only normal-work token is PROPOSED
`FRIDA_PHYSICAL_COMPOSITE`; its only protocol tokens are `CAPV2_ADMIT`,
`CAPV2_CLOSE_SUCCESS`, and `CAPV2_REVOKE_FAILURE`. Registry lookup rejects every
other token before resource acquisition. Repeated spelling across the two entries
for an engine token denotes separately registered policy entries, not a shared
session, key, cursor, lease, or resource.

Authority resources are exactly: private read-only device evidence source,
guardian encrypted-stream receiver, supervisor detached-attestation verifier,
fixed parser set, and transcript emitter. Frida resources are exactly: pinned Frida
device/server authority, target selector oracle, observer source, callback sink,
and exact session/script teardown. Neither resource set is a subset alias of the
other and no live resource handle appears in both.

### Intentional common values versus independent namespaces

The exact values intentionally common to both lanes are only:

- PlanCore digest `P` and execution binding digest `E`;
- broker `serviceSessionId` (not either lane session ID);
- clock incarnation, operation deadline, cleanup deadline;
- exact target-policy digest and target selector identity values needed by both;
- supervisor trust-chain digest; and
- the fact that both are members of the same supervisor-owned job.

Everything else—keys, key IDs, factory/session/epoch/admission IDs, owners,
endpoint objects, endpoint native identities, operation sequences, callback
ordinals, bulk cursors, transcript-ID namespaces, challenges, nonces, and terminal
receipts—is independent. Independent cursors may all have numeric value `0` at
creation; identity is `(planCoreSha256, lane/hop namespace, cursor kind, value)`.
Equal numeric zero is not aliasing. Using a cursor from a different namespace is.

## Windows object identity, assignment, and never-started closure

A bare PID or Windows handle value is never authority. `WindowsObjectIdentityV2`
has these **PROPOSED exact fields**:
`planCoreSha256`, `objectKind`, `ownerPid`, `ownerProcessStartId`,
`nativeValue`, `generation`,
`grantedRights`, `inheritanceDisposition`, `sourceObjectIdentitySha256`,
`duplicateOrdinal`, `duplicatedIntoPid`, and `creationReceiptSha256`.

`nativeValue` is a canonical unsigned decimal string. `generation` is allocated by
the exact owner registry and never reused. A duplicate binds its source identity,
ordinal, destination PID/start identity, reduced rights, and noninheritance policy.
Two processes may coincidentally have the same numeric value; no comparison omits
owner PID/start/generation/lineage.

Every service/worker is created suspended. `JobAssignmentReceiptV2` is strictly a
pre-execution-binding object and has these **PROPOSED exact fields**:
`authority`, `schemaVersion`, `planCoreSha256`, `bindingStage=pre-execution`,
`processRole`, `processIdentity`, `jobIdentity`, `assignmentGeneration`,
`createdSuspended=true`, `assignedBeforeResume=true`,
`activeJobProcessSetSha256`, `capturedMonotonicNs`, and `receiptOutcome`.
It MUST NOT contain `executionBindingSha256`, any placeholder for `E`, or the digest
of an object that contains `E`. After `E` and its supervisor attestation validate,
`ProcessResumeReceiptV2` binds `P`, `E`, the exact assignment-receipt digest,
process/job identities, pre/post suspended state, resume generation, capture time,
and outcome. It records bootstrap resume only and grants no normal work. The
separate validated work gate is mandatory. The earlier service transition is the closed
`SERVICE_BOOTSTRAP_KEY_ONLY -> SERVICE_BOOTSTRAP_WAIT_EXECUTION` path described
above; `ServiceKeyBootstrapReceiptV2` binds `P`, image/process/job identity,
zero-authority handle-set digest, service public key/key ID, nonexportability,
execution-gate identity, and outcome, and contains no `E`. This strict
pre-binding/bootstrap/post-binding split preserves the acyclic construction graph.

Only after committed E does every lane receive one closure-union observation,
even if its Child never starts. Pre-E partial lanes belong solely to construction settlement.
`LaneNeverStartedReceiptV2` has these **PROPOSED exact fields**:
`planCoreSha256`, `laneBodySha256` if constructed, `lane`, `processCreated`,
`jobAssignmentReceiptSha256`, `resumed=false`, `readyPublished=false`,
`epochAdmissionState`, `endpointCloseSetSha256`, `keyDestructionReceiptSha256`,
`processJoinReceiptSha256`, `outcome`, and `terminal=true`. An uncertain assignment
or join stays uncertain; it is not represented as harmless never-started success.

`LaneClosureRefV2` is the normalized **PROPOSED exact** closure union used by
post-close receipts. Its closed field set is defined in **Acquisition and missing-layer algebra**:
proved-quiescent, terminal-unquiesced, never-started, or missing-crashed. A complete
terminal without quiescence is retained as such, never discarded or upgraded.
A success snapshot requires proved-quiescent with a success terminal.

## Trusted supervisor detached attestations

Requester claims are never used as placement, pen, checkpoint, or selector
evidence. The supervisor obtains each body from its exact pinned provider,
validates it, detaches canonical bytes, binds a fresh challenge and PlanCore, and
signs it under the root-attested per-run supervisor key. A requester-known MAC is
never accepted for these detached attestations.

`SupervisorDetachedAttestationBodyV2` has these **PROPOSED exact fields**:
`authority`, `schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`serviceSessionId`, `attestationKind`, `challenge`, `captureId`,
`capturedMonotonicNs`, `providerIdentitySha256`, `subjectBodySha256`,
`previousAttestationSha256`, and `operationDeadlineNs`.

`SupervisorDetachedAttestationEnvelopeV2` has these **PROPOSED exact fields**:
`authority`, `schemaVersion`, `planCoreSha256`, `executionBindingSha256`, `bodySchema`,
`bodyByteLength`, `bodySha256`, `signatureAlgorithm`, `supervisorSigningKeyId`,
`supervisorKeyAttestationSha256`, and `signature`. Its signature input is exactly
`LD(D(SupervisorDetachedAttestationEnvelopeV2,signature),
[raw(P), raw(E), utf8(supervisorSigningKeyId), raw(bodySha256),
u64be(byteLength(body)), body])`; envelope digest is external.

Its exact typed subject schemas are:

- PROPOSED `PlacementSubjectV2`: `hostSessionId`, `hostProcessIdentity`,
  `hostPackageSha256`, `taskId`, `activityTokenSha256`, `displayId`,
  `placementGeneration`, `requestedRect`, `measuredRect`, `resumed`, `visible`,
  and `measurementSha256`;
- PROPOSED `PenLeaseSubjectV2`: detached scalar `leaseIdSha256`, `serial`,
  `guardianProcessIdentity`, `leaseSequence`, `acquiredDeviceBoottimeMs`,
  `expiresDeviceBoottimeMs`, `inputBlocked=true`, and `providerReceiptSha256`;
- PROPOSED `CheckpointSubjectV2`: `runSessionId`, `checkpointSequence`,
  `checkpointSha256`, `durabilityReceiptSha256`, and `storeIdentitySha256`; and
- PROPOSED `SelectorSubjectV2`: `serial`, `package`, `component`, `pid`,
  `processStartId`, `uid`, `fridaServerSessionId`, `physicalAttachReceiptSha256`,
  `selectorCaptureSequence`, and `providerReceiptSha256`.

The signature proves supervisor/provider provenance and challenge binding; typed
validators still validate the subject. No live pen lease, host object, checkpoint
handle, process handle, or selector provider crosses into a worker or bridge.

## `authority_worker-v2`: broker-global 24-slot machine

The OS service, not the requester and not the authority Child, owns proposed state
`BROKER_AUTH_SLOT_CURSOR` with exact next values `0..24`. The authority Child has a
separate lane operation cursor. The service advances the broker cursor only after
it validates the exact Child slot receipt and wraps it into the service-global
record chain. Slots 0..11 are followed by a separate proposed
`BROKER_FRIDA_BARRIER`; the barrier is not slot 12 and does not increment the slot
cursor. Slot 12 is admitted only after the barrier holds one detached-success
`FridaPhysicalSettlementEnvelopeV2`. The later Frida lane-terminal wrapper cannot
be the barrier predecessor because it does not exist until physical work ends.

```text
BROKER_AUTH_NEW
  -> BROKER_AUTH_SLOT_0 ... BROKER_AUTH_SLOT_11
  -> BROKER_AUTH_WAIT_FRIDA_BARRIER
  -> BROKER_AUTH_FRIDA_BARRIER_SETTLED
  -> BROKER_AUTH_SLOT_12 ... BROKER_AUTH_SLOT_23
  -> BROKER_AUTH_SNAPSHOT_CANDIDATE

first error -> BROKER_AUTH_FAILING -> BROKER_AUTH_CLOSED_FAILURE|UNCERTAIN
```

The exact slots and exact payload schema references are:

| Slot | Phase/action | Exact PROPOSED payload schema |
|---:|---|---|
| 0 | BEFORE open | `PhaseOpenEvidenceV2` with `phase=before`, no Frida predecessor, and exact placement/pen/checkpoint/tool/private-ADB attestations. |
| 1 | BEFORE device state | `DeviceStateEvidenceV2` with `phase=before`. |
| 2 | BEFORE target process | `TargetProcessEvidenceV2` with `phase=before`. |
| 3 | BEFORE target base APK | `GuardianFileDigestEvidenceV2` with `phase=before`, `fileRole=target-base-apk`. |
| 4 | BEFORE framework | `GuardianFileDigestEvidenceV2` with `phase=before`, `fileRole=framework`. |
| 5 | BEFORE native module/APK attachment | `GuardianFileDigestEvidenceV2` with `phase=before`, `fileRole=native-module-apk`. |
| 6 | BEFORE original PDF | `GuardianFileDigestEvidenceV2` with `phase=before`, `fileRole=original-pdf`, and nonnull `FileUriBindingV2`. |
| 7 | BEFORE nullable mark | Closed union `GuardianFileDigestEvidenceV2` or `GuardianAbsenceBeforeEvidenceV2`, with `phase=before`, `fileRole=mark`. |
| 8 | BEFORE activity evidence | `ParsedTranscriptEvidenceV2` with `phase=before`, `transcriptKind=activity-dump`. |
| 9 | BEFORE display evidence | `ParsedTranscriptEvidenceV2` with `phase=before`, `transcriptKind=display-dump`. |
| 10 | BEFORE window evidence | `ParsedTranscriptEvidenceV2` with `phase=before`, `transcriptKind=window-dump`. |
| 11 | BEFORE seal | `PhaseSealEvidenceV2` with `phase=before`, prior slots `0..10`, and active-operation checkpoint; its external slot-record digest becomes the BEFORE root. |
| 12 | AFTER open | `PhaseOpenEvidenceV2` with `phase=after`, slot-11 root, exact settled `FridaPhysicalSettlementEnvelopeV2`, and fresh placement/pen/checkpoint/tool/private-ADB attestations. |
| 13 | AFTER device state | `DeviceStateEvidenceV2` with `phase=after` and a fresh capture ID. |
| 14 | AFTER target process | `TargetProcessEvidenceV2` with `phase=after` and a fresh capture ID. |
| 15 | AFTER target base APK | `GuardianFileDigestEvidenceV2` with `phase=after`, `fileRole=target-base-apk`, and the exact retained guardian FD incarnation from slot 3. |
| 16 | AFTER framework | `GuardianFileDigestEvidenceV2` with `phase=after`, `fileRole=framework`, and the exact retained guardian FD incarnation from slot 4. |
| 17 | AFTER native module/APK attachment | `GuardianFileDigestEvidenceV2` with `phase=after`, `fileRole=native-module-apk`, and the exact retained guardian FD incarnation from slot 5. |
| 18 | AFTER original PDF | `GuardianFileDigestEvidenceV2` with `phase=after`, `fileRole=original-pdf`, exact slot-6 FD incarnation, and exact `FileUriBindingV2`. |
| 19 | AFTER nullable mark | `GuardianFileDigestEvidenceV2` or `GuardianAbsenceAfterEvidenceV2`, matching the present/absent decision and guardian/directory FD incarnation at slot 7. |
| 20 | AFTER activity evidence | `ParsedTranscriptEvidenceV2` with `phase=after`, `transcriptKind=activity-dump`, and a fresh transcript reference. |
| 21 | AFTER display evidence | `ParsedTranscriptEvidenceV2` with `phase=after`, `transcriptKind=display-dump`, and a fresh transcript reference. |
| 22 | AFTER window evidence | `ParsedTranscriptEvidenceV2` with `phase=after`, `transcriptKind=window-dump`, and a fresh transcript reference. |
| 23 | AFTER seal | `PhaseSealEvidenceV2` with `phase=after`, prior AFTER slots `12..22`, prior BEFORE root/barrier, stability result, and active-operation checkpoint; its external slot-record digest becomes the AFTER root. |

No structural-equivalence inference is permitted: each row cites a closed schema
plus exact field constraints. The schema definitions follow.

### Proposed exact evidence schemas

All names/fields/tokens here are **PROPOSED and not frozen**.

Every slot payload is wrapped by `SlotEvidenceEnvelopeV2` with exact fields:
`authority`, `schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`authorityLaneBodySha256`, `serviceSessionId`, `brokerSlot`, `phase`,
`laneOperationCursor`, `globalRecordOrdinal`, `operationToken`, `captureId`,
`capturedMonotonicNs`, `typedEvidence`, `typedEvidenceSha256`,
`transcriptRefs`, `previousSlotRecordSha256`, and `operationDeadlineNs`.
The slot record digest is computed externally and is absent from the body.

- `PhaseOpenEvidenceV2` exact fields: `phase`, `phaseChallenge`,
  `placementAttestationSha256`, `penAttestationSha256`,
  `checkpointAttestationSha256`, `toolBundleAttestationSha256`,
  `privateAdbAttestationSha256`, `hostProcessIdentitySha256`,
  `phasePredecessorRootSha256`, `fridaPhysicalSettlementEnvelopeSha256`, and
  `fridaBarrierRecordSha256`. BEFORE requires the last two to be null; AFTER
  requires both nonnull.
- `DeviceStateEvidenceV2` exact fields: `phase`, `serial`, `bootId`,
  `firmwareFingerprint`, `deviceBoottimeMs`, `adbServerIdentitySha256`,
  `sourceCaptureReceiptSha256`, and `bodySha256` of the bounded source bytes.
- `TargetProcessEvidenceV2` exact fields: `phase`, `serial`, `package`,
  `component`, `pid`, `processStartId`, `uid`, `cmdlineSha256`,
  `processHandleIdentitySha256`, and `sourceCaptureReceiptSha256`.
- `GuardianFileDigestEvidenceV2` exact fields: `phase`, `fileRole`,
  `guardianSessionId`, `guardianProcessIdentitySha256`, `fdIncarnationSha256`,
  `readEpoch`, `fileUriBinding`, `statBefore`, `expectedSize`, `streamedBytes`,
  `plaintextSha256`, `finalOffset`, `extraReadEof`, `statAfter`,
  `guardianOpenReceiptSha256`, `childStreamReceiptSha256`, and
  `guardianEpochReceiptSha256`. The exact `FileStatV2` nested object is defined in
  the guardian section.
- `GuardianAbsenceBeforeEvidenceV2` exact fields: `phase=before`, `fileRole=mark`,
  `guardianSessionId`, `guardianProcessIdentitySha256`,
  `directoryFdIncarnationSha256`, `entryNameUtf8Sha256`, `lookupEpoch=0`,
  `lookupBeforeReceiptSha256`, `directoryStatBefore`, `present=false`,
  `guardianEpochReceiptSha256`. There is no AFTER lookup or future field.
- `GuardianAbsenceAfterEvidenceV2` exact fields: `phase=after`, `fileRole=mark`,
  `guardianSessionId`, `guardianProcessIdentitySha256`,
  `directoryFdIncarnationSha256`, `entryNameUtf8Sha256`, `lookupEpoch=1`,
  `beforeAbsenceEvidenceSha256`, `lookupAfterReceiptSha256`,
  `directoryStatAfter`, `present=false`, `guardianEpochReceiptSha256`.
  It binds the exact BEFORE directory/name/identity and validates directory stat
  stability; it cannot retroactively add a second lookup to BEFORE.
- `ParsedTranscriptEvidenceV2` exact fields: `phase`, `transcriptKind`,
  `transcriptRef`, `parserImageSha256`, `parserPolicySha256`,
  `parsedAuthoritySha256`, `parseReceiptSha256`, and `sourceCaptureReceiptSha256`.
- `PhaseSealEvidenceV2` exact fields: `phase`, `firstPriorSlot`, `lastPriorSlot`,
  `priorSlotRecordDigests`, `priorPhaseRootSha256`, `evidenceMapSha256`,
  `orderedTranscriptRefSha256`, `stabilityProjectionSha256`,
  `fridaBarrierRecordSha256`, `activeOperationCheckpointSha256`, and
  `phaseOutcome=sealed`.

BEFORE requires first/last prior slot 0/10, exactly eleven prior digests,
`priorPhaseRootSha256=null`, and null Frida barrier. AFTER requires 12/22, exactly
eleven prior digests, the external slot-11 digest and exact settled barrier. The
maps and transcript/stability projections contain only these prior payloads;
neither contains slot 11/23, its receipt, or its eventual root. Compute the seal
payload, then its SlotEvidenceEnvelope, then its external slot record digest.
That final external digest is the phase root consumed by later operations. The
snapshot may later list all 24 records without feeding that list back into either
seal. Active checkpoint equality covers prior work only; active count is one.

### Exact snapshot success receipt

`AuthoritySnapshotReceiptV2` is an unsigned body later authenticated by the
service chain. It has these **PROPOSED exact fields**:

| PROPOSED field | Exact requirement |
|---|---|
| `authority` | Proposed success-snapshot authority. |
| `schemaVersion` | Integer `2`. |
| `planCoreSha256` | Exact `P`. |
| `executionBindingSha256` | Exact `E`. |
| `serviceSessionId` | Exact broker session. |
| `authorityLaneBodySha256` | Exact lane body `A`. |
| `brokerSlotCursorStart` | Integer `0`. |
| `brokerSlotCursorEnd` | Integer `24`. |
| `slotRecordDigests` | Exact ordered list of 24 distinct digests for slots 0..23. |
| `beforePhaseRootSha256` | Exact slot-11 phase root. |
| `fridaBarrierRecordSha256` | Exact barrier service record between slots 11 and 12. |
| `fridaPhysicalSettlementEnvelopeSha256` | Exact detached-success physical Frida barrier envelope. |
| `fridaCompositeClosureRecordSha256` | Exact post-lane-close composite record, finalized only with the snapshot receipt. |
| `afterPhaseRootSha256` | Exact slot-23 phase root. |
| `beforeEvidenceMapSha256` | Exact closed evidence map for slots 0..11. |
| `afterEvidenceMapSha256` | Exact closed evidence map for slots 12..23. |
| `orderedTranscriptRefsSha256` | Digest of all slot transcript refs in slot order. |
| `stabilityPolicySha256` | Exact PlanCore policy. |
| `stabilityResultSha256` | Exact passed comparison result, with every compared field enumerated. |
| `authorityLaneClosureRef` | Exact `LaneClosureRefV2` proved-quiescent/success arm, including terminal and detached quiescence digests. |
| `serviceRecordCursor` | Exact next broker-global record ordinal. |
| `outcome` | Proposed token `snapshot-success`. |

The two final-snapshot EvidenceMapV2 objects are formed after their seal records
exist and include those records. They are different objects from the prior-seal
maps committed by PhaseSealEvidenceV2 (0..10 and 12..22 respectively). Their
different mapKind tags, ranges and hashes must not be aliased. Neither seal body
contains its final-snapshot map or its own record digest.

### Exact snapshot failure receipt

Exactly one `AuthoritySnapshotFailureReceiptV2` replaces the success body on any
authority/barrier failure. It has these **PROPOSED exact fields**:
`authority`, `schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`serviceSessionId`, `authorityLaneBodySha256`, `brokerSlotCursorStart=0`,
`brokerSlotCursorAtFailure`, `completedSlotRecordDigests` (an exact prefix only),
`firstFailureLayer`, `firstFailureState`, `firstFailureSlot`,
`firstFailureOperation`, `firstFailureCode`, `firstFailureEvidenceSha256`,
`beforePhaseRootSha256`, `fridaBarrierRecordSha256`,
`fridaPhysicalSettlementEnvelopeSha256`,
`fridaCompositeClosureRecordSha256`, `afterPhaseRootSha256`,
`partialEvidenceMapSha256`, `orderedTranscriptRefsSha256`,
`stabilityPolicySha256`, `stabilityResultSha256` (null unless comparison ran),
`authorityLaneClosureRef`, `serviceRecordCursor`, and
`outcome` (`snapshot-failure` or `snapshot-uncertain`). Nullability is determined
solely by the exact failure cursor for phase, Frida-settlement, transcript, and
stability observations; they cannot be backfilled with later normal-work evidence.
Post-failure closure evidence is different: the Authority `LaneClosureRefV2` and
Frida composite-closure record are mandatory finalization inputs, using exact
failure/uncertain or never-started arms as applicable. The snapshot failure receipt
is created only after those closure inputs exist.

## Device-side retained descriptor guardian

Android file descriptors cannot be inherited into a Windows worker. The adapter
therefore uses a device-side guardian and must never describe the relay as an
inherited/proxy FD.

One guardian instance owns exactly one file FD, or for absent mark exactly one
directory FD/name binding, for the service session. Protected system files use a
separately reviewed exact privileged guardian role. User-document files use the
least credential that can open the exact path. Failure under that credential does
not auto-escalate to root. A privileged role has a fixed path allowlist and syscall
surface and cannot execute a shell, write, create, rename, chmod, chown, mount,
signal arbitrary processes, enumerate directories, or open a caller-selected path.

The supervisor attests guardian image/dependency digest, Android boot ID, PID/start
identity, UID/GID/capabilities/SELinux context, exact role/path-policy digest,
guardian session, and ephemeral stream public key. The Authority Child verifies
that detached attestation. The application requester cannot supply it.

### Child-only stream and same-FD proof

The Authority Child creates an ephemeral stream key pair only after work-gate
admission. The guardian does not accept that public key merely because a relay
supplied it. `ChildStreamKeyAttestationBodyV2` exact fields are
`planCoreSha256`, `executionBindingSha256`, `authorityLaneBodySha256`,
`childProcessIdentity`, `childImageManifestSha256`, `childSessionId`,
`guardianSessionId`, `guardianProcessAttestationSha256`, `guardianChallenge`,
`fileRole`, `phase`, `readEpoch`, `fdAcquisitionReceiptSha256`,
`childStreamPublicKey`, `keyId`, `workGateSha256`, `supervisorObservedNs`,
`operationDeadlineNs`. The supervisor obtains the key from the exact image-pinned
Child bootstrap/owner, signs the body with its E-rooted key, and sends its
`ChildStreamKeyAttestationEnvelopeV2` to the challenge's exact guardian. The
guardian verifies P/E/lane/process/image/session/role/epoch/challenge equality and
consumes it once. The matching supervisor-signed guardian key attestation binds
the Child's fresh challenge and the same acquisition/epoch. Relays cannot attest
either endpoint, select either key, or redirect the stream to Child F.

The fixed proposed crypto profile is X25519, HKDF-SHA256 and ChaCha20-Poly1305,
not a negotiated suite. X25519 keys are exactly 32 bytes, base64-encoded only at
the public attestation boundary; require canonical field-element encoding,
reject low-order/all-zero shared secret in constant time, and reject key reuse
across acquisition/epoch. Private keys never leave their owners. Define
`GuardianKeyContextV2` with exact fields `planCoreSha256`,
`executionBindingSha256`, `authorityLaneBodySha256`, `childKeyAttestationSha256`,
`guardianKeyAttestationSha256`, `guardianSessionId`, `fdAcquisitionReceiptSha256`,
`fileRole`, `phase`, `readEpoch`, `childKeyId`, `guardianKeyId`.
For canonical context bytes K and shared secret Z:

```text
salt = SHA256(LD(D(GuardianKeyContextV2,hkdf-salt), [K]))
prk  = HKDF-Extract-SHA256(salt, Z)
okm  = HKDF-Expand-SHA256(prk,
         LD(D(GuardianKeyContextV2,hkdf-info), [K, utf8("guardian-to-authority")]), 68)
file_key = okm[0:32]; nonce_prefix = okm[32:36]; confirm_key = okm[36:68]
nonce(chunkIndex) = nonce_prefix || u64be(chunkIndex)
```

Direction, FD, role, phase and epoch are all key-separated; nonce indices start
at zero and strictly increase, with no retry on partial writes. The guardian and
Child each send `GuardianKeyConfirmationV2` over their separately authenticated
control route: exact fields `keyContextSha256`, `authorRole`, `challenge`,
`peerChallenge`, `confirmationTag`. The tag is HMAC-SHA256(confirm_key,
LD(D(GuardianKeyConfirmationV2,key-confirmation),[canonical confirmation body
with confirmationTag omitted])). Verify both roles before any file read; wipe Z/prk/
confirm_key after confirmation. Confirmation tag is never encrypted with a data
nonce. A reused nonce/chunk number, wrong role, failed confirmation or timeout
revokes the entire epoch; no resume/rekey-in-place exists.

`GuardianChunkAadV2` has only `planCoreSha256`, `executionBindingSha256`,
`keyContextSha256`, `fdIncarnationSha256`, `fileRole`, `phase`, `readEpoch`,
`chunkIndex`, `offset`, `plaintextLength`, `previousChunkRecordSha256`.
AAD is exactly LD(D(GuardianChunkAadV2,aead-aad),[canonicalAAD]); it contains no
ciphertext hash, tag, nonce hash or future chunk record. Encrypt first, then form
the chunk body/ciphertext hash and external record digest. The wire is exactly
`u32be(aadLen)||AAD_JSON||u32be(ciphertextLen)||ciphertext||tag16`; plaintext
1..65,536 bytes, final chunk may be shorter, aadLen<=4,096, ciphertextLen equals
plaintextLength. One zero-byte file has zero chunks plus the authenticated EOF
terminal, not a zero-length encrypted chunk. Buffer bounds are checked before
allocation. Raw stream frame maximum is 69,656 bytes. The service relays these
bytes unchanged, has no private/shared/derived file key, and sees no plaintext.
This stream is separate from transcript inline/bulk transport.

For a present file, the guardian performs exactly:

1. resolve the sealed path component-by-component with retained directory FDs,
   no-follow semantics, no dot segment, and no reparse/symlink traversal;
2. open once with read-only, close-on-exec, no-follow flags and no create/truncate;
3. capture `FileStatV2` and require regular file, exact UID/GID/mode policy,
   `nlink=1`, `size` within the role bound, and stable path-to-`(dev,ino)` binding;
4. for each phase, call `lseek(fd, 0, SEEK_SET)` and require returned offset `0`;
5. sequentially read/encrypt exact chunks from that same FD; the Child decrypts,
   hashes, and counts without serializing plaintext;
6. require total bytes equals captured `st_size` and the role's expected size;
7. issue one extra read on the same FD and require zero-byte EOF;
8. require `lseek(fd, 0, SEEK_CUR)` equals `st_size`;
9. capture a second `FileStatV2` and require the complete stability policy;
10. after AFTER or first failure, close the exact FD generation, destroy stream
    keys, emit authenticated close/key-destruction receipts, and exit/join.

`FileStatV2` has these **PROPOSED exact fields**:
`device`, `inode`, `mode`, `uid`, `gid`, `nlink`, `size`, `mtimeNs`, `ctimeNs`,
`blocks`, `blockSize`, and `statSerializationVersion`. All are canonical decimal
strings except the fixed serialization version; values are range-checked signed or
unsigned 64-bit according to the frozen platform profile. BEFORE/AFTER stability
must enumerate which timestamp fields may change; the current design admits no
silent timestamp exception.

`FileUriBindingV2` has these **PROPOSED exact fields**:
`canonicalUriUtf8`, `canonicalUriSha256`, `scheme=file`, `authorityEmpty=true`,
`queryAbsent=true`, `fragmentAbsent=true`, `decodedAbsolutePathUtf8`,
`decodedPathSha256`, `pathResolutionReceiptSha256`, `descriptorDevice`, and
`descriptorInode`. UTF-8 serialization is exact NFC with uppercase percent-hex
normalization policy frozen before implementation. Encoded separators, NUL,
relative paths, dot segments, authority, query, fragment, and path/FD mismatch
fail before streaming.

For absent mark, the guardian retains the exact parent directory FD, validates the
sealed basename, performs no-follow name lookup before and after the Frida barrier,
and binds directory stat/change evidence and lookup sequence. It never returns a
synthetic zero-byte file.

`GuardianFdIncarnationV2` has these **PROPOSED exact fields**:
`guardianSessionId`, `guardianProcessIdentitySha256`, `ownerPid`,
`ownerProcessStartId`, `fdNumber`, `fdGeneration`, `fdAcquisitionReceiptSha256`,
`openFlags`, `pathResolutionReceiptSha256`, `device`, `inode`, `fileType`, and
`initialOffset`. The FD number is process-local; every seek/stat/read/EOF/close
receipt binds this full incarnation and a strictly increasing syscall sequence.

Before `open`, the guardian publishes `GuardianFdReservationBodyV2` with exact
fields `planCoreSha256`, `executionBindingSha256`, `guardianSessionId`,
`guardianProcessIdentitySha256`, `fileRole`, `acquisitionId`, `fdGeneration`,
`pathResolutionReceiptSha256`, `openFlags`, `challenge`, `state=reserved`.
This reservation has no FD number, stat, key-context or GuardianOpen reference.
After the syscall, `GuardianFdAcquisitionBodyV2` has exact fields
`planCoreSha256`, `executionBindingSha256`, `reservationReceiptSha256`,
`guardianSessionId`, `acquisitionId`, `fdNumber`,
`fdGeneration`, `openFlags`, `initialStat`, `initialOffset`, `syscallSequence`,
`acquisitionOutcome`. This is the live acquisition result, not a final closure
state. open-retained requires fdNumber, fdGeneration, openFlags, initialStat and
initialOffset to be present and exact; open-failed requires fdNumber/initialStat/
initialOffset null and a proved failed syscall; open-uncertain preserves only
independently observed fields and authorizes no read/close by guessed descriptor.
fdGeneration remains the pre-reserved generation in all arms. The enclosing
authenticated owner observation supplies the exact syscall failure/uncertainty.
Its external signed receipt digest is `fdAcquisitionReceiptSha256`. Only now form
`GuardianFdIncarnationV2`; only later form key attestations and GuardianOpen.
No acquisition receipt contains its later incarnation or GuardianOpen digest.
The reserved token survives an open-result publication crash; recovery does not
invent a descriptor number or retry open.

The exact PROPOSED guardian bodies are:

- `GuardianOpenBodyV2`: `authority`, `schemaVersion`, `planCoreSha256`,
  `executionBindingSha256`, `guardianSessionId`, `fileRole`,
  `guardianProcessAttestationSha256`, `guardianRolePolicySha256`,
  `filePolicySha256`, `fileUriBinding` (nonnull only for original PDF),
  `fdIncarnation`, `openStat`, `expectedByteLength`, `childStreamPublicKey`,
  `guardianStreamPublicKey`, `keyAgreementBindingSha256`,
  `readEpochInitial=0`, `capturedDeviceBoottimeMs`, and `outcome=open`;
- `GuardianStreamChunkBodyV2`: `authority`, `schemaVersion`,
  `planCoreSha256`, `executionBindingSha256`, `guardianSessionId`, `fileRole`,
  `phase`, `readEpoch`, `fdIncarnationSha256`, `syscallSequence`, `chunkIndex`,
  `offset`, `plaintextLength`, `ciphertextLength`, `aeadNonce`, `aeadAadSha256`,
  `ciphertextSha256`, `previousChunkRecordSha256`, and `final=false`; ciphertext
  and AEAD tag are detached binary payload and never serialized as evidence;
- `GuardianReadEpochTerminalBodyV2`: `authority`, `schemaVersion`,
  `planCoreSha256`, `executionBindingSha256`, `guardianSessionId`, `fileRole`,
  `phase`, `readEpoch`, `fdIncarnationSha256`, `seekSetReceiptSha256`,
  `statBefore`, `totalBytes`, `chunkCount`, `plaintextSha256`,
  `firstChunkRecordSha256`, `finalChunkRecordSha256`, `zeroByteEofReceiptSha256`,
  `finalOffsetReceiptSha256`, `statAfter`, `pathToFdRevalidationReceiptSha256`,
  `childDecryptCountHashReceiptSha256`, `streamHalfCloseReceiptSha256`,
  `streamEofReceiptSha256`, `previousReadEpochTerminalSha256`,
  `sameFd=true`, `terminal=true`, and `outcome`;
- `GuardianAbsenceBodyV2`: `authority`, `schemaVersion`, `planCoreSha256`,
  `executionBindingSha256`, `guardianSessionId`, `fileRole=mark`, `phase`,
  `directoryFdIncarnation`, `sealedBasenameUtf8Sha256`, `lookupSequence`,
  `lookupReceiptSha256`, `directoryStat`, `present=false`,
  `previousAbsenceBodySha256`, and `outcome=absent`; and
- `GuardianCloseBodyV2`: `authority`, `schemaVersion`, `planCoreSha256`,
  `executionBindingSha256`, `guardianSessionId`, `fileRole`,
  `fdOrDirectoryIncarnationSha256`, `lastReadOrAbsenceReceiptSha256`,
  `fdCloseReceiptSha256`, `allReadEpochKeysDestroyedReceiptSha256`,
  `guardianPrivateKeyDestroyedReceiptSha256`, `deviceSendEndpointCloseSha256`,
  `exitIntentReceiptSha256`, `firstFailure`, `closeOutcome`, and `terminal=true`.

The trusted supervisor, not the guardian, constructs
`GuardianProcessClosureReceiptV2` after the close body. Its **PROPOSED exact
fields** are `planCoreSha256`, `executionBindingSha256`, `guardianSessionId`,
`guardianProcessIdentitySha256`, `guardianCloseBodySha256`,
`deviceTransportEofReceiptSha256`, `processJoinReceiptSha256`,
`remainingHandleCloseSetSha256`, `stagingDeletionReceiptSha256`, and `outcome`.
Thus the guardian never attests its own later join.

Every PlanCore guardian role has one GuardianClosureRefV2 even if service terminal
is missing. Its sole exact field set and six closed acquisition arms are in
Closed guardian transport below; the old three-arm interpretation is forbidden.
Supervisor closure commits all role refs. Cancel, authenticated EOF or original
Android BOOTTIME lease expiry seals reads and drives key/FD close/self-exit.
Windows job-empty never proves guardian process/FD/transport closure.

Each read epoch uses one one-way end-to-end encrypted logical stream over two
one-shot outer transport hops: guardian owns the device-send endpoint and the
service owns its receive endpoint; the service owns a distinct host-relay send
endpoint and Authority Child owns its receive endpoint. The service must forward
the exact inner header/ciphertext/tag bytes unchanged. Each outer hop has its own
key/endpoint binding and half-close/EOF/close receipts, while the guardian/Child
inner AEAD key is unknown to the service. A new phase uses a new read epoch, inner
key, nonces, and both one-shot endpoint pairs but the same retained FD incarnation.
Endpoint owner, direction, duplicate lineage, key destruction, EOF, close, and
process crash are committed in the read terminal or closure receipt.

No plaintext file byte may enter a transcript spool, service memory, supervisor
memory, control/inline/bulk frame, receipt, exception, log, or crash diagnostic.

### Closed guardian transport, controls and failure arms

The file stream is NOT transcript bulk transport. It has two outer hops:
G_DEVICE_TO_SERVICE (Android guardian sender, Windows service receiver) and
SERVICE_TO_AUTHORITY (Windows service sender, Authority Child receiver).
Only guardian and Child possess inner X25519/AEAD keys. Outer hop owners receive
distinct 32-byte authenticated transport masters through their already-pinned
supervisor/guardian bootstrap channels. Four transcript namespaces remain separate;
a transcript takes one of the two Child branches then service→supervisor→verifier
(three physical transfers), whereas this file stream has exactly two relay hops.

GuardianHopBindingV2 exact fields: planCoreSha256, executionBindingSha256,
guardianTransportBindingSha256, guardianSessionId, fileRole, phase, readEpoch,
hopNamespace, senderIdentitySha256, receiverIdentitySha256,
sendEndpointIdentitySha256, receiveEndpointIdentitySha256,
offerReceiptSha256, acceptReceiptSha256, creatorAliasCloseReceiptSha256,
controlBindingSha256, masterKeyId, generation.
The exact offer/duplicate-retention ACK/creator-alias-close/first-write-grant
procedure is the transcript endpoint procedure, using this distinct file-hop
binding/schema/domain and no transcript index. All offer/grant controls directly
bind P/E, guardian session/role/phase/epoch; there is one stream per binding.
The source master is independently pinned before this binding exists; it does not
derive from its own key ID. HKDF-SHA256 salt is
SHA256(LD(D(GuardianHopBindingV2,hkdf-salt),[raw(P),raw(E),canonicalBinding])).
HKDF info is LD(D(GuardianHopBindingV2,hkdf-info),
[canonicalBinding,utf8(purpose)]), producing 32 bytes separately for literal
file-payload, file-ack-control, file-terminal. Direction and generation are in the
binding; key IDs hash [utf8(purpose),raw(key)] in its key-id domain.
No transcript master, inner AEAD key or different file epoch may substitute.

GuardianControlBodyV2 exact fields: planCoreSha256, executionBindingSha256,
guardianSessionId, fileRole, phase, readEpoch, hopBindingSha256,
controlSequence, previousControlRecordSha256, kind, payloadSchema,
payloadSha256, payloadByteLength, absoluteDeviceExpiryMs, hostOperationDeadlineNs.
Kind is exactly the closed Guardian pre-binding control dispatch table below;
child/guardian attestations and stream acceptance have distinct kind/schema tags. Payload is separately length/hash/
schema-checked canonical bytes, 1..65536, and kind fixes its sole schema.
The first three kinds travel through the pinned supervisor/guardian bootstrap
control channel until both confirmations exist; they cannot authenticate themselves
using an unconfirmed derived key. After confirmations, file-ack-control authenticates
the ordered control channel. Neither transition resets its sequence/predecessor.
GuardianControlEnvelopeV2 fields: P/E, guardianSessionId, hopBindingSha256,
controlSequence, keyId, bodySchema=GuardianControlBodyV2, bodyByteLength,
bodySha256, tag. tag is canonical base64 of 32 HMAC bytes over
LD(D(GuardianControlEnvelopeV2,mac),[canonical header without tag, raw_body]).
Genesis is SHA256(LD(D(GuardianControlBodyV2,genesis),
[raw(P),raw(E),raw(streamReservationSha256),utf8(direction),utf8(controlClass)])); later predecessor hashes the complete prior
canonical body under D(GuardianControlBodyV2,record-hash).
Partial/replayed/out-of-order controls, wrong purpose or any normal-ingress record
after cancel are terminal uncertainty. A separate terminalization class permits
only EOF/ACK/close after normal ingress seals.

Inner chunk AAD and its previous-record chain are exact:
inner genesis = SHA256(LD(D(GuardianStreamChunkBodyV2,genesis),
[raw(P),raw(E),raw(keyContextSha256),raw(fdIncarnationSha256),
utf8(phase),u64be(readEpoch)])).
For each 1..65536-byte plaintext chunk, canonical GuardianChunkAadV2 binds that
predecessor. Build exact 12-byte nonce (four derived prefix bytes + u64be(index)).
aeadNonce on wire is canonical padded base64 of those 12 bytes (exactly 16 chars);
confirmationTag is canonical padded base64 of 32 HMAC bytes (exactly 44 chars).
Compute innerFrame as the previously defined AAD_JSON/ciphertext/tag16 frame.
inner record hash = SHA256(LD(D(GuardianStreamChunkBodyV2,record-hash),
[canonical GuardianStreamChunkBodyV2, raw innerFrame])).
The chunk body's ciphertext/AAD hashes follow encryption and do not occur in AAD;
the nonce field must equal the derived value, not choose a nonce.
The service relays byte-for-byte; the Child verifies body/AAD/nonce/record/AEAD
before hashing plaintext, wipes the fixed plaintext buffer, and never publishes it.

GuardianRelayHeaderV2 exact fields: planCoreSha256, executionBindingSha256,
hopBindingSha256, keyId, guardianSessionId, fileRole, phase, readEpoch,
frameOrdinal, innerChunkIndex, innerFrameByteLength, innerFrameSha256,
previousRelayRecordSha256, hostOperationDeadlineNs.
A relay frame is u32be(headerLen)||header||u32be(innerLen)||innerFrame||tag32.
headerLen<=4096; innerLen in 1..69656; max frame = 8+4096+69656+32 = 73792.
tag32=HMAC(file-payload,LD(D(GuardianRelayHeaderV2,frame-mac),
[canonicalHeader,innerFrame])). Relay record hash uses the same two parts under
D(GuardianRelayHeaderV2,record-hash), excluding external tag/hash. Genesis uses
[raw(P),raw(E),raw(hopBindingSha256)] under D(GuardianRelayHeaderV2,genesis).
Ordinal/index start 0, exact next; at most 16384 file chunks for the 1GiB role
bound. Offset is plaintext index*65536, checked before multiply/add.
The receiver authenticates outer frame, exact inner hash and previous chain before
forwarding. File streams cannot enter transcript spools/control-body payloads.

Each hop follows offer→ACK→alias close→grant→all relay frames→sender half-close
→receiver exact EOF/drain/hash/count/data-close/payload-key-destruction
→GuardianHopSettlementAckV2→sender ACK verification/payload-key destruction/send-close
→GuardianHopTerminalBodyV2 under the separate file-terminal key→receiver validation.
GuardianHopSettlementAckV2 fields: P/E, hopBindingSha256, guardianSessionId,
phase, readEpoch, frameCount, totalInnerBytes, finalRelayRecordSha256,
receiverEofReceiptSha256, receiverDataCloseReceiptSha256,
receiverPayloadKeyDestroyedReceiptSha256, receiverValidationReceiptSha256.
It is wrapped in the authenticated GuardianControl envelope's eof-ack kind.
GuardianHopTerminalBodyV2 fields: P/E, hopBindingSha256, guardianSessionId,
phase, readEpoch, keyContextSha256, childConfirmationSha256,
guardianConfirmationSha256, frameCount, totalInnerBytes, finalRelayRecordSha256,
settlementAckEnvelopeSha256, senderHalfCloseReceiptSha256,
senderPayloadKeyDestroyedReceiptSha256, senderDataCloseReceiptSha256,
acquisitionSnapshotRef, outcome, terminal=true.
GuardianHopTerminalEnvelopeV2 fields: P/E, hopBindingSha256,
bodySchema=GuardianHopTerminalBodyV2, bodyByteLength, bodySha256,
keyId, algorithm=HMAC-SHA256, tag.
MAC input is [raw(P),raw(E),raw(hopBindingSha256),utf8(keyId),
raw(bodySha256),u64be(bodyByteLength),raw_body] under its mac domain.
Control/ACK/terminal keys and their output handles remain named emitter slots;
the next retained observer proves their later destruction/EOF/close. No hop
terminal certifies its own final control-key destruction.

GuardianReadEpochTerminalBodyV2 additionally binds keyContextSha256,
childConfirmationSha256, guardianConfirmationSha256, deviceHopTerminalEnvelopeSha256,
relayHopTerminalEnvelopeSha256. For a zero-byte present file: totalBytes=0,
chunkCount=0, firstChunkRecordSha256=null, finalChunkRecordSha256=null,
plaintextSha256=SHA256(empty). Both key confirmations, same-FD seek/stat/EOF checks,
and both zero-frame hop settlements remain mandatory. A zero-frame hop has
frameCount=0,totalInnerBytes=0,finalRelayRecordSha256=null, not a fabricated chunk.
For nonzero files both chunk digests and final relay digest are required.
No zero-byte rule applies to transcripts or DetachedPayloadV2.

GuardianClosureRefV2.kind is normal/never-started/started-not-acquired/
open-failed/open-uncertain/missing-crashed.
Never-started requires proved no guardian process. Started-not-acquired requires
an actual guardian identity, proved no file/directory acquisition, independent
process/control closure and no open/read body. Open-failed requires the exact
failed syscall acquisition receipt plus independent guardian/process closure;
it has no FD incarnation or read terminal. Open-uncertain preserves its pending
reservation/partial identity in a snapshot and never authorizes a guessed close.
Missing-crashed preserves every known prefix and independent missing-layer proof.
Only normal with exact FD/read/close/hop/process closure is success for a used file.
All six arms contain acquisitionSnapshotRef, guardianAcquisitionState,
fdAcquisitionReceiptSha256?, guardianCloseBodySha256?,
supervisorProcessClosureReceiptSha256?, missingLayerReceiptSha256?, outcome.
Every uncertain arm is recovery-required even if Windows job becomes empty.
Fault before/after every key/FD/offer/payload/half-close/ACK/terminal/close step
burns that epoch; no retry, re-open, nonce reset, raw fallback or implicit success.

## `frida_worker-v2` one physical composite

Before physical attach, `PreAttachSelectorCommitV2` binds only the E-rooted target
policy, exact target/server identities and observer digest. It is not the later
logical attach receipt. After physical attach and fresh selector observation,
`LogicalAttachBindingV2` has exact fields `planCoreSha256`,
`executionBindingSha256`, `fridaLaneBodySha256`, `serial`, `package`, `component`,
`pid`, `processStartId`, `uid`, `fridaServerSessionId`, `observerSourceSha256`,
`targetPolicySha256`, `logicalAttachNonce`, `physicalAttachReceiptSha256`,
`freshSelectorAttestationSha256`, `selectorChallenge`, `physicalOperationId`,
`loadOperationId`, `loadSourceByteLength`, `loadSourceSha256`,
`stepCursorBeforeLoad`, `previousPhysicalStepReceiptSha256`,
`supervisorObservedNs`, `operationDeadlineNs`. It exists strictly after E,
physical attach and selector proof. The E-rooted supervisor signs its exact body
as `LogicalAttachBindingEnvelopeV2`; the Child verifies this before load under the
same operation lock and cursor. `loadSourceSha256=observerSourceSha256`; the
source byte length is pinned, loadOperationId is reserved once, and previous step
is exactly the selector-fresh receipt. No API call/callback/selector refresh may
advance the Frida cursor between validation and the exact load dispatch. The
load receipt references this binding's external digest; the binding never names
its future load receipt. On sign/delivery/freshness/cursor/handle/deadline failure,
only conditional teardown is permitted. The later logical facade consumes this
authenticated binding and cannot construct or substitute one itself.

The one proposed factory operation follows layer-prefixed physical states:

```text
FRIDA_PHYS_ADMITTED
  -> FRIDA_PHYS_PREBOUND
  -> FRIDA_PHYS_ATTACHING
  -> FRIDA_PHYS_ATTACHED
  -> FRIDA_PHYS_SELECTOR_CHALLENGED
  -> FRIDA_PHYS_SELECTOR_FRESH
  -> FRIDA_PHYS_SCRIPT_LOADED
  -> FRIDA_PHYS_CALLBACKS_OPEN
  -> FRIDA_PHYS_CALLBACKS_SEALED
  -> FRIDA_PHYS_SCRIPT_UNLOADED
  -> FRIDA_PHYS_DETACHED
  -> FRIDA_PHYS_QUIESCENT
  -> FRIDA_PHYS_SETTLED_SUCCESS

first error -> FRIDA_PHYS_FAILING
            -> callback fence -> conditional exact unload -> conditional exact detach
            -> FRIDA_PHYS_SETTLED_FAILURE | FRIDA_PHYS_SETTLED_UNCERTAIN
```

After physical attach and immediately before script load, the Child issues a fresh
challenge to the supervisor selector oracle through a dedicated end-to-end
authenticated evidence path relayed by the service. The detached
`SelectorSubjectV2` binds the physical-attach receipt. The Child validates the
supervisor trust chain, capture sequence/time, exact selector equality, target and
Frida-server liveness, and deadline. No caller-selected selector or cached
pre-attach proof is accepted. No intervening Frida operation is allowed between
fresh proof validation and load.

Success callback grammar is exactly one complete snapshot then one success
terminal. Observer failure grammar is exactly one fixed-code failure then one
failure terminal. Missing, partial, duplicate, extra, reordered, oversized, late,
or post-terminal callbacks fail. Callback record digests form the Frida step chain.
Callback failure is distinguished as physical observer failure, transport failure,
or later requester-local callback-delivery failure.

`FridaPhysicalStepReceiptV2` has these **PROPOSED exact fields**:
`authority`, `schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`fridaLaneBodySha256`, `physicalOperationId`, `stepCursorBefore`,
`stepCursorAfter`, `stepToken`, `stateBefore`, `stateAfter`,
`previousStepReceiptSha256`, `startedMonotonicNs`, `completedMonotonicNs`,
`resultBindingSha256`, `outcome`, and `firstFailure`. Cursor starts at `0` and each
attempted step or cleanup disposition advances exactly once. The receipt digest is
external and chained by the next receipt. `FridaStepDispositionV2` has exact fields
`ordinal`, `stepToken`, `disposition`, and `stepReceiptSha256`; the composite holds
exactly seven ordered entries for `physical-attach`, `selector-fresh`,
`script-load`, `callbacks-seal`, `script-unload`, `physical-detach`, and
`operation-quiescence`. Success requires seven `completed` arms. Failure requires a
completed prefix, exactly one first `failed` arm, then only `not-reached`,
`cleanup-completed`, `cleanup-failed`, or `cleanup-not-required` arms justified by
the retained-resource state. Every non-`not-reached`/non-`cleanup-not-required` arm
has a receipt digest; those two arms require it null.

`FridaCallbackRecordV2` has these **PROPOSED exact fields**: `authority`,
`schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`fridaLaneBodySha256`, `physicalOperationId`, `callbackOrdinal`, `callbackKind`,
`callbackTranscriptRef`, `observerResultCode`, `previousCallbackRecordSha256`,
`capturedMonotonicNs`, and `terminal`. Success is exactly ordinal 0
`snapshot`/nonterminal then ordinal 1 `success-terminal`/terminal. Physical
observer failure is exactly ordinal 0 `failure`/nonterminal then ordinal 1
`failure-terminal`/terminal. Transport failure before a complete authenticated
record has no invented callback record and is bound by the physical step failure.
The callback genesis and every external record digest use the PROPOSED callback
record domain; the ordered list and final root are both committed.

`FridaPhysicalSettlementBodyV2` is the unsigned barrier body with these
**PROPOSED exact fields**:
`authority`, `schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`serviceSessionId`, `fridaLaneBodySha256`, `logicalAttachBindingSha256`,
`initialSelectorSha256`, `physicalAttachReceiptSha256`,
`freshSelectorAttestationSha256`, `scriptLoadReceiptSha256`,
`observerSourceSha256`, `callbackTranscriptRef`, `callbackCount`,
`callbackRecordDigests`, `callbackChainRootSha256`,
`callbackSealReceiptSha256`, `scriptUnloadReceiptSha256`,
`physicalDetachReceiptSha256`, `operationLocalQuiescenceReceiptSha256`,
`physicalStepDispositions`, `physicalStepReceiptDigests`,
`physicalStepCursorStart=0`, `physicalStepCursorEnd`,
`callbackCursorStart=0`, `callbackCursorEnd`, `physicalStepChainRootSha256`,
`firstFailure` (null on success), `completedBeforeOperationDeadline`, and
`physicalOutcome` (`detached-success`, `detached-failure`, or
`cleanup-uncertain`). The detached, lane-authenticated
`FridaPhysicalSettlementEnvelopeV2` has these **PROPOSED exact fields**:
`authority`, `schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`fridaLaneBodySha256`, `bodySchema`, `bodyByteLength`, `bodySha256`, `laneMacAlgorithm`, `laneKeyId`, and
`laneMac`. The exact MAC input is
`LD(D(FridaPhysicalSettlementEnvelopeV2,mac), [raw(P), raw(E),
raw(bodySha256), u64be(byteLength(body)), body])`; body and envelope digests are
external. The service validates it and creates
`FridaBarrierRecordV2` with these **PROPOSED exact fields**: `authority`,
`schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`globalRecordOrdinal`, `previousServiceRecordSha256`, `beforePhaseRootSha256`,
`fridaPhysicalSettlementEnvelopeSha256`, `physicalOutcome`,
`acceptedMonotonicNs`, and `terminal=true`. The barrier-record digest, committed by
the later signed service root, is the authority for slot 12. Neither object can
claim lane terminality or lane quiescence.

After the Frida lane emits its one terminal and detached quiescence envelope, the
service constructs `FridaCompositeReceiptV2` with these **PROPOSED exact fields**:
`authority`, `schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`serviceSessionId`, `fridaLaneBodySha256`,
`fridaPhysicalSettlementEnvelopeSha256`, `fridaPhysicalOutcome`,
`fridaLaneClosureRef`, `firstFailure`, `completedBeforeOperationDeadline`, and
`compositeClosureOutcome` (`closed-success`, `closed-failure`, or
`closed-uncertain`). Its canonical body digest is wrapped as an exact
service-global record; that record digest is
`fridaCompositeClosureRecordSha256`. It is created only after lane closure and
therefore is never used to authorize slot 12.

The physical-settlement digest is nonnull exactly when a complete lane-MAC-valid
settlement envelope exists. A never-started closure requires it null,
`fridaPhysicalOutcome=never-started`, nonnull first failure, and
`completedBeforeOperationDeadline=false`. A started lane that crashes before a
complete settlement uses the missing-crashed or terminal-unquiesced closure arm,
null physical-settlement digest, and a nonnull first failure; no partial envelope
digest is substituted.

No session/script/callback object crosses the physical operation boundary.

## Transcript inline/bulk topology

File streams are excluded from this section. Transcript kinds are limited to
activity/display/window source bytes, observer callbacks, and fixed bounded
diagnostics.

### Exact carrier partition

- Canonical transcript length `1..65536`: one authenticated inline detached-body
  frame; bulk is forbidden.
- Canonical transcript length `65537..4194304`: authenticated bulk frames; inline
  is forbidden.
- Length `0` or `>4194304`: fail.
- Maximum 16 transcript objects and 16,777,216 aggregate canonical transcript
  bytes per service plan.

Normal slot/orchestration control bodies contain only `TranscriptRefV2`; they never
embed transcript bytes or chunks. A dedicated inline-carrier frame may carry the
detached <=64 KiB canonical bytes whose digest is in the reference.

### Every hop, owner, key, and endpoint

All names below are PROPOSED. Each row is a session-scoped one-way endpoint
factory, not one reusable byte stream. For every transcript object, the receiver
creates a fresh one-shot endpoint pair, retains the receive endpoint, transfers
only the noninheritable send endpoint to the named sender, and records both full
`WindowsObjectIdentityV2` values in `DataEndpointBindingV2`. The sender owns that
send endpoint until half-close; the receiver owns the receive endpoint until EOF,
validation, and close. A per-object direction key is HKDF-derived from the row's
distinct hop master key, `P`, `E`, hop namespace, transcript index/ID, endpoint
binding digest, and key generation. No key or endpoint is reused for another
object. Acknowledgement uses the row's separate authenticated control path.

| Hop namespace | Sender/owner | Receiver/owner | Direction/key/closure |
|---|---|---|---|
| `AUTH_CHILD_TO_SERVICE` | Authority Child owns each transferred one-shot send endpoint. | Service Authority Parent creates/owns its paired receive endpoint. | Authority hop-master -> independent per-object key; Child half-close/key-destroy/send-close plus service EOF/receive-close receipts. |
| `FRIDA_CHILD_TO_SERVICE` | Frida Child owns each transferred one-shot send endpoint. | Service Frida Parent creates/owns its paired receive endpoint. | Frida hop-master -> independent per-object key; Child half-close/key-destroy/send-close plus service EOF/receive-close receipts. |
| `SERVICE_TO_SUPERVISOR` | Service owns each transferred one-shot send endpoint. | Supervisor creates/owns its paired receive endpoint. | Service-output hop-master -> independent per-object key; service half-close/key-destroy/send-close plus supervisor EOF/receive-close receipts. |
| `SUPERVISOR_TO_VERIFIER` | Supervisor owns each transferred one-shot send endpoint. | Settlement verifier creates/owns its paired receive endpoint. | Supervisor-output hop-master -> independent per-object key; supervisor half-close/key-destroy/send-close plus verifier EOF/receive-close receipts. |

These are four distinct hop namespaces, not four serial transfers of one object.
The exact path is `[AUTH_CHILD_TO_SERVICE,SERVICE_TO_SUPERVISOR,SUPERVISOR_TO_VERIFIER]`
or `[FRIDA_CHILD_TO_SERVICE,SERVICE_TO_SUPERVISOR,SUPERVISOR_TO_VERIFIER]`, selected
by the source lane. The test matrix covers all four namespace rows and both exact
three-transfer chains; no fictitious extra process/hop is inferred.

No endpoint is bidirectional, reused by another transcript, shared between rows,
inherited by an unintended process, or kept open by a third party. Endpoint
transfer is an explicit reduced-rights duplicate whose source/destination lineage
is in `DataEndpointBindingV2`; the creator closes its temporary send duplicate
before its authenticated first-write grant. Dynamic creation occurs after E and
does not suspend/resume an already-running sender. At each forwarding hop the receiver fully
authenticates and canonical-validates the source object into a bounded
session-scoped spool, then re-emits under the next hop's key/record chain. The
canonical transcript digest and transcript index remain stable; hop record digests
change. Spool identity, size, digest, seal, close, and deletion are in cleanup.

### Endpoint offer, ownership acknowledgement, and two-party settlement

Before creation the service reserves `(P,E,transcriptIndex,transcriptId,kind,source)`
in `TranscriptReservationV2`. Its exact fields are `planCoreSha256`,
`executionBindingSha256`, `transcriptIndex`, `transcriptId`, `transcriptKind`,
`sourceLane`, `reservationNonce`, `state=reserved`. Index allocation is one-shot
and monotonic before any endpoint/key/spool syscall. `TranscriptAbandonmentV2`
binds the reservation digest, first failure and complete acquisition-state vector;
it consumes that index forever. No later normal object follows a failed transfer.

For each row, the receiver reserves/acquires the pair, authenticates source and
destination process/job/generation, duplicates only send rights into the sender,
and sends `EndpointOfferV2` over the E-bound control path. Its exact fields are
`planCoreSha256`, `executionBindingSha256`, `hopFactoryBindingSha256`,
`reservationSha256`, `transferId`, `offerNonce`, `sendAcquisitionReceiptSha256`,
`receiveAcquisitionReceiptSha256`, `duplicateReceiptSha256`,
`senderProcessIdentity`, `receiverProcessIdentity`, `direction=send-only`.
`EndpointAcceptV2` exact fields are offer digest, transfer ID, sender identity,
retained duplicate identity digest, offer nonce and `accepted=true`. The sender
checks its exact reduced-rights noninheritable handle before this ACK; it cannot
write yet. Receiver then closes its source send alias and verifies no leaked alias.

`DataEndpointBindingV2` exact fields are `planCoreSha256`,
`executionBindingSha256`, `hopFactoryBindingSha256`, `hopNamespace`,
`reservationSha256`, `transferId`, `senderIdentity`, `receiverIdentity`,
`sendEndpointIdentity`, `receiveEndpointIdentity`, `offerReceiptSha256`,
`acceptReceiptSha256`, `creatorSendAliasCloseReceiptSha256`,
`duplicateLineageRootSha256`, `direction=send-only`, `keyGeneration`.
It references prior acquisition/offer/ACK/close receipts, never its own hash.
Receiver authenticates `EndpointFirstWriteGrantV2` containing binding digest,
transfer ID, offer/accept digests and `grantOrdinal=0`. Sender validates this and
its handle again immediately before its first write. Missing/partial ACK, alias
uncertainty or grant loss never permits payload; the reservation becomes abandoned.

Derive three disjoint per-object keys from the E-bound hop master with
HKDF-SHA256 salt `SHA256(LD(D(DataEndpointBindingV2,hkdf-salt),[raw(P),raw(E),canonicalBinding]))`
and info `LD(D(DataEndpointBindingV2,hkdf-info),[canonicalBinding,utf8(purpose)])`,
where purpose is exactly `payload|settlement-ack|terminal`. Each output is 32
bytes. Hop master stays in the owners until all its object keys are settled;
it is never a file-stream key. Terminal/ACK keys are not destroyed at payload EOF.

Both carrier modes use this exact two-party order:

```text
reserved -> offer -> duplicate-retained ACK -> alias closed -> first-write grant
 -> sender payload -> sender half-close
 -> receiver exact EOF/count/hash/canonical validation -> receiver data close
 -> receiver authenticated SettlementAckV2
 -> sender verifies ACK -> destroys payload direction key -> closes send handle
 -> sender terminal envelope (using separate terminal key)
 -> receiver validates terminal -> immutable hop reference/forwarding permitted
```

`SettlementAckV2` exact fields: `planCoreSha256`, `executionBindingSha256`,
`dataEndpointBindingSha256`, `transferId`, `ackOrdinal=0`, `carrier`,
`transcriptSha256`, `totalBytes`, `finalPayloadRecordSha256`,
`senderHalfCloseReceiptSha256`, `receiverEofReceiptSha256`,
`receiverEndpointCloseReceiptSha256`, `receiverCanonicalValidationSha256`,
`receiverPayloadKeyDestructionReceiptSha256`.
Receiver-authored ACK is authenticated only by the exact
SettlementAckEnvelopeV2 definition below; its tag is not inside SettlementAckV2. Sender cannot claim receiver EOF from its own half-close.
The sender-authored terminal body names this exact ACK digest plus its subsequent
payload-key destruction and send-close receipts. Its envelope uses the distinct
terminal key; signing with the already-destroyed payload key is forbidden.
Receiver verifies that envelope before reference publication. Terminal/ACK keys,
hop master and control endpoints are then closed under the owner ledger; their
post-envelope closure is proved by the next observer layer, never inside their
own last authenticated envelope. ACK/terminal replay, late data, EOF without exact
payload, read/write hang, peer crash or uncertainty selects abort/uncertain states,
never reference success. Abort drains no unbounded input and returns by cleanup
deadline with durable exact unresolved acquisitions.

`InlineTerminalEnvelopeV2` and `BulkManifestEnvelopeV2` are distinct schema/domain
instances of the fixed MAC-envelope codec: P, E, raw body length/digest, author
identity/key ID, binding digest and tag; no inline JSON body interpolation. Their
bodies add `settlementAckSha256` to their listed closure fields. Their `author`
is the row's sender. `TranscriptHopClosureV2` records the route entry, terminal
digest, both endpoint states, payload/ACK/terminal/master key acquisition states,
spool state and independent observer receipt. A spool is exact retained encrypted
storage (1..4,194,304 plaintext bytes, aggregate<=16,777,216), never a caller path;
seal before read, authenticate exact file identity/length/hash, then close/delete
its exact generation. In-memory spools have equivalent bounded acquisition states.

### ACK-control authority and exact settlement envelopes

AckControlFactoryBindingV2 is pre-E/P-only and precedes HopFactoryBindingV2:
planCoreSha256,factoryId,senderProcessIdentitySha256,receiverProcessIdentitySha256,
senderControlSendIdentitySha256,receiverControlReceiveIdentitySha256,
receiverControlSendIdentitySha256,senderControlReceiveIdentitySha256,
masterKeyId,generation,endpointPolicySha256.
The supervisor creates/duplicates both directions, verifies exact reduced rights,
noninheritance and no extra writer aliases, and owns the closing ledger. This
bootstrap factory is not a data endpoint and has no future E. The HopFactory
ackControlBindingSha256 field names this factory, not the post-E binding.

AckControlBindingV2 is post-E:
planCoreSha256,executionBindingSha256,ackControlFactoryBindingSha256,
hopFactoryBindingSha256,senderProcessIdentitySha256,receiverProcessIdentitySha256,
generation,normalSequenceInitial=0,terminalSequenceInitial=0.
No derived key ID occurs inside the binding. Derive disjoint sender-control and
receiver-control 32-byte keys from the factory's pre-attested master, with salt
SHA256(LD(D(AckControlBindingV2,hkdf-salt),[raw(P),raw(E),canonicalBinding]))
and info LD(D(AckControlBindingV2,hkdf-info),
[canonicalBinding,utf8(direction)]). Key IDs use this type's key-id domain over
[utf8(direction),raw(key)]. Both keys and endpoint aliases remain retained by their
two exact owners, never the untrusted requester. Public key IDs are not secret MACs.

AckControlEnvelopeV2 exact metadata: P,E,ackControlBindingSha256,direction,
sequenceClass,messageSequence,previousEnvelopeSha256,kind,
bodySchema,bodyByteLength,bodySha256,keyId,tag.
Direction is sender-control or receiver-control; sequenceClass is normal or
terminalization, each with exact-next sequence starting 0. kind/bodySchema are:
offer/EndpointOfferV2,accept/EndpointAcceptV2,grant/EndpointFirstWriteGrantV2,
settlement/SettlementAckEnvelopeV2,carrier-terminal/InlineTerminalEnvelopeV2 or
BulkManifestEnvelopeV2,close/AckControlCloseBodyV2.
Normal class permits offer/accept/grant only; terminalization permits
settlement/carrier-terminal/close only. Normal seal is irreversible, while
terminalization remains open until all reserved transfers settle or become uncertain.
Each first predecessor is SHA256(LD(D(AckControlEnvelopeV2,genesis),
[raw(P),raw(E),raw(bindingHash),utf8(direction),utf8(sequenceClass)])).
Later predecessor is the complete prior envelope's typed external hash. tag is
HMAC-SHA256(directionKey,LD(D(AckControlEnvelopeV2,mac),
[canonical metadata without tag,raw_body])), base64(32). Frame body 1..65536,
metadata<=4096; max 69672. Wrong class/direction/key/ordinal/predecessor or trailing
bytes rejects before dispatch. Per-transfer offer/ACK/grant ID can occur once only,
independently of message-sequence uniqueness.

SettlementAckV2 is the receiver's unsigned body (P/E and all exact earlier fields).
SettlementAckEnvelopeV2 exact metadata: P,E,dataEndpointBindingSha256,
ackControlBindingSha256,receiverIdentitySha256,ackOrdinal=0,
bodySchema=SettlementAckV2,bodyByteLength,bodySha256,keyId,tag.
Use the per-transfer settlement-ack key, never the long-lived control-direction
key, with LD(D(SettlementAckEnvelopeV2,mac),
[raw(P),raw(E),raw(dataEndpointBindingSha256),raw(ackControlBindingSha256),
utf8(keyId),raw(bodySha256),u64be(bodyByteLength),raw_body]).
Its external hash is SHA256(LD(D(SettlementAckEnvelopeV2,envelope-hash),
[canonical metadata,raw_body])). The authenticated ACK-control channel carries
that envelope as its settlement payload, bodySchema=SettlementAckEnvelopeV2.
Thus there are two distinct authentications: transfer acknowledgement and
control-route sequencing. All settlementAckSha256 fields name this envelope,
not an unsigned body, control transport tag, or payload record.
SettlementAckV2 alone has no tag or mac purpose and provides no provenance.

AckControlCloseBodyV2 exact fields: P,E,ackControlBindingSha256,direction,
lastNormalSequence,lastTerminalSequence,settledTransferRootSha256,
pendingTransferSnapshotRef,normalIngressSealed=true,
remainingEmitterStateSha256,outcome,terminal=true.
Every offered transfer appears once in settled root or authenticated pending
snapshot; closure cannot omit an abandoned/unknown transfer. Emit this close body,
half-close exact send direction, have peer authenticate final EOF, then close/destroy
the exact control-direction key. Sender cannot self-attest that later key destruction.
The supervisor/next layer independently commits both owner endpoint/key/process
acquisition states, including normal never-created or uncertain arms.
Missing close, EOF-only, blocked callback, mid-envelope crash or expired deadline
retains uncertainty and returns under the original cleanup budget; no resync/retry.
The last callback/delivery owner is isolated, not allowed to control its own close
observer. A control channel cannot be retired while any admitted transfer uses it.

### Ordinals and exact chunk chain

The service assigns one `globalRecordOrdinal` across all accepted semantic records:
slots, Frida barrier/steps, transcript admissions, lane closure, and cleanup. The
chain deliberately stops before `ServiceTerminalBodyV2`; that unsigned body signs
the pre-terminal root and therefore cannot be a member of the root it names. The
ordinal starts at `0` and increments with no gap or duplicate. The service separately assigns
`transcriptIndex` from `0` in admission order. Child->service records also have a
lane/hop-local `hopRecordOrdinal`; after validation the service wraps them at the
next global ordinal. Equal numeric values in different named namespaces are valid.

`ServiceGlobalRecordV2` has these **PROPOSED exact fields**: `authority`,
`schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`serviceSessionId`, `globalRecordOrdinal`, `recordKind`,
`semanticBodySha256`, `transcriptIndex` (nonnull only for a transcript record),
`previousServiceRecordSha256`, and `acceptedMonotonicNs`. Its external digest is
`SHA256(LD(D(ServiceGlobalRecordV2,record-hash), [canonicalRecord]))`. At ordinal
0 the predecessor is
`SHA256(LD(D(ServiceGlobalRecordV2,genesis),
[raw(P), raw(E), serviceSessionId_raw]))`; thereafter it is exactly the prior
record digest.

`TranscriptAdmissionBodyV2` has exact fields `planCoreSha256`,
`executionBindingSha256`, `reservationSha256`, `transcriptIndex`, `transcriptId`,
`transcriptKind`, `carrier`, `canonicalByteLength`, `transcriptSha256`,
`sourceHopNamespace`, `sourceDataEndpointBindingSha256`, `sourceDirectionKeyId`,
`sourceCarrierTerminalEnvelopeSha256`, `sourceHopFinalRecordSha256`.
It has neither a TranscriptRef digest nor `serviceAdmissionRecordSha256`.
Canonicalize this body, wrap its digest in one ServiceGlobalRecord, compute that
record's external digest, and only then construct the immutable TranscriptRef.
The global record never names the future ref. `TranscriptForwardReceiptV2`
binds the original ref digest, exact next route index/namespace, prior hop terminal
and new hop terminal digest; it preserves canonical bytes/digest/index/ID.
The final verifier requires the whole ordered selected route, not just a last-hop
hash or a set of unordered closures. All four namespace variants have distinct
factory/key/endpoint generations.

`TranscriptRefV2` has these **PROPOSED exact fields**:
`planCoreSha256`, `executionBindingSha256`, `transcriptIndex`, `transcriptId`,
`transcriptKind`, `carrier` (`inline` or `bulk`), `canonicalByteLength`,
`transcriptSha256`, `sourceHopNamespace`, `sourceDataEndpointBindingSha256`,
`sourceDirectionKeyId`, `sourceCarrierTerminalEnvelopeSha256`,
`sourceHopFinalRecordSha256`, `admissionBodySha256`, and `serviceAdmissionRecordSha256`.
For inline, `sourceCarrierTerminalEnvelopeSha256` names the exact
`InlineTerminalEnvelopeV2`; for bulk it names the exact
`BulkManifestEnvelopeV2`. No nullable manifest shortcut exists.

For bulk, `BulkChunkHeaderV2` has these **PROPOSED exact fields**:
`authority`, `schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`hopNamespace`, `dataEndpointBindingSha256`, `directionKeyId`,
`transcriptIndex`, `transcriptId`, `transcriptKind`, `chunkIndex`,
`offset`, `chunkBytes`, `hopRecordOrdinal`, `previousChunkRecordSha256`, and
`operationDeadlineNs`.

`previousChunkRecordSha256` means the digest of the complete previous logical chunk
record—domain-separated canonical header plus raw payload—**not** the previous raw
chunk digest and not the previous HMAC tag. For chunk 0 it equals:

```text
SHA256(LD(D(BulkChunkHeaderV2,genesis),
  [raw(P), raw(E), hopNamespace_utf8, u64be(transcriptIndex),
   transcriptId_raw, raw(dataEndpointBindingSha256), utf8(directionKeyId)]))
```

For each chunk:

```text
chunkRecordSha256 = SHA256(LD(D(BulkChunkHeaderV2,record-hash),
  [canonical_header, raw_chunk]))

chunkTag = HMAC-SHA256(hop_direction_key,
  LD(D(BulkChunkHeaderV2,frame-mac), [canonical_header, raw_chunk]))
```

The digest/tag are external to the header, avoiding self-reference. Non-final
chunks are exactly 65,536 bytes; final chunk is 1..65,536; offset is exactly
`chunkIndex * 65536`. Indices and hop ordinals are strictly next.

`BulkManifestBodyV2` has these **PROPOSED exact fields**:
`authority`, `schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`hopNamespace`, `dataEndpointBindingSha256`, `directionKeyId`,
`transcriptIndex`, `transcriptId`, `transcriptKind`,
`totalBytes`, `chunkCount`, `transcriptSha256`, `genesisRecordSha256`,
`finalChunkRecordSha256`, `firstHopRecordOrdinal`, `lastHopRecordOrdinal`,
`senderHalfCloseReceiptSha256`, `directionKeyDestructionReceiptSha256`,
`senderEndpointCloseReceiptSha256`, `receiverEofReceiptSha256`,
`receiverEndpointCloseReceiptSha256`, `settlementAckSha256`, `canonicalEncoding`, and `terminal=true`.
It is authenticated in a distinct
manifest envelope on the control path after all chunks. Receiver validates chunks,
manifest, sender half-close, exact EOF, and endpoint close before publishing a
`TranscriptRefV2`. A control reference never precedes this settlement.

Inline records use a parallel `InlineTranscriptBodyV2` with **PROPOSED exact
fields** `planCoreSha256`, `executionBindingSha256`, `hopNamespace`,
`dataEndpointBindingSha256`, `directionKeyId`, `transcriptIndex`, `transcriptId`,
`transcriptKind`, `canonicalByteLength`,
`transcriptSha256`, `hopRecordOrdinal`, `previousRecordSha256`, and
`operationDeadlineNs`; its detached canonical transcript bytes are
HMAC-authenticated. `InlineTerminalBodyV2` has exact fields planCoreSha256,
executionBindingSha256, hopNamespace, dataEndpointBindingSha256, directionKeyId,
transcriptIndex, transcriptId, transcriptKind, canonicalByteLength,
transcriptSha256, inlineRecordSha256, senderHalfCloseReceiptSha256,
directionKeyDestructionReceiptSha256, senderEndpointCloseReceiptSha256,
receiverEofReceiptSha256, receiverEndpointCloseReceiptSha256, settlementAckSha256,
canonicalEncoding=utf8-canonical-json-v2, terminal=true.
Its authenticated `InlineTerminalEnvelopeV2` is complete before
a reference is published. Each inline object also uses one fresh one-shot endpoint;
inline is a carrier-size distinction, not permission to embed bytes in control.
For the first inline record, `previousRecordSha256` is exactly
`SHA256(LD(D(InlineTranscriptBodyV2,genesis),
[raw(P), raw(E), hopNamespace_utf8, u64be(transcriptIndex), transcriptId_raw,
raw(dataEndpointBindingSha256), utf8(directionKeyId)]))`; an inline object has
exactly one record, so no second record is permitted.

### Bulk/inline crash boundaries

Deterministic faults are required before/after: key creation; each endpoint create,
duplicate, publish, and job inheritance check; spool create/seal; header length;
partial header/payload/tag; each chunk write/read; final chunk; manifest sign/write;
manifest validation; sender half-close; receiver EOF; control-reference
publication; source-hop close; next-hop first/last record; spool close/delete; and
process crash on either side of every hop. Partial objects never become references.
Close uncertainty makes the containing terminal uncertain.

## Unsigned terminal bodies and three terminal chains

### Exact envelope construction

For the one service-signature profile and the signed supervisor layer:

1. canonicalize an unsigned body `B` that has no signature, body digest, envelope
   digest, or self-reference;
2. compute `bodySha256 = SHA256(LD(D(exact-body-schema,body-hash), [B]))`;
3. select exactly one type-specific signature domain: the PROPOSED service-terminal
   signature domain for `ServiceTerminalBodyV2`, or the PROPOSED supervisor-closure
   signature domain for `SupervisorClosureBodyV2`;
4. compute the exact signature input
   `LD(selected-domain, [raw(P), raw(E), utf8(signingKeyId),
   raw(bodySha256), u64be(byteLength(B)), B])`;
5. sign once with the layer's attested key;
6. construct the final envelope from body bytes, body digest, algorithm, key ID,
   attestation-envelope digest, and signature; and
7. compute the envelope digest externally. The envelope never contains its own
   digest.

The only provenance algorithm is Ed25519 (32-byte public key, 64-byte signature),
with exact attested key IDs and type-specific domains. No service MAC arm, MAC
attestation, algorithm negotiation or requester-known provenance key exists.
Lane/control/transfer HMACs authenticate their transport, not service provenance.
Authenticated envelopes use detached raw canonical body bytes, not a JSON object
or escaped JSON string embedded in their metadata; see the codec registry.

### Service terminal

`ServiceTerminalBodyV2` has these **PROPOSED exact fields**:
`authority`, `schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`serviceSessionId`, `serviceProcessIdentity`, `outcome`,
`physicalSuccessCandidateSealedNs`, `firstFailure`,
`authoritySnapshotReceiptSha256`, `authoritySnapshotFailureReceiptSha256`,
`fridaPhysicalSettlementEnvelopeSha256`,
`fridaCompositeClosureRecordSha256`, `authorityLaneClosureRef`,
`fridaLaneClosureRef`,
`guardianTerminalRootSha256`, `transcriptRootSha256`,
`preTerminalServiceRecordRootSha256`, `preTerminalServiceRecordCursorFinal`,
`serviceOwnedCloseSetSha256`, `remainingOutputHandleIdentitySha256`,
`remainingSigningHandleIdentitySha256`, `operationDeadlineNs`,
`cleanupDeadlineNs`, and `terminal=true`.

Exactly one of snapshot success/failure digests is nonnull. The service signs once
with its E-attested service key. It then destroys its provenance key, writes the already-buffered envelope,
closes its output endpoint, and exits. It cannot attest closure of those two final
capabilities; the supervisor does.

`serviceOwnedCloseSetSha256` commits the exact sorted service-owned resource ledger
after closing everything except the separately named remaining output endpoint and
signing-key handle. The two named identities must be live, distinct, absent from
that close set, and the only remaining service-owned capabilities at signing time.

`preTerminalServiceRecordRootSha256` is the final root after all service semantic
and cleanup records but before the terminal body. The terminal body is never added
back to that chain. The service terminal signature and external terminal-envelope
digest are the only final service-chain commitments, eliminating a terminal/root
self-reference.

`ServiceTerminalEnvelopeV2` metadata has exact fields `authority`,
`schemaVersion`, `planCoreSha256`, `executionBindingSha256`, `bodySchema`,
`bodyByteLength`, `bodySha256`, `signatureAlgorithm=Ed25519`, `signingKeyId`,
`executionAttestationSha256`, `signature`. Its body schema is exactly
ServiceTerminalBodyV2, its public key is the service key committed in E, and its
digest is external. `macArm`, `signatureArm`, `body`, and `provenanceKind` are
unknown fields and reject rather than silently selecting a fallback.

### Supervisor closure

The supervisor validates the service envelope, observes exact service signing-key
destruction, output EOF, endpoint close, process join, and job membership. It then
constructs unsigned `SupervisorClosureBodyV2` with these **PROPOSED exact fields**:
`authority`, `schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`supervisorProcessIdentity`, `servicePredecessorKind`,
`serviceTerminalEnvelopeSha256`, `missingServiceTerminalReceiptSha256`,
`serviceTerminalOutcome`, `serviceProvenanceVerificationReceiptSha256`,
`serviceOutputEofReceiptSha256`,
`serviceSigningHandleCloseReceiptSha256`, `serviceProcessJoinReceiptSha256`,
`serviceRemainingHandleCloseSetSha256`, `jobIdentity`, `jobAssignmentRootSha256`,
`jobActiveProcessCount`, `jobEmptyReceiptSha256`, `guardianClosureRefs`,
`allAcquisitionSnapshotRef`, `supervisorOwnedCloseSetSha256`,
`remainingSupervisorOutputHandleIdentitySha256`,
`remainingSupervisorSigningHandleIdentitySha256`, `firstSupervisorFailure`,
`closureOutcome`, `cleanupDeadlineNs`, and `terminal=true`.

`servicePredecessorKind` is exactly `terminal-present`, `terminal-missing-proved`,
or `terminal-unobserved-uncertain`. In the last arm the missing receipt's underlying
MissingLayerTerminalBodyV2 must be unobserved-uncertain: no invented output EOF,
process join or key closure, and closureOutcome remains uncertain.
The former requires the service-envelope digest and forbids the missing receipt;
the latter requires `MissingServiceTerminalReceiptV2`, forbids a service-envelope
digest, and sets the service outcome to `missing`. It never fabricates a service
terminal.

`SupervisorClosureEnvelopeV2` has these **PROPOSED exact fields**: `authority`,
`schemaVersion`, `planCoreSha256`, `executionBindingSha256`, `bodySchema`, `bodyByteLength`, `bodySha256`,
`signatureAlgorithm`, `signingKeyId`, `supervisorKeyAttestationSha256`, and
`signature`. Its digest is external. The supervisor signs once, destroys its
per-run signing key, writes the buffered envelope, closes output, and exits. The
settlement verifier—the next layer—observes supervisor signing-handle closure,
authenticated EOF, output endpoint close, and process join.

Likewise, `supervisorOwnedCloseSetSha256` excludes exactly the separately named
supervisor output and signing handles and includes every other supervisor-owned
generation. The settlement verifier rejects overlap, omission, extra live handles,
or a remaining third capability.

### Requester-local settlement/terminal chain

The settlement verifier starts a third chain from the exact `ServiceObservationV2`
and supervisor observation unions, not an unconditional pair of envelope digests.
It records supervisor key/output/process closure,
bridge creation/validation, facade receipt consumption, local callback delivery,
and final facade closure. It emits exactly one unsigned local
`RequesterTerminalBodyV2`; its digest is local authority, not service provenance.

`RequesterTerminalBodyV2` has these **PROPOSED exact fields**: `authority`,
`schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`serviceObservation`, `supervisorPredecessorKind`,
`supervisorClosureEnvelopeSha256`, `missingSupervisorClosureReceiptSha256`,
`supervisorClosureObservationReceiptSha256`, `bridgeBodySha256`,
`bridgeValidationReceiptSha256`, `logicalReceiptChainRootSha256`,
`globalConsumptionCursorFinal`, `authorityFacadeTerminalReceiptSha256`,
`fridaFacadeTerminalReceiptSha256`, `callbackDeliveryRootSha256`,
`firstRequesterFailure`, `requesterOutcome` (`success`, `failure`, or `uncertain`),
`localQuiescenceReceiptSha256`, and `terminal=true`. A failure before bridge
creation requires both bridge fields null and an exact first failure; a failure
after bridge creation preserves both bridge fields. This body is locally hashed as
`SHA256(LD(D(RequesterTerminalBodyV2,body-hash), [canonicalBody]))`;
it is neither inserted into nor used to rewrite either signed predecessor chain.
`supervisorPredecessorKind` is exactly `closure-present`, `closure-missing-proved`
or `closure-unobserved-uncertain`; the first requires only the supervisor envelope,
the latter two require only their typed missing-layer observation digest. The
uncertain arm does not demand nonexistent join/EOF/handle-close receipts. A bridge
requires closure-present plus independently proved post-envelope closure.

At orchestration construction, the outer S2b owner creates a closed
`RequesterTerminalRegistryV2` with exactly one compare-and-set terminal slot and a
distinct process identity from the adversarial application. Normal completion lets
the logical requester commit its terminal. If its isolated verifier worker exits
before committing, the surviving outer owner commits exactly one
`requesterOutcome=uncertain` fallback binding the verifier join/failure receipt and
completed predecessor prefix. Competing commits lose deterministically and cannot
change the winner. The outer entry returns by its original settlement deadline
with either the committed terminal or a detached durable-publication-uncertain
receipt naming the same reserved slot. Storage failure permits no unbounded wait
or second terminal slot. This local availability device is not service provenance and never
signs or rewrites either preceding chain.

The proposed layer states are:

```text
SERVICE_TERM_OPEN -> SERVICE_TERM_SUCCESS|FAILURE|UNCERTAIN  (one service-signed)
                  -> SERVICE_TERM_MISSING_ATTESTED            (one supervisor proof)
SUPERVISOR_TERM_OPEN -> SUPERVISOR_TERM_CLOSED|UNCERTAIN     (one supervisor-signed)
                     -> SUPERVISOR_TERM_MISSING_ATTESTED      (one verifier proof)
REQUESTER_TERM_OPEN -> REQUESTER_TERM_SUCCESS|FAILURE|UNCERTAIN (exactly one local)
```

“Exactly one terminal per layer” means exactly one closed union arm in the layer's
append-once registry. The normal arm is that layer's complete signed envelope. If
the process dies before emitting any valid envelope, only the next layer may commit
the distinct missing-emission arm after proving process join, authenticated output
EOF/invalid-prefix disposition, signing-handle closure, and output-handle closure.
The exact `MissingLayerTerminalBodyV2` union below also supports deadline-expired
unobserved closure without manufacturing those successful receipts. Its digest is
authenticated by the next layer's terminal body, not by the missing process. A
valid emitted envelope is retained even when its later closure remains uncertain.

Examples are intentionally non-collapsing:

- service success + supervisor job/EOF uncertainty = service remains signed
  success, supervisor is uncertain, requester creates no bridge;
- service/supervisor success + requester callback handler failure = both signed
  chains remain success/closed, requester terminal is local failure;
- missing service terminal + proved supervisor cleanup = the service-layer registry
  selects its supervisor-attested missing-emission arm and the supervisor closes as
  failure; it never fabricates a service-signed failure envelope;
- missing supervisor closure + verifier-observed supervisor join/EOF/handle close =
  the supervisor-layer registry selects its verifier-attested missing-emission arm,
  no bridge is created, and the requester commits local failure/uncertainty.

### Acquisition and missing-layer algebra

These closed unions replace boolean created/closed shortcuts, including keys and
handles that were not acquired. Every final lane, hop, guardian, signing key,
output endpoint, spool, process, job and callback worker is enumerated exactly
once by its pre-reserved role/acquisition ID. `AcquisitionStateV2` exact fields:
`resourceRole`, `acquisitionId`, `resourceKind`, `state`, `creationIntentSha256`,
`identitySchema`, `identitySha256`, `creationReceiptSha256`, `closeReceiptSha256`,
`joinReceiptSha256`, `keyDestructionReceiptSha256`, `observerReceiptSha256`,
`firstUncertainty`. `resourceKind` is `process|job|endpoint|key|fd|directory-fd|spool`.

| State | Exact required/null rules |
|---|---|
| `not-created` | Creation intent and independent no-creation observation nonnull; identity/creation/close/join/key-destruction null; uncertainty null. Absence of a publication is not this proof. |
| `created-closed` | Intent, exact identity/schema, acquisition result, close and observer nonnull; process additionally requires join; key additionally requires key destruction; those two fields null for other kinds; uncertainty null. |
| `created-uncertain` | Intent and observer/timeout receipt nonnull; preserve every authenticated identity/result/closure prefix; unknown identity is null with null creation receipt; firstUncertainty nonnull. The name includes a syscall-result-lost reservation which *may* have created a resource, not a fabricated creation fact. |

Before P exists, AcquisitionTokenV2/AcquisitionReservationV2 permit P=null only
under the externally pinned outer owner's same construction ID; these are
pre-plan supervisor/verifier/registry acquisitions, never lane/device authority.
After P exists those existing records remain unchanged references in its
construction settlement, and every new reservation requires exact P. No record
is retroactively rewritten or relabeled with a computed P.

During work, separate `AcquisitionReservationV2` and `AcquisitionResultV2` events
represent reserved and created-retained state; final closure never silently drops
one. `AcquisitionResultV2` binds the reservation digest, result disposition,
exact identity/schema and observed time, but not a future consumer/closure digest.
`RemainingEmitterStateV2` names the exact last live signing/output capabilities at
envelope emission. They cannot be marked created-closed inside that envelope;
the next layer appends their final AcquisitionState values, even when the emitter
crashes after signing. Pre-E settlement enumerates the same acquisition algebra
under P without invented E/lane-body identities. Generic cleanup receives only
the already-retained exact identities, never a reserved token guessed into a PID.

`LaneClosureRefV2` exact fields: `planCoreSha256`, `executionBindingSha256`,
`lane`, `closureKind`, `capabilityTerminalEnvelopeSha256`,
`capabilityQuiescenceEnvelopeSha256`, `neverStartedReceiptSha256`,
`missingLayerReceiptSha256`, `acquisitionSnapshotRef`, `outcome`.

| closureKind | Nonnull inputs | Null inputs / result |
|---|---|---|
| `proved-quiescent` | Valid terminal and quiescence envelopes | Never/missing null; outcome follows valid terminal; success requires every acquisition closed. |
| `terminal-unquiesced` | Valid terminal plus missing/uncertain-quiescence observation | Quiescence and never null; outcome uncertain even if terminal said success. |
| `never-started` | Exact never-started receipt and acquisition states | Terminal/quiescence/missing null; no operation admitted; not a success snapshot. |
| `missing-crashed` | Next-owner missing-layer observation and acquisition states | No invented terminal/quiescence/never receipt; outcome uncertain or proved failure closure. |

`MissingLayerTerminalBodyV2` is the uniform post-E observation body with exact
fields `planCoreSha256`, `executionBindingSha256`, `missingLayer`,
`missingProcessAcquisitionState`, `emissionStatus`, `observedOutputPrefixSha256`,
`observedOutputByteLength`, `outputDisposition`, `signingKeyAcquisitionState`,
`outputAcquisitionState`, `processAcquisitionState`, `observerLayer`,
`observerIdentitySha256`, `observationReceiptSha256`, `observedHostNs`,
`cleanupDeadlineNs`, `firstFailure`, `outcome=emission-unavailable`, `terminal=true`.
`missingLayer` is `lane-authority|lane-frida|guardian|service|supervisor|verifier`;
`emissionStatus` is `proved-missing|unobserved-uncertain`; output disposition is
`empty-eof|invalid-prefix-eof|incomplete-prefix-timeout|not-created`.
Proved-missing requires exact EOF/join/key+output closure or proved not-created;
timeout never manufactures any of those receipts. `observedOutputPrefixSha256`
is SHA-256 of exactly the bounded observed bytes, including empty bytes; it is not
a digest of a hypothetical terminal. The observer signs/MACs only under its
registered next-layer profile. Missing-service, missing-supervisor and missing-
quiescence receipts are distinct typed instances, never type aliases at the wire.

`ServiceObservationV2` exact fields: `kind`, `serviceTerminalEnvelopeSha256`,
`supervisorClosureEnvelopeSha256`, `missingServiceObservationSha256`,
`missingSupervisorObservationSha256`.
`present` requires the complete independently root-valid service envelope and
preserves a supervisor envelope if received; missingService is null. The
`supervisor-attested-missing` arm requires signed supervisor closure and its exact
missing-service observation, service envelope null; this describes nonreceipt of
a valid emission, not proof of process absence (the nested emissionStatus decides).
`unknown-because-supervisor-missing` requires null service/supervisor envelopes,
null missingService, and the verifier's exact missing-supervisor observation. A
requester never invents service absence when it also lacks the supervisor. Every
arm preserves independently available signed evidence and forbids a success bridge
without the complete normal chain.

`RequesterTerminalRegistryV2` has exact fields `constructionId`, `planCoreSha256`,
`executionBindingSha256`, `outerOwnerIdentity`, `verifierAcquisitionState`,
`reservedSlotId`, `winnerKind`, `winnerBodySha256`, `commitReceiptSha256`.
Only post-E instances have nonnull E; pre-E uses the separate construction schema.
`winnerKind=verifier-terminal|outer-verifier-crash|publication-uncertain`; the last
requires null commit receipt and retains the single reserved slot. The exact
`VerifierCrashRequesterBodyV2` binds P/E, that slot, verifier acquisition/observation,
available service/supervisor observation prefix, callback-worker acquisition state,
first failure and `outcome=uncertain`; it contains no fabricated bridge or facade
terminal digest. CAS and durable checkpoint determine one winner. A later recovery
may resolve that same publication, never commit a competing normal terminal.

## Bridge, compatibility projection, and receipt-only facades

The settlement verifier creates a bridge only after validating service success,
supervisor `closureOutcome=closed`, supervisor signing/output/process closure, and
all referenced transcripts. Bridge construction must finish before the fixed
cleanup/settlement deadline. Facade consumption may occur later because it carries
no physical authority and performs no physical I/O.

### Requester bridge proposed exact keyset

`RequesterBridgeBodyV2` has these **PROPOSED exact fields**:
`authority`, `schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`serviceTerminalEnvelopeSha256`, `supervisorClosureEnvelopeSha256`,
`supervisorOutputEofReceiptSha256`, `supervisorSigningHandleCloseReceiptSha256`,
`supervisorProcessJoinReceiptSha256`, `authoritySnapshotReceiptSha256`,
`fridaPhysicalSettlementEnvelopeSha256`,
`fridaCompositeClosureRecordSha256`, `compatibilityProjectionSha256`,
`logicalReceiptTemplateRootSha256`, `bridgeNonce`, `constructedMonotonicNs`,
`constructionCursor=0`, and `constructedAfterCompleteClosure=true`.

The bridge digest is computed externally. An independent validator reloads detached
canonical bytes, revalidates the trust chain and projection digest, and atomically
publishes proposed state `REQUESTER_BRIDGE_VALIDATED`. The bridge is single-use and
cannot be supplied by the application requester.

To remain acyclic, receipt templates are canonicalized and hashed first; they bind
`P`, `E`, the compatibility projection, and immutable service/supervisor closure
digests but never the future bridge digest. The bridge then commits their ordered
root. Only runtime logical outcome receipts bind the external bridge-body digest.

### Compatibility projection bytes/schema

`NativePageCompatibilityProjectionV2` is canonical UTF-8 JSON, 1..131,072 bytes,
with no own digest/length field. Its external descriptor carries length and digest.
Its **PROPOSED exact fields** are:

`authority`, `schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`serviceTerminalEnvelopeSha256`, `supervisorClosureEnvelopeSha256`,
`authorityAdmissionProjection`, `fridaAdmissionProjection`,
`authoritySnapshotReceiptSha256`, `fridaPhysicalSettlementEnvelopeSha256`,
`fridaCompositeClosureRecordSha256`,
`beforeStageProjection`, `afterStageProjection`, `fridaLogicalProjection`,
`orderedTranscriptRefs`, `stabilityResultSha256`, `physicalClosureProjection`,
and `failureProjection=null`.

`CompatibilityProjectionDescriptorV2` has these **PROPOSED exact fields**:
`authority`, `schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`projectionKind`, `canonicalEncoding=utf8-canonical-json-v2`,
`projectionByteLength`, and `projectionSha256`. It carries no projection bytes and
is accepted only alongside the exact already-local detached projection object.

Nested exact schemas are:

- PROPOSED `AdmissionProjectionV2`: `provider`, `imageManifestSha256`,
  `factoryPolicySha256`, `laneTerminalEnvelopeSha256`,
  `laneQuiescenceEnvelopeSha256`, and `admitted=true`;
- PROPOSED `StageProjectionV2`: `phase`, `slotFirst`, `slotLast`,
  `slotRecordDigests`, `phaseRootSha256`, `evidenceMapSha256`,
  `taskAuthoritySha256`, `placementAttestationSha256`, `penAttestationSha256`,
  `checkpointAttestationSha256`, `transcriptRefs`, and `stabilityProjectionSha256`;
- PROPOSED `FridaLogicalProjectionV2`: `logicalAttachBindingSha256`,
  `physicalSettlementEnvelopeSha256`, `compositeClosureRecordSha256`,
  `callbackTranscriptRef`, `callbackCount`,
  `callbackChainRootSha256`, `sealReceiptSha256`, `unloadReceiptSha256`,
  `detachReceiptSha256`, and `physicalOutcome=detached-success`; and
- PROPOSED `PhysicalClosureProjectionV2`: `authorityLaneTerminalEnvelopeSha256`,
  `authorityLaneQuiescenceEnvelopeSha256`, `fridaLaneTerminalEnvelopeSha256`,
  `fridaLaneQuiescenceEnvelopeSha256`, `guardianTerminalRootSha256`,
  `transcriptHopClosureRootSha256`, `serviceTerminalEnvelopeSha256`,
  `serviceSigningHandleCloseReceiptSha256`, `serviceOutputEofReceiptSha256`,
  `serviceProcessJoinReceiptSha256`, `supervisorClosureEnvelopeSha256`,
  `supervisorSigningHandleCloseReceiptSha256`,
  `supervisorOutputEofReceiptSha256`, `supervisorProcessJoinReceiptSha256`, and
  `jobEmptyReceiptSha256`.

A failure uses separate `NativePageCompatibilityFailureProjectionV2` and never
populates success fields with null-like placeholders. Its proposed exact fields are
`authority`, `schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`serviceTerminalEnvelopeSha256`, `supervisorClosureEnvelopeSha256`,
`authoritySnapshotFailureReceiptSha256`,
`fridaPhysicalSettlementEnvelopeSha256`,
`fridaCompositeClosureRecordSha256`,
`firstFailure`, `completedTranscriptRefs`, `physicalClosureProjection`, and
`localFailureMapping`.

PROPOSED `LocalFailureMappingV2` has exact fields `sourceLayer`, `sourceState`,
`sourceCode`, `sourceReceiptSha256`, `facadeKind`, `logicalMethod`,
`publicFailureCode`, and `retryable=false`. The Frida physical-settlement digest is
nullable only when that operation never produced a complete envelope; its
post-lane-close composite record is mandatory. Completed transcript references are
an exact admission-order prefix, never a best-effort set.

These are v2 bytes and types. An unmodified v1 runner is not assumed to accept
them. Any adapter to an existing coordinator must be separately reviewed and may
not modify `AuthorityEngine` v1 or relabel v2 bytes as v1 authority.

### Exact logical receipt templates, states, and outcome shape

The bridge contains an immutable ordered bundle of normal-call
`LogicalReceiptTemplateV2` bodies, not preconstructed future outcome receipts.
Each template has these **PROPOSED exact fields**: `planCoreSha256`,
`executionBindingSha256`, `compatibilityProjectionSha256`,
`serviceTerminalEnvelopeSha256`, `supervisorClosureEnvelopeSha256`, `templateIndex`,
`globalConsumptionOrdinal`, `facadeKind`, `method`, `requiredFacadeCursorBefore`,
`requiredStateBefore`, `successFacadeCursorAfter`, `successStateAfter`,
`successPhysicalBindingKind`, `successPhysicalBindingSha256`,
`successProjectionSha256`, `callbackPolicy`, `failurePolicySha256`, and
`terminalForFacadeOnSuccess`. `logicalReceiptTemplateRootSha256` is the digest of
the exact length-prefixed template bodies in index order. A method validates its
template and current state, performs only permitted local projection/callback work,
then constructs exactly one success or failure outcome receipt.

The common `LogicalMethodReceiptBodyV2` has these **PROPOSED exact fields**:
`authority`, `schemaVersion`, `planCoreSha256`, `executionBindingSha256`,
`bridgeBodySha256`, `templateBodySha256`, `facadeId`, `facadeKind`, `method`,
`globalConsumptionOrdinal`, `facadeCursorBefore`, `facadeCursorAfter`,
`stateBefore`, `stateAfter`, `previousLogicalReceiptSha256`, `outcome`,
`physicalReceiptSha256`, `projectionSha256`, `callbackRange`,
`callbackChainRootSha256`, `deliveredCallbackCount`, `failure`,
`localQuiescenceSha256`, and `terminalForFacade`.

Success requires `outcome=success`, the template's exact success cursor/state and
bindings, and `failure=null`. Failure requires `outcome=failure`, cursor advancement
to that attempted method's after value, layer-prefixed state
`REQUESTER_<FACADE>_FAILED`, a closed `LogicalFailureBodyV2`, no later lifecycle
success, and one requester-terminal failure. Cleanup-only method receipts remain
admissible under the exact trace exception arms and cannot clear that failure. `LogicalFailureBodyV2` proposed fields are `layer`,
`method`, `code`, `callbackIndex`, `completedCallbackCount`,
`sourceReceiptSha256`, `causeDigestSha256`, and `firstFailure=true`; no free-form
exception text is authoritative.

For every non-`load` method, `callbackRange=null`,
`callbackChainRootSha256=null`, and `deliveredCallbackCount=0`. For a non-callback
success, both physical/projection digests are the nonnull values pinned by the
template. A pre-consumption validation failure requires
`physicalReceiptSha256=null`, `projectionSha256=null`, and a failure source equal
to the rejected template/bridge/current-predecessor digest. A failure after a
physical projection has validated preserves that template-pinned physical digest.
Only `load` may fail during callback replay: it preserves the physical settlement
digest and projection, binds the exact delivered prefix range/root/count, and sets
`callbackIndex` to the first undelivered/failing callback. Closure success requires
both facade teardown receipt digests and nonnull `localQuiescenceSha256`; closure
failure preserves any completed teardown predecessor and cannot reopen a facade.

The exact layer-prefixed success states are:

```text
REQUESTER_AUTH_NEW -> REQUESTER_AUTH_ADMITTED
 -> REQUESTER_AUTH_BEFORE_CONSUMED -> REQUESTER_AUTH_AFTER_CONSUMED
 -> REQUESTER_AUTH_QUIESCENT -> REQUESTER_AUTH_CLOSED

REQUESTER_FRIDA_NEW -> REQUESTER_FRIDA_ADMITTED
 -> REQUESTER_FRIDA_LOGICALLY_ATTACHED -> REQUESTER_FRIDA_CALLBACKS_REPLAYED
 -> REQUESTER_FRIDA_CALLBACKS_SEALED -> REQUESTER_FRIDA_UNLOADED
 -> REQUESTER_FRIDA_DETACHED -> REQUESTER_FRIDA_QUIESCENT
 -> REQUESTER_FRIDA_CLOSED

any attempted-method failure -> REQUESTER_<FACADE>_FAILED
adapter close              -> REQUESTER_ADAPTER_CLOSED_SUCCESS|FAILURE|UNCERTAIN
```

### Exact runner trace, read-only assertions and cleanup arms

The compatibility target is the actual frozen runner trace below, not the former
14-step illustrative schedule. Assertions do not consume a normal-operation permit
or a one-shot facade success cursor. Their independent proof observations remain
ordered in the local trace; repeated assertions are not silently dropped.
Only admission/capture/attach/load consume OperationStartPermit, exactly once.

| Trace index | Exact nominal successful call / event | Semantics |
|---:|---|---|
| 0 | authority.admission(timeout,permit) | Logical admission attempt 0. |
| 1 | authority.assert_quiescent(timeout) | Authority proof 0. |
| 2 | frida.admission(timeout,permit) | Logical Frida admission attempt 0. |
| 3 | frida.assert_quiescent(timeout) | Frida provider proof 0; current S6 compatibility blocker below. |
| 4 | authority.capture(before_request,timeout,permit) | phase=before,sequence=1,no predecessor; exact original deadline. |
| 5 | authority.assert_quiescent(timeout) | Authority proof 1. |
| 6 | frida.attach(serial,pid,timeout,permit) | Exact selector; one session returned or no session exists. |
| 7 | session.load(source,collector.on_message,timeout,permit) | One exact source and one handler; no public success until callbacks settle. |
| 8 | collector.wait(); collector.result(); collector.seal() | No provider permit; immutable exact callback result then publication fence. |
| 9 | session.seal_callbacks(timeout) | Attempt if attach returned a session, even if load failed. |
| 10 | session.unload(timeout) | Attempt even if the prior cleanup step failed. |
| 11 | session.detach(timeout) | Attempt even if prior cleanup steps failed. |
| 12 | session.assert_quiescent(timeout) | Separate session proof; attempt despite prior errors. |
| 13 | frida.teardown(timeout) via _TeardownOnce | One provider terminal action, shared with watchdog/cancel. |
| 14 | frida.assert_quiescent(timeout) | Frida provider proof 1. |
| 15 | collector.assert_clean_after_quiescence(); watchdog stop/join | Late callback/error remains failure. |
| 16 | authority.capture(after_request,timeout,permit) | phase=after,sequence=2,exact BEFORE receipt; same manifest/binding/run nonce/hard deadline. |
| 17 | authority.assert_quiescent(timeout) | Authority proof 2. |
| 18 | frida.assert_quiescent(timeout) | Frida provider proof 2, repeated intentionally. |
| 19 | final tool validation, stability, canonical result and hard-deadline check | Failure cannot become success by cleanup grace. |

No successful-path authority cancel/fail-stop occurs in run_one_stage. Local
adapter/bridge closure is a separate requester terminal step after this trace,
not a fabricated provider teardown call. Tool identity checks also run before
the protected block, after Frida admission and BEFORE validation, and in final
cleanup. Preflight failures before the protected block do not enter that block's
cleanup branch.

Closed exception transitions reproduce the actual runner:
(a) _bounded_call always seals its permit, stops/joins its watchdog and attempts
the supplied assertion. Provider exception invokes ordinary cancel. Invalid,
unsettled, reused or wrong-thread permit and watchdog expiry/clock failure invoke
terminal cancel. Failed assertion invokes ordinary cancel and one second assertion;
even if it then succeeds the original failed assertion remains an error.
Ordinary and terminal cancel each deduplicate; terminal suppresses later ordinary.
Authority ordinary cancel is cancel_and_quiesce; terminal is _AuthorityFailStopOnce.
Both Frida paths use _TeardownOnce. Provider-specific quiescence errors retain
their type; cleanup/expiry/permit/operation errors follow the frozen precedence.

(b) If attach never returned a session, skip session cleanup only; provider teardown
and assertion still occur. If attach returned, always attempt all four session
steps 9..12, even after failed load, callback/permit/deadline/observer failure.
Each cleanup exception is caught independently; none skips later steps or provider
cleanup. Cleanup errors outrank the primary operation failure. Watchdog expiry
uses the same once-only provider teardown and never grants a retry.

(c) Outer failure marks the authority channel unsafe when admission was not
established, its provider-specific quiescence error occurred, or authenticated BEFORE
receipt is missing. Unsafe means terminal authority fail-stop→assert→suppress AFTER.
Otherwise attempt AFTER under original request deadline, including the runner's
cleanup-grace permit arm. Any authority-specific AFTER failure invokes terminal
fail-stop/assert. Final Frida assertion, tool checks and available stability checks
are still attempted; cleanup/postcondition errors outrank operation errors.

(d) A failed logical load sets sticky failure but retains the exact cleanup-only
script/physical receipt. seal_callbacks, unload, detach and session assertion remain
admissible cleanup attempts. Their receipts use outcome=cleanup-complete or
cleanup-failed and cannot restore lifecycle success or overwrite the earlier failure.
Idempotent seal/unload/detach returns in their already-closed states are read-only
proofs, not repeated starts. A teardown that already won may make later steps fail;
the facade must reproduce that result instead of skipping the call.
Repeated authority assertion while open is a real worker proof in S7 and may
fail-stop on error; a v2 receipt-only facade substitutes only the separately
reviewed detached proof semantics, never claims the original operation was inert.

Two concrete current-adapter incompatibilities are explicit admission blockers:
S6 admission sets READY but its assert_quiescent requires CLOSED, so the nominal
runner's trace index 3 currently fails. The runner's post-hard-deadline AFTER
cleanup permit does not extend S7's AuthorityRequest deadline; S7 rejects it.
A v2 facade must preserve the trace/error meanings through a separately reviewed
adapter, not weaken CLOSED or manufacture late evidence. Existing concrete S6/S7
integration is NOT claimed successful by this design.

Frozen runner cleanup calls have <=25ms slices within hard+250ms; after expiry
the runner still attempts each callback with 1ms and records failure. The v2
receipt-only facade may finish bounded local failure/proof handling, but its
physical adapter must dispatch no new physical mutation after its absolute cleanup
deadline. This difference is an explicit compatibility/timing gate, not authority
to extend physical work. No physical operation, live provider/pen lease, process
handle or callback sink crosses the bridge. All facade mutations are local
receipt state or isolated callback delivery over already-validated bytes.

### Exact current interfaces and isolated logical callback contract

This table is the source-checked current Python contract, not a claim that its
v1 wire authority is compatible with this proposed v2 projection. A separately
reviewed adapter must preserve these signatures and exception/lifetime meanings:

| Current owner | Exact method and result | V2 logical mapping / constraint |
|---|---|---|
| AuthorityProvider | `preview_admission() -> CanonicalAuthority` | Detached read-only admission projection; no cursor or source call. |
| AuthorityProvider | `admission(timeout_ms:int, start_permit:OperationStartPermit) -> CanonicalAuthority` | One admission attempt; consumes one local guarded registration only after physical settlement. |
| AuthorityProvider | `capture(request:AuthorityRequest, timeout_ms:int, start_permit:OperationStartPermit) -> StageAuthorityCapture` | BEFORE sequence 1 then AFTER sequence 2, same run nonce, exact predecessor receipt; returns record/task/receipt detached. No capture_before/capture_after/stage method exists. |
| AuthorityProvider | `cancel_and_quiesce(timeout_ms:int) -> None` | Terminal cancellation; v2 consumes failure/cancel receipt, never physical service I/O. |
| AuthorityProvider | `assert_quiescent(timeout_ms:int) -> None` | Current provider can assert per-call quiet while still open; after fail-stop requires closed owner and no obligations. V2 validates the corresponding detached proof and local delivery barrier. |
| AuthorityProvider | `fail_stop_and_quiesce(timeout_ms:int) -> None` | Current retained isolated worker kill/join boundary; v2 closes only its logical projection/callback owner since physical closure preceded bridge. No fabricated teardown alias. |
| FridaProvider | `preview_admission() -> CanonicalAuthority` | Read-only projection, no cursor. |
| FridaProvider | `admission(timeout_ms:int, start_permit:OperationStartPermit) -> CanonicalAuthority` | Exactly one admission. |
| FridaProvider | `attach(serial:str, pid:int, timeout_ms:int, start_permit:OperationStartPermit) -> FridaSession` | Exactly one matching selector; consume authenticated post-attach LogicalAttachBinding, never attach again. |
| FridaProvider | `teardown(timeout_ms:int) -> None` | Terminal fence before lock waits; local logical closure only in v2; cannot overwrite failure/uncertainty. |
| FridaProvider | `assert_quiescent(timeout_ms:int) -> None` | Current provider requires CLOSED, exact server teardown, no obligations and closed owner; v2 requires the corresponding settled projection. |
| FridaProvider | `stage_frida_record(phase:str) -> dict` | Read-only detached evidence for exact before/after state; current before requires READY/ATTACHED live server and after CLOSED+absence, never mutation or receipt-cursor consumption. |
| FridaSession | `load(source:str,on_message:Callable[[Any,Any],None],timeout_ms:int,start_permit:OperationStartPermit) -> None` | Exact observer bytes, one load; v2 replays only immutable settled callback projection through the isolated dispatcher below. |
| FridaSession | `seal_callbacks(timeout_ms:int) -> None` | Irrevocably fence new callback starts, then boundedly settle in-flight delivery. |
| FridaSession | `unload(timeout_ms:int) -> None` | Exact once-only transition after seal; no script I/O in v2. |
| FridaSession | `detach(timeout_ms:int) -> None` | Exact once-only transition after unload; no session I/O in v2. |
| FridaSession | `assert_quiescent(timeout_ms:int) -> None` | Session-scoped callback barrier, distinct from provider closed-server assertion. |

`AuthorityRequest` is exact phase/sequence/run-nonce/previous-receipt/binding
authority, not a caller dictionary shortcut. `OperationStartPermit` currently
requires exactly one synchronous completed start registration and is sealed on
return; its watchdog may invoke terminal cancellation concurrently. V2 cannot
pretend an ignored permit was consumed. Any compatibility adapter consumes it
exactly once around the local receipt transition and returns only after that
registration settles; it never serializes the permit or lets it authorize physical
work. Current Authority and Frida implementations, v1 schema, runner and registry
are unchanged. The frozen 250ms total/25ms-per-call remote teardown budget remains
unproved hardware admission, not a timing claim made by this design.

Read-only queries have no global ordinal. Repeat quiet assertions are read-only
proof checks, not new success receipts. The exact nominal/exception trace above governs the facade; a different simplified
scheduler or assertion count is not compatible. Implementation still requires a
reviewed adapter for the concrete READY/CLOSED and deadline incompatibilities. Closed
`LogicalFailurePolicyV2` permits terminal cancel/fail-stop/teardown/adapter-close
and the exact retained-session cleanup suffix after a failed load; it never
allows another admission/capture/attach/load success or reopens a cursor.

Potentially hostile `on_message` code never executes on supervisor, service,
settlement verifier, facade lock owner or a thread whose join can block the outer
entry. It executes in a distinct outer-S2b-owned callback process with no device,
worker, provider, provenance key or terminal-registry handle. The dispatcher sends
one immutable callback at a time and receives a bounded `CallbackDeliveryAckV2`
binding bridge digest, callback ordinal/input digest, generation, disposition and
handler-result digest. A throw, hang, disconnect, attempted reentrant facade call,
or ACK replay revokes publication generation before any lock wait; no later callback
begins. One in-flight callback may only finish inside its isolated process, whose
exact kill/join/closure is attempted under the original local-delivery deadline.
Failure to prove that closure yields requester-uncertain, not a successful local
quiescence receipt. Callback delivery needs a separately fixed bounded local
deadline captured at facade construction (not the expired physical deadline),
and never extends physical/cleanup authority. Arbitrary same-process callback
execution is explicitly outside the supported adversarial-requester profile.

## Deadlines, conversions, and bridge timing

Wire nanoseconds are canonical positive decimal strings parsed into signed int64
`1..9223372036854775807`. Parse rejects sign, leading zero, whitespace, overflow,
and nondecimal input. The checked sum `operationDeadlineNs + cleanupGraceNs` must
not overflow and must equal the PlanCore cleanup deadline.

Every physical check uses the same clock incarnation and original operation
deadline. Remaining nanoseconds use checked subtraction. `remaining <= 0` expires.
Windows local waits convert with overflow-safe quotient/remainder ceiling
`remainingNs // 1_000_000 + int(remainingNs % 1_000_000 != 0)`, cap each wait to the smaller of remaining time, the
reviewed poll slice, and `0xFFFFFFFE` milliseconds, and repeat only while the same
absolute deadline remains live. `INFINITE`, wrapped DWORDs, negative-to-unsigned
conversion, and a fresh `now+timeout` are forbidden.

A physical success candidate—including slot 23 and Frida detached quiescence—must
seal at `now < operationDeadlineNs`. Service/supervisor terminal construction,
exact cleanup, closure observation, transcript settlement already in flight, and
bridge construction may continue until `cleanupDeadlineNs`. That grace cannot
create or repair a physical success candidate. Bridge construction must occur
after supervisor output EOF/process join and before cleanup deadline. If that
window is empty or expires, no facade is created. Once a bridge is valid, later
receipt-only facade calls may occur after the deadlines; they authorize no live
resource or new observation.

The supervisor's retained host clock is the sole success-time authority. Child,
service, guardian and requester timestamp claims are evidence only, never a way
to reopen a host deadline. A signed acceptance receipt records the host clock
incarnation, original deadline, challenge and time immediately after evidence
validation and before its atomic acceptance. No device BOOTTIME value is
subtracted from host monotonic time. Guardian-local receipts explicitly use
`capturedDeviceBoottimeMs`; old generic capturedMonotonicNs wording does not imply
a cross-machine clock. A child report can precede acceptance but cannot date it.

`GuardianLeaseGrantV2` exact fields are `planCoreSha256`,
`executionBindingSha256`, `guardianSessionId`, `guardianBootId`,
`offerChallenge`, `offeredDeviceBoottimeMs`, `absoluteDeviceExpiryMs`,
`leaseSequence`, `workGateSha256`, `hostOperationDeadlineNs`,
`supervisorIssuedNs`. The guardian first offers its own BOOTTIME sample/challenge;
the grant fixes expiry from that sample (checked addition, maximum 1,000ms), not
from delayed receipt time. The supervisor signs only while its original host
deadline is live. Guardian consumes sequence/challenge once, rejects expired grants,
and checks BOOTTIME before every read/seek/stream dispatch and watchdog tick.
Renewal is a new authenticated offer/sequence, never a rebase of host authority;
no renewal after host failure/normal-work seal. Cancel/EOF/lease expiry seals reads,
wipes keys and closes/exits. This is a conservative local safety lease, not a claim
that network latency maps device expiry to an exact host instant. Device suspend
counts in BOOTTIME. Any inability to prove guardian closure by host cleanup expiry
is retained uncertainty/reboot-required, not successful Windows-job cleanup.

At cleanup entry retain one immutable absolute total deadline equal to the
PlanCore cleanupDeadlineNs. For every allowed cleanup call take one trusted
host-clock sample n, checked-add 25,000,000ns, and retain
callDeadline=min(cleanupDeadlineNs,n+25,000,000ns); overflow rejects the call.
Pass that exact absolute deadline to the isolated adapter, include time spent
waiting for dispatch locks, and check completion against that same bound. No
callback may replace the clock, extend/rebase either deadline, or convert a
late 30ms return into a successful 25ms cleanup call. At or beyond either bound,
preserve the obligation and uncertainty; do not retry under a new per-call window.
The total grace is exactly 250,000,000ns, never 25ms multiplied by the number of
remaining operations. The runtime must prove the fixed operation sequence fits;
this has not been demonstrated on hardware.

At cleanup expiry, issue no new blocking call or mutation. Probe only already-
retained handles with nonblocking observation, create `CleanupExpiryReceiptV2`
with exact P/E, closing layer/cursor, original operation/cleanup deadlines,
host sample, completed prefix and remaining acquisition states, and publish through
the pre-reserved durable outer terminal slot. Publication itself has the same
finite bound; if the storage operation cannot settle, return a detached
`PublicationUncertainReceiptV2` referencing its reserved transaction and prior
checkpoint, not a claim of fsync success. A separately retained recovery owner
keeps the obligation; the caller never spins waiting for uncertainty to disappear.
This requires reviewed nonblocking/cancellable OS adapters. Uninterruptible kernel
I/O, loader/driver bugs, arbitrary in-process callbacks and unbounded storage APIs
are explicit implementation/hardware blockers, not timeout assumptions hidden in
Python. For all per-call waits use `min(originalCleanupDeadline, now+slice)` only
after checked addition and recheck completion against that exact bound.

## Shared session cleanup and explicit closure

Cleanup is one service-session ledger with the exact intentionally shared job and
two otherwise independent lane subledgers. Order is:

1. atomically seal application/requester and normal-operation ingress; retain a
   separate terminalization-only record class for pending transfer settlement,
   acquisition/closure, Frida composite, snapshot outcome and cleanup records;
2. fence both v2 Parents, callbacks, inline carriers, bulk senders, and guardian
   stream epochs;
3. complete the exact Frida conditional seal/unload/detach suffix if retained
   identities permit; never act on a name/PID alone;
4. settle every already-admitted transcript one-shot data hop and spool, or mark
   the owning layer uncertain; no lane/process endpoint needed for draining is
   closed before this step;
5. close/revoke Frida lane and capture detached terminal/quiescence envelopes;
6. close/revoke Authority lane and capture detached terminal/quiescence envelopes;
7. close every guardian same-FD/directory-FD generation, destroy stream keys, join
   exact guardian processes, and verify session staging removal;
8. terminate/join exact worker identities not already exited, including
   never-started/suspended workers, and close all duplicate/endpoint generations;
9. finalize the Frida composite-closure record and authority snapshot
   success/failure receipt from their sealed candidates and exact lane closure
   union arms; append all final acquisition/cleanup/guardian records, then atomically
   seal the preterminal service root/cursor; no body committed by this root names it;
10. service creates exactly one terminal body/envelope from the frozen preterminal
   root, destroys signing key,
   closes output, and exits;
11. supervisor attests service key/output/process closure, job assignment receipts,
    zero active job processes, and all remaining handles; it creates exactly one
    closure envelope, destroys its per-run key, closes output, and exits;
12. logical requester/settlement verifier attests supervisor key/output/process
    closure and either
    creates/validates the bridge or records local failure/uncertainty; and
13. receipt-only facades consume the ordered templates and the requester terminal
    registry commits exactly one requester closure terminal.

No close receipt authorizes a second close of a numerically reused handle. Every
close is keyed by owner PID/start, native value, generation, and duplicate lineage.
Failure to prove any sibling closure does not stop attempts on other siblings but
does make the appropriate layer uncertain.

## Crash/failure boundaries

| Boundary | Exact handling | Layer result |
|---|---|---|
| PlanCore canonicalization/hash | No service, worker, guardian, job, or endpoint creation. Close/join the already image-verified construction-only supervisor under an outer receipt. | No protocol terminal chain; outer construction failure. |
| Supervisor key creation/root attestation | Destroy any created key/handle; no lane body. | Supervisor construction failure. |
| Service/worker CreateProcess before handle publication | Retain acquisition token immediately; kill/join exact process or mark uncertain. | Supervisor failure/uncertain. |
| Job assignment before/after kernel call or receipt publication | Process stays suspended; query exact job/process identity, kill/join; never resume uncertain assignment. | Assignment failure/uncertain receipt. |
| Lane key/epoch/endpoint partial creation | Before E: P-rooted construction acquisition union. After E: never-started/missing/unquiesced lane closure as actually observed. | Construction abort or post-E service failure/uncertain, never a fabricated E. |
| Child ready publication/EOF | Reject unsigned/partial ready; revoke lane and join exact Child. | Service failure/uncertain. |
| Authority slot 0..11 | Preserve completed exact prefix; do not start Frida. | Snapshot failure then service failure/uncertain. |
| Frida barrier before physical attach | No AFTER slots; close both lanes. | Service failure/uncertain. |
| Physical attach/selector/load/callback/seal/unload/detach | Preserve first step failure; perform only exact conditional cleanup suffix. | Frida detached-failure or uncertain; no AFTER. |
| Authority slot 12..23 | Preserve signed Frida success unchanged and completed slot prefix. | Snapshot failure then service failure/uncertain. |
| Guardian launch/open/path/stat/key agreement | No fallback credential/path/raw transfer; close exact partial resources. | Slot/service failure or uncertain. |
| Guardian stream seek/chunk/EOF/offset/stat/close | Reject same-FD proof; destroy keys, close/join exact guardian. | Slot/service failure or uncertain. |
| Inline/bulk each hop | Apply every crash point listed in the topology section; no partial reference. | Owning layer failure/uncertain. |
| Service terminal body canonicalization/sign | Preserve unsigned body only as diagnostic; it is not terminal. | Supervisor reports missing service terminal and cleanup state. |
| Service after signature before output/EOF/exit | Supervisor accepts only complete envelope then proves key/output/process closure. | Service chain exists only if full envelope validates; supervisor closed/uncertain independently. |
| Supervisor terminal body/sign/output/EOF/exit | Verifier accepts only complete root-valid envelope then proves key/output/process closure. | Supervisor terminal closed/uncertain; no bridge without all proof. |
| Application requester disconnect/crash | Supervisor/service do not await it; complete physical cleanup. The isolated verifier/outer S2b owner commits requester failure or uncertainty and exposes no facade. | Exactly one requester terminal for a completed outer entry; service/supervisor chains independent. |
| Isolated settlement-verifier worker crash | Outer S2b owner observes exact join, closes its endpoint generations, and wins the one-slot requester registry with an uncertain terminal; no facade. | Exactly one requester-uncertain terminal; signed prior chains unchanged. |
| Outer S2b owner/host loss | No protocol can truthfully prove post-loss local execution; recovery accepts no facade and treats the persisted run as externally incomplete. | Outside the completed-entry guarantee; never fabricate or rewrite any terminal. |
| Bridge construction/validation | No service rerun or envelope rewrite. | Requester local failure. |
| Logical callback handler throws at callback `i` | Stop replay, emit exact load-failure receipt with `i` and delivered prefix; close logical facades. | Requester failure; service/supervisor remain success. |
| Logical method reorder/replay/concurrency | First mismatch emits one local failure and terminal closure. | Requester failure only. |
| Operation deadline boundary | Fence normal physical work atomically; enter fixed cleanup window. | Service failure/uncertain unless success candidate already sealed. |
| Cleanup deadline boundary | Stop new cleanup calls; retain exact obligations. | Current closing layer uncertain. |
| PID/handle/FD/server/session numeric reuse | Do not act on foreign generation. | Explicit uncertainty. |

Free-form exception text and stack traces are never receipt authority. Failure codes
are a closed PROPOSED enumeration that must be frozen before implementation.

## Closed canonical codec, schema limits and control framing

All proposed schemas use this exact `canonical-json-v2` codec unless explicitly raw binary:

- NFC strings, no BOM/NUL/surrogates/invalid UTF-8;
- object keys are ASCII member names sorted by unsigned UTF-8 byte order;
  reject duplicates before constructing a map, unknown/missing keys, or whitespace;
- emit quotation mark as `\"`, backslash as `\\`, U+0001..U+001F as lowercase
  `\u00xx` (no short-escape alternatives), and other NFC Unicode scalars as literal
  UTF-8; slash is never escaped. NUL, lone surrogates and invalid UTF-8 reject;
- no floats, exponents, NaN, Infinity, or negative zero;
- JSON integers only in `[-(2^53-1), 2^53-1]`; larger platform values are bounded
  canonical decimal strings;
- maximum depth 16; ordinary control has at most 4,096 total nodes/keys;
  dedicated image/construction/terminal bodies have at most 32,768 nodes/keys;
  ordinary text is <=128 UTF-8 bytes, ASCII path <=1,024 bytes, canonical file URI
  <=4,096 ASCII bytes; transcript payload is raw detached bytes under its own bound;
- lowercase SHA-256 hex exactly 64 characters;
- padded canonical RFC 4648 base64 without whitespace;
- control envelope 1..4,096 canonical bytes and detached ordinary control body
  1..65,536 canonical bytes; large bootstrap/terminal body classes below use only
  their dedicated framed channels, never a larger ordinary control frame; and
- frame
  `u32be(envelopeLen)||envelope||u32be(bodyLen)||body||tag32`, where tag32 is
  HMAC-SHA256(key, LD(D(ControlEnvelopeV2,frame-mac),[envelope,body])). The
  length delimiter already authenticates both lengths; encoded lengths must
  exactly equal the consumed byte counts.

`ControlEnvelopeV2` has these **PROPOSED exact fields**: `authority`,
`schemaVersion`, `planCoreSha256`, `executionBindingSha256`, `hopNamespace`,
`direction`, `messageSequence`, `globalRecordOrdinal` where service-assigned,
`kind`, `bodyByteLength`, `bodySha256`, `previousEnvelopeRecordSha256`, and
`operationDeadlineNs`. EOF inside a frame or bytes after a terminal frame fail.
Transport HMAC integrity is not service provenance.

Every registered schema has exact common members `authority` and `schemaVersion`:
`authority="rtl-reader/native-page/adapter-v2/schema/" + exactSchemaName`,
`schemaVersion=2`. A field list above means the union of these two members and the
listed members, with no duplicated serialized key. Nested named objects also
carry their own exact schema tag. Header `bodySchema` must name that exact tag;
body bytes are detached raw canonical UTF-8, never base64, an escaped JSON string,
or a parsed/reserialized substitute in a signature input.

Scalar types are closed: H=lowercase 64-hex digest; ID=32 random bytes encoded H;
TOK=ASCII `[A-Za-z0-9_.:/-]{1,128}` token; U=exact JSON integer 0..2^53-1;
JI=exact JSON integer -(2^53-1)..2^53-1; U64=decimal string `0|[1-9][0-9]{0,19}`
and <=2^64-1; N=positive decimal string <=2^63-1; SN=canonical signed-decimal
string in signed-int64 range with no plus/leading-zero/negative-zero; B=exact
boolean. Every `*Sha256`/`*KeyId` is H, every nonce/challenge/session/transfer/
acquisition ID is ID unless an earlier fixed token explicitly differs, host `*Ns`
and deadlines use N, sizes/offsets/device clocks use U64, counters/cursors use U.
FileStat timestamp exceptions use SN. Explicit type constraints above take
precedence over suffix classification; no new field may be inferred from a suffix.
Null is allowed only by its listed union arm, never an omitted member or zero hash.
All result/outcome/state/operation/schema enums are exact tokens from this document;
arbitrary strings or inherited/subclass integer/bool aliases reject.

Vectors are bounded and ordered: dependencies<=128 sorted by ordinal+path;
guardian roles exactly target-base-apk/framework/native-module-apk/original-pdf/mark;
transcript refs<=16; slot digests exactly the indicated 11/12/24 or failed prefix;
bulk chunks<=64; physical dispositions exactly seven; callbacks<=2;
acquisition states<=512 in reserved acquisition-ID order, including unused slots;
four namespace hop entries in registry order, each with its per-object cursor.
Sets are encoded as these specified ordered arrays, not unordered JSON maps.

| Size class | Registered members | Canonical body cap | Largest framed representation |
|---|---|---:|---:|
| SMALL | Chunk/AAD/header/ref/offer/accept/grant/ACK/key-confirmation and scalar disposition schemas | 4,096 | Ordinary MAC frame: 8+4096+4096+32 = 8,232 |
| CONTROL | Every remaining registered body not assigned another class | 65,536 | Ordinary MAC frame: 8+4096+65536+32 = 69,672 |
| LARGE | PlanCoreV2, WorkerImagePinV2, ConstructionSettlementBodyV2, ServiceTerminalBodyV2, SupervisorClosureBodyV2, RequesterTerminalBodyV2, VerifierCrashRequesterBodyV2 | 1,048,576 | Dedicated signed envelope: 8+4096+1048576 = 1,052,680 |
| LARGE-SNAPSHOT | AcquisitionSnapshotBodyV2 only, detached and authenticated before reference admission | 2,101,761 | Up to 4,194,304 carrier bytes, 64 bounded chunks; never ordinary control |
| PROJECTION | NativePageCompatibilityProjectionV2 and NativePageCompatibilityFailureProjectionV2 | 131,072 | Local detached bytes exactly <=131,072; never ordinary control payload |
| TRANSCRIPT | Inline payload / bulk complete transcript | 65,536 / 4,194,304 | Inline payload frame: 8+4096+65536+32 = 69,672; bulk chunk same; at most 64 chunks |
| GUARDIAN | Detached file ciphertext chunk | 65,536 | 8+4096+65536+16 = 69,656 |

Enforce both member bounds and encoded body cap before allocating/writing. The
maximum-size fixture of a schema is the deterministic largest accepted member
combination within its encoded cap, not permission for all independent member
maxima to overflow the frame. Each schema's codec fixture includes a maximal
encoded-cap case and a max-member over-cap rejection. Signed header signature is
canonical padded base64 of 64 bytes (88 chars), MAC is 32 bytes (44 chars), public
key is 32 bytes (44 chars). These encodings are INCLUDED in the 4,096-byte header
cap; detached body is not encoded again. Full envelope external digest covers
LD(D(exactEnvelopeType,envelope-hash),[header,body]); binary serialization is
`u32be(headerLen)||header||u32be(bodyLen)||body`. Transport authentication uses its
distinct frame domain; neither hash includes itself.

## Closed schema and domain registry

This registry is a proposed normative candidate, not an implementation certificate.
Every wire type named in this document is a distinct registered schema; the only
non-wire names are the Python API classes `CapabilityEngineV2`,
`ParentCapabilitySessionV2`, `ChildCapabilitySessionV2`, and `FridaProviderV2`.
There are no extension schemas, structural aliases, wildcard subjects, or opaque
JSON `Any` members. A reference is an H digest of already admitted canonical bytes
of the specifically named schema, not permission to supply an arbitrary object.
The named body field lists above, the common header, the typed completions below,
and their closed union rules together define the schema. A contradiction or
unresolved member is an admission blocker, never implementation discretion.

Define, for exact registered schema name T and allowed purpose p:

```text
schema(T) = "rtl-reader/native-page/adapter-v2/schema/" || T
D(T,p)    = "rtl-reader/native-page/adapter-v2/" || T || "/" || p
```

T and p are literal case-sensitive ASCII tokens; neither is caller-selected.
These strings are injective because registered names contain no slash and all end
in V2. Purpose is one of the closed profiles below. No old shared body-hash,
terminal-signature, generic MAC, or undocumented "PROPOSED ... domain" literal is
an accepted alternative. Earlier descriptive domain labels resolve only through
this table; a validator never tries two domains.

| Profile / exact types | Permitted purpose and exact input |
|---|---|
| Every registered non-envelope T | `body-hash`: LD(D(T,body-hash), [canonical(T)]). |
| Every registered envelope T | `envelope-hash`: LD(D(T,envelope-hash), [canonical(metadata), raw_body]); neither contains the resulting hash. |
| Root/supervisor signed envelopes: SupervisorKeyAttestationEnvelopeV2, ExecutionAttestationEnvelopeV2, SupervisorDetachedAttestationEnvelopeV2, ChildStreamKeyAttestationEnvelopeV2, LogicalAttachBindingEnvelopeV2, ServiceTerminalEnvelopeV2, SupervisorClosureEnvelopeV2 | `signature`: the exact tuple in that envelope's section, with this envelope's D(T,signature). Service uses its E-attested Ed25519 key; the root attests only the supervisor per-run key. |
| CapabilityTerminalEnvelopeV2, CapabilityQuiescenceEnvelopeV2, FridaPhysicalSettlementEnvelopeV2, InlineTerminalEnvelopeV2, BulkManifestEnvelopeV2 | `mac`: LD(D(T,mac), [raw(P), raw(E), raw(bodySha256), u64be(bodyByteLength), raw_body]). Key is the lane or terminal-direction key specified for that exact envelope. |
| ControlEnvelopeV2 | `frame-mac`: LD(D(T,frame-mac), [canonical(header), raw_body]); 32-byte HMAC-SHA256 external tag. |
| ServiceGlobalRecordV2 | `record-hash` over [canonical(record)]; `genesis` over [raw(P), raw(E), raw(serviceSessionId)]. |
| BulkChunkHeaderV2 | `record-hash` and `frame-mac` over [canonical(header), raw_chunk]; `genesis` over [raw(P), raw(E), utf8(hopNamespace), u64be(transcriptIndex), raw(transcriptId), raw(dataEndpointBindingSha256), utf8(directionKeyId)]. |
| InlineTranscriptBodyV2 | `record-hash` and `frame-mac` over [canonical(header), raw_transcript]; `genesis` uses the exact bulk-genesis tuple with this distinct T. |
| LaneBindingBodyV2 | `session-id` over [raw(P), raw(serviceSessionId), utf8(lane), raw(laneNonce)]; `key-id` over [raw(laneKey)]. |
| HopFactoryBindingV2 | `key-id` over [raw(hopMasterKey)]. |
| DataEndpointBindingV2 | `key-id`, `hkdf-salt`, `hkdf-info`: exact transport-key derivation below. |
| GuardianKeyContextV2 | `key-id` over [utf8(child or guardian), raw X25519 public key], before context construction; `hkdf-salt`, `hkdf-info`: exact Child/guardian derivation in Child-only stream. |
| TrustAnchorPinV2, SupervisorKeyAttestationBodyV2, ServiceKeyBootstrapReceiptV2 | `key-id` over [utf8(Ed25519), raw 32-byte signing public key], separately typed for root/supervisor/service. |
| GuardianChunkAadV2 | `aead-aad`: LD(D(T,aead-aad), [canonical(AAD body)]). This LD value, not bare JSON, is the AEAD associated-data input. |
| GuardianKeyConfirmationV2 | `key-confirmation`: LD(D(T,key-confirmation), [canonical(confirmation body without tag)]). |
| SettlementAckV2 | body-hash only; exact authenticated framing is SettlementAckEnvelopeV2 under the transfer ACK key. |
| RequesterBridgeBodyV2, LogicalReceiptTemplateV2, LogicalMethodReceiptBodyV2, RequesterTerminalBodyV2, MissingLayerTerminalBodyV2 | Only their distinct `body-hash` profiles; a digest is not provenance. Their authenticated enclosing layer/retained registry provides provenance. |

P is the PlanCoreV2 body hash; A/F are LaneBindingBodyV2 body hashes; E is the
ExecutionBindingBodyV2 body hash. All hash displays are lowercase hex but every
LD digest argument is decoded 32 bytes. No service-provenance MAC profile exists.
Root, service, supervisor, and guardian signing keys cannot be reused as transport
keys. Ed25519 signing keys have distinct retained IDs; X25519 keys are never used
for signatures. Key IDs are themselves typed hashes, not authorization.

For a dynamic transfer let B be canonical DataEndpointBindingV2 and M the exact
32-byte master from its E-bound HopFactoryBinding. Set
`salt=SHA256(LD(D(DataEndpointBindingV2,hkdf-salt),[raw(P),raw(E),B]))`,
`PRK=HKDF-Extract-SHA256(salt,M)`. Independently expand 32 bytes for each literal
purpose `payload`, `settlement-ack`, `terminal` with
`LD(D(DataEndpointBindingV2,hkdf-info),[B,utf8(purpose)])`.
Each key's ID is
`SHA256(LD(D(DataEndpointBindingV2,key-id),[utf8(purpose),key]))`.
Binding B contains the E-bound factory digest, which commits the master key ID,
not any derived key ID/hash, so derivation
does not depend on its output. Derived IDs are carried by subsequent grant/frame/
ACK/terminal records. A factory generation/transfer ID can derive once only;
abandonment permanently burns it.

### Typed completion registry

Notation: H=32-byte lowercase-hex digest, I=fresh 64-hex ID, S=bounded NFC text,
PTH=ASCII canonical absolute path, URI=canonical ASCII file URI, U=exact bounded
JSON nonnegative integer, T=positive signed-int64 decimal-string host time,
BT=positive signed-int64 decimal-string Android BOOTTIME milliseconds,
B=exact boolean, R(T)=digest reference to admitted schema T, V(T,n)=ordered vector
of at most n exact T values, and ? means nullable only under the listed closed arm.
A name ending Sha256 is H (or its explicitly marked nullable arm). Every field
listed here is in addition to the common schema header. Integer aliases/bools,
subclasses in in-process adapters, unknown keys and enum alternatives reject.
Unqualified PID/UID/task/display/count/index are U; process starts, handle native
values, device/inode/ctime nanoseconds use canonical U64 decimal strings.
Every purpose/status/role/operation string is a closed enum from its named section,
not arbitrary S. The per-type encoded class is explicit: SMALL for scalar/reference
receipts, CONTROL for vectors/protocol bodies, LARGE/PROJECTION only as designated
in the size registry. No type may silently promote to a larger channel.

The following previously named foundational types are completed here:

| Exact schema(s), encoded class | Exact fields and domains |
|---|---|
| TrustAnchorPinV2, SMALL | algorithm=Ed25519, publicKey=canonical base64(32 bytes), publicKeySha256:H, policyVersion:U in 1..2147483647. |
| DependencyPinV2, SMALL | ordinal:U in 0..127, canonicalPath:PTH, sha256:H, size:U64, fileIdentitySha256:H, loadDisposition in preloaded-only/retained-load-only. |
| ProcessImagePinV2, CONTROL | role in outer-owner/verifier/supervisor/service, imagePath:PTH, imageSha256:H, fileIdentitySha256:H, dependencyManifestSha256:H, dependencies:V(DependencyPinV2,128), environmentPolicySha256:H, mitigationPolicySha256:H. |
| GuardianImagePinV2, CONTROL | role in target-base-apk/framework/native-module-apk/original-pdf/mark, imagePath:PTH, imageSha256:H, dependencies:V(DependencyPinV2,128), dependencyManifestSha256:H, uid:U, gid:U, supplementaryGroups:ordered unique U[0..16], capabilityMask:U64, selinuxContext:S, credentialPolicySha256:H. |
| ProcessIdentityV2, SMALL | platform in windows/android, pid:U in 1..2147483647, processStartId:U64, bootId:I, imageSha256:H, acquisitionTokenSha256:H. Starts compare only within identical platform/boot ID. |
| JobIdentityV2, SMALL | ownerProcessIdentity:R(ProcessIdentityV2), objectIdentity:R(WindowsObjectIdentityV2), jobGeneration:I, killOnLastClose=true, assignmentPolicySha256:H. |
| AcquisitionTokenV2, SMALL | planCoreSha256:H?, constructionId:I, ownerIdentity:R(ProcessIdentityV2), resourceRole:closed role, acquisitionOrdinal:U in 0..511, generation:I. |
| TargetPolicyV2, CONTROL | serial:S, package:S, component:S, allowedUid:U, documentUri:URI, selectedPageIndex:U, observerSourceSha256:H, requireNonzeroDisplay=true, requireCausalAttach=true, forbiddenOwnerRoles:exact ordered stock-target/pen-worker/pen-guardian/private-adb/service/authority-worker/frida-worker. Static selectors only: no PID/start/acquisition/task/activity/display identity. |
| HostPolicyV2, SMALL | package:S, component:S, packageSha256:H, canvas=[1404,1872], densityDpi=300, rotation=0, stageIndex:U in 0..3, requestedRect:exact four U coordinates, requireNonzeroDisplay=true, requireRetainedGeneration=true. Static policy only: no live session/process/task/activity/display/generation. |
| FilePolicyV2, CONTROL | uriScheme=file, files:exact role-ordered GuardianFilePolicyV2[5], maxTranscriptBytes=4194304, rawDisclosureAllowed=false. |
| GuardianFilePolicyV2, SMALL | role in target-base-apk/framework/native-module-apk/original-pdf/mark, path:PTH, uri:URI, presencePolicy in required/observe-nullable, reviewedContentSha256:H?, maxFileBytes:U64 in 0..1073741824, hardlinkCount=1. Only mark may be observe-nullable; reviewedContentSha256 may be null only when not statically provisioned. Neither null nor nonnull asserts observed presence, absence or descriptor identity. |
| AdapterLimitsV2, SMALL | maxControlHeaderBytes=4096, maxControlBodyBytes=65536, maxTranscriptBytes=4194304, maxTranscripts=16, maxChunkBytes=65536, maxPathBytes=1024, maxUriBytes=4096, maxDependencies=128, maxAcquisitions=512, maxGuardianFileBytes=1073741824, guardianLeaseMs=1000, callbackCountMax=2, cleanupTotalNs="250000000", cleanupCallMaxNs="25000000". |
| StabilityPolicyV2, CONTROL | policyId=native-page-visual-fixed-v2, comparedFields:exact ordered tokens defined below, permittedDriftFields:empty vector, requireSameRawPageTriplet=true. |
| StabilityResultV2, CONTROL | planCoreSha256:H, executionBindingSha256:H, policySha256:H, beforeEvidenceMapSha256:H, afterEvidenceMapSha256:H, comparisons:V(StabilityComparisonV2,64), passed:B. Every policy field occurs once in order; passed iff every comparison equal. |
| StabilityComparisonV2, SMALL | field:exact policy token, beforeValueSha256:H, afterValueSha256:H, equal:B; equal iff the typed canonical values and hashes match. |
| ToolBundleSubjectV2, CONTROL | bundleId:I, retainedRootIdentitySha256:H, manifestSha256:H, dependencies:V(DependencyPinV2,128), verifiedAll=true, providerReceiptSha256:H. |
| PrivateAdbSubjectV2, SMALL | serial:S, serverProcessIdentity:R(ProcessIdentityV2), serverPort:U in 1..65535, socketIdentitySha256:H, bundleManifestSha256:H, sessionId:I, providerReceiptSha256:H. |
| FileStatV2, SMALL | Exact earlier guardian field set: device/inode/mode/uid/gid/nlink/size/blocks/blockSize:U64; mtimeNs/ctimeNs:SN; statSerializationVersion=2. No added linkCount/mountId aliases. |
| FileUriBindingV2, CONTROL | Exact earlier guardian field set: canonicalUriUtf8:URI, canonicalUriSha256:H, scheme=file, authorityEmpty=true, queryAbsent=true, fragmentAbsent=true, decodedAbsolutePathUtf8:PTH, decodedPathSha256:H, pathResolutionReceiptSha256:H, descriptorDevice/descriptorInode:U64. |
| EvidenceMapV2, CONTROL | phase in before/after, mapKind in prior-seal/final-snapshot/failed-prefix, firstSlot:U in 0..23, lastSlot:U in 0..23, orderedEntries:V(EvidenceMapEntryV2,12). No dynamic object member map. |
| EvidenceMapEntryV2, SMALL | slot:U in 0..23, operationToken:exact slot token, payloadSchema:exact slot schema token, payloadSha256:H, slotRecordSha256:H. |
| ParsedAuthorityV2, CONTROL | planCoreSha256:H, executionBindingSha256:H, phase in before/after, evidenceMapSha256:H, targetPolicySha256:H, hostPolicySha256:H, filePolicySha256:H, parsedTranscriptRefs:V(TranscriptRefV2,16), parserImageSha256:H, parserPolicySha256:H, accepted=true. |
| TranscriptRefSetV2, CONTROL | planCoreSha256:H, executionBindingSha256:H, refs:V(TranscriptRefV2,16). Strict global admission order; no duplicate index/ID. |
| SpoolIdentityV2, SMALL | ownerIdentity:R(ProcessIdentityV2), objectIdentity:R(WindowsObjectIdentityV2), acquisitionTokenSha256:H, generation:I, maxBytes=4194304, encrypted=true, deleteOnClose=true. |
| LaneControlTransportV2, CONTROL | parentSend:R(WindowsObjectIdentityV2), childReceive:R(WindowsObjectIdentityV2), childSend:R(WindowsObjectIdentityV2), parentReceive:R(WindowsObjectIdentityV2), endpointPolicySha256:H. Four exact distinct rights-reduced identities. |
| CapabilityBindingBodyV2, CONTROL | planCoreSha256:H, executionBindingSha256:H, laneBodySha256:H, factoryId:exact factory, sessionId:I, epochId:I, workGateSha256:H, resourceBindingSha256:H, operationDeadlineNs:T. |
| OperationLeaseV2, SMALL | capabilityBindingSha256:H, operationId:I, operationToken:exact factory token, cursor:U, absoluteDeadlineNs:T, startPermitNonce:I, consumed:B. No raw v1 permit or callable. |
| DetachedPayloadV2, SMALL | payloadSchema:exact admitted schema, payloadByteLength:U in 1..65536, payloadSha256:H, operationReceiptSha256:H. Raw bytes follow separately, never JSON-embedded. |
| DetachedBulkReferenceV2, SMALL | transcriptRefSha256:H, terminalEnvelopeSha256:H, operationReceiptSha256:H, canonicalByteLength:U in 65537..4194304. |
| LogicalFailurePolicyV2, SMALL | policyId=receipt-only-no-retry-v2, callbackDeliveryDeadlineNs:T, allowedMethods:exact normal/failure method table, failureCodeRegistrySha256:H, failClosed=true. |
| CallbackDeliveryAckV2, SMALL | planCoreSha256:H, executionBindingSha256:H, bridgeSha256:H, logicalOperationId:I, callbackIndex:U in 0..1, callbackRecordSha256:H, publicationGeneration:I, isolatedReceiverIdentity:R(ProcessIdentityV2), result in returned/raised/disconnected/timed-out/reentrancy, acceptedMonotonicNs:T. Only returned before deadline permits the next callback. |
| RemainingEmitterStateV2, CONTROL | emitterLayer in service/supervisor/verifier, emitterIdentity:R(ProcessIdentityV2), outputAcquisitionSha256:H, signingKeyAcquisitionSha256:H, processAcquisitionSha256:H, nextObserverIdentity:R(ProcessIdentityV2). Never claims its own future exit. |
| AcquisitionReservationV2, SMALL | planCoreSha256:H?, constructionId:I, token:R(AcquisitionTokenV2), expectedKind:acquisition kind, expectedRole:closed role, ownerIdentity:R(ProcessIdentityV2), absoluteDeadlineNs:T. No resource identity before actual acquisition. |
| AcquisitionResultV2, SMALL | contextPhase:pre-plan/pre-E/post-E, constructionId:I, planCoreSha256:H?, executionBindingSha256:H?, reservationSha256:H, result in acquired/not-acquired/uncertain, identitySchema:exact resource schema?, identitySha256:H?, acquisitionReceiptSha256:H?, capturedMonotonicNs:T. acquired requires all three; not-acquired requires all null plus reservation-derived proof in enclosing owner chain; uncertain never authorizes action. |
| CleanupExpiryReceiptV2, CONTROL | planCoreSha256:H, executionBindingSha256:H?, cleanupDeadlineNs:T, observedMonotonicNs:T, operationName:closed cleanup token, operationStarted:B, acquisitionSnapshotRef:AcquisitionSnapshotRefV2, nextRecoveryOwnerIdentity:R(ProcessIdentityV2), outcome=cleanup-deadline-uncertain. E null only in construction settlement. |
| PublicationUncertainReceiptV2, SMALL | planCoreSha256:H?, constructionId:I, intendedSchema:exact terminal schema, intendedBodySha256:H?, lastDurableCheckpointSha256:H?, publicationState in not-attempted/partial/acknowledgement-missing, responsibleOwnerIdentity:R(ProcessIdentityV2), outcome=uncertain. No field asserts that this receipt itself was durably written. |

Closed stability tokens are, in order: serial, target-process, target-task,
target-activity, host-process, host-task, host-activity, host-apk, host-session,
host-display, host-generation, private-adb, pen-lease, observer, pdf-path,
pdf-descriptor, pdf-content, mark-presence, mark-path, mark-descriptor, mark-content,
framework-descriptor, framework-content, module-descriptor, module-content,
raw-current-page, raw-page-info-page, raw-presenter-page.
The three raw page fields must remain equal between phases; they are not asserted
equal to the zero-based selected page. Calibration remains blocked.

### Complete signed-envelope LD tuples

Let B be the separately transported canonical body bytes, H its typed body hash,
N=u64be(len(B)), KID=utf8(the exact metadata signing key ID, 64 lowercase hex
characters), P/E decoded 32-byte hashes and CID decoded constructionId.
All Ed25519 signatures are exactly 64 bytes, encoded canonical padded base64.
These are the COMPLETE part lists, in order, under D(exactEnvelope,signature):

| Exact signed envelope | Body | Key authority | Exact LD parts |
|---|---|---|---|
| SupervisorKeyAttestationEnvelopeV2 | SupervisorKeyAttestationBodyV2 | Provisioned supervisor root | [P,KID,raw(H),N,B] |
| PBoundObservationEnvelopeV2 | ServiceBootstrapResumeReceiptV2 / ServiceBootstrapEffectReceiptV2 / ServiceKeyBootstrapReceiptV2, closed bodySchema union | P-attested supervisor per-run key | [P,KID,raw(H),N,B] |
| ExecutionAttestationEnvelopeV2 | ExecutionBindingBodyV2 | P-attested supervisor per-run key | [P,E,KID,raw(H),N,B] |
| SupervisorDetachedAttestationEnvelopeV2 | SupervisorDetachedAttestationBodyV2 | E-attested supervisor per-run key | [P,E,KID,raw(H),N,B] |
| ChildStreamKeyAttestationEnvelopeV2 | ChildStreamKeyAttestationBodyV2 | E-attested supervisor per-run key | [P,E,KID,raw(H),N,B] |
| GuardianStreamKeyAttestationEnvelopeV2 | GuardianStreamKeyAttestationBodyV2 | E-attested supervisor per-run key | [P,E,KID,raw(H),N,B] |
| LogicalAttachBindingEnvelopeV2 | LogicalAttachBindingV2 | E-attested supervisor per-run key | [P,E,KID,raw(H),N,B] |
| ServiceTerminalEnvelopeV2 | ServiceTerminalBodyV2 | E-attested service key | [P,E,KID,raw(H),N,B] |
| SupervisorClosureEnvelopeV2 | SupervisorClosureBodyV2 | E-attested supervisor per-run key | [P,E,KID,raw(H),N,B] |
| ConstructionSettlementEnvelopeV2 | ConstructionSettlementBodyV2 | Externally pinned outer key, binds P | [P,KID,raw(H),N,B] |
| PrePlanAbortEnvelopeV2 | PrePlanAbortBodyV2 | Externally pinned outer key, no P/E | [CID,KID,raw(H),N,B] |
| PrePlanCleanupExpiryEnvelopeV2 | PrePlanCleanupExpiryReceiptV2 | Externally pinned outer key, no P/E | [CID,KID,raw(H),N,B] |

No envelope adds/removes a part or signs a hex spelling where raw is specified.
Subject kind/challenge/identity are protected by exact body bytes/hash; no parallel
undocumented signature suffix exists. BodySchema is fixed by the pairing/closed
union and metadata hash/length must match the raw body before signature verify.
The envelope hash always uses its own envelope-hash domain over metadata and B.
PBoundObservationEnvelopeV2 exact metadata fields: P, bodySchema, bodyByteLength,
bodySha256, signatureAlgorithm=Ed25519, signingKeyId,
supervisorKeyAttestationSha256, signature; no E member.
PrePlanAbortEnvelopeV2 and PrePlanCleanupExpiryEnvelopeV2 use constructionId,
bodySchema,bodyByteLength,bodySha256,signatureAlgorithm=Ed25519,signingKeyId,
outerTrustAnchorSha256,signature; no P/E member.
ConstructionSettlementEnvelopeV2 replaces constructionId in this metadata with P
(the construction ID is inside its body), with the same outer trust anchor field.

PreAttachSelectorCommitV2 exact fields: P,E,fridaLaneBodySha256,
liveTargetBindingSha256,liveHostBindingSha256,targetPolicySha256,
targetProcessIdentitySha256,fridaServerProcessIdentitySha256,
fridaServerSessionId,observerSourceSha256,physicalOperationId,
selectorChallenge,supervisorObservedNs,operationDeadlineNs.
It is a supervisor-attested prior-only body with no attach/load/result receipt.
LogicalAttachBindingV2 follows actual attach plus a fresh selector; it cannot be
substituted by this earlier commit.

PrePlanCleanupExpiryReceiptV2 is separate from CleanupExpiryReceiptV2.
Exact fields: constructionId,outerOwnerIdentitySha256,outerTrustAnchorSha256,
cleanupReservationSha256,constructionCursor,settlementDeadlineNs,observedHostNs,
completedConstructionPrefixSha256,acquisitionSnapshotRef,
firstFailure,outcome=pre-plan-cleanup-uncertain.
P/E fields are forbidden. The reference must be pre-plan and construction-ID-equal.
The outer owner signs its distinct envelope and then PrePlanAbortBodyV2 commits
prePlanCleanupExpiryEnvelopeSha256 (null iff expiry never occurred). Thus the
expiry receipt precedes the abort; it never references the abort's future digest.
If publication cannot be proved, PublicationUncertainReceiptV2 binds the same
construction reservation, never claims successful persistence or adds invented P.

### Receipt and envelope completion profiles

The exact observation receipt schemas CloseReceiptV2, JoinReceiptV2,
JobEmptyReceiptV2, EndpointHalfCloseReceiptV2, EndpointEofReceiptV2,
EndpointCloseReceiptV2, KeyDestructionReceiptV2, OwnerQuiescenceReceiptV2,
PathResolutionReceiptV2 and SameFdReceiptV2 use
the following fixed field set, with distinct schema tags and closed subject/effect
rules: planCoreSha256:H, executionBindingSha256:H?, reservationSha256:H,
subjectIdentitySchema:exact registered identity schema, subjectIdentitySha256:H,
observerIdentity:R(ProcessIdentityV2), observerReceiptSha256:H?,
previousReceiptSha256:H?, observationKind:exact literal named below,
capturedMonotonicNs:T?, capturedDeviceBoottimeMs:BT?, result in proved/uncertain,
detailSha256:H?. Exactly one clock field is nonnull, selected by observer platform.
E may be null only under the P-rooted construction branch. An observation producer
never attests its own later close/join. First receipt predecessor is null, later
predecessor is exact. No result=proved without the independent platform observation.

| Type | Exact observationKind / typed detail requirement |
|---|---|
| CloseReceiptV2 | handle-closed / WindowsObjectIdentityV2 or GuardianFdIncarnationV2; no detail. |
| JoinReceiptV2 | process-joined / ProcessIdentityV2; detail is ExitObservationV2. |
| JobEmptyReceiptV2 | job-empty / JobIdentityV2; detail is empty JobMemberSetV2. |
| EndpointHalfCloseReceiptV2 | send-half-closed / WindowsObjectIdentityV2; peer identity is retained in DataEndpointBindingV2. |
| EndpointEofReceiptV2 | receive-eof-drained / WindowsObjectIdentityV2; detail is StreamEndObservationV2 with zero trailing bytes. |
| EndpointCloseReceiptV2 | endpoint-closed / WindowsObjectIdentityV2; no detail. |
| KeyDestructionReceiptV2 | key-destroyed / AcquisitionTokenV2; detail is KeyDestructionObservationV2. |
| OwnerQuiescenceReceiptV2 | owner-quiescent / ProcessIdentityV2; detail is zero OwnerActivityObservationV2. |
| GuardianProcessClosureReceiptV2 | Not part of this profile: retains the exact dedicated supervisor-authored field set in Device-side retained descriptor guardian. |
| PathResolutionReceiptV2 | path-resolved / GuardianFdIncarnationV2 of retained directory; detail is PathResolutionObservationV2. |
| SameFdReceiptV2 | same-fd / GuardianFdIncarnationV2; detail is SameFdObservationV2. |

All details are SMALL except CONTROL JobMemberSetV2/PathResolutionObservationV2.
Their exact fields are: ExitObservationV2 {exitCode:U, signal:U?, joined=true};
JobMemberSetV2 {members:V(ProcessIdentityV2,8)};
StreamEndObservationV2 {byteCount:U64, finalRecordSha256:H?, trailingByteCount=0};
KeyDestructionObservationV2 {keyId:H, generation:I, destroyed=true,
remainingAliasCount=0}; OwnerActivityObservationV2 {activeOperationCount=0,
inFlightCallbackCount=0, openTransferCount=0, normalIngressSealed=true};
PathResolutionObservationV2 {canonicalPath:PTH, anchorIdentitySha256:H,
ancestorIdentities:ordered H[1..32], componentCount:U in 1..32,
nofollow=true, noXdev=true, beneath=true, finalStatSha256:H};
SameFdObservationV2 {fdAcquisitionReceiptSha256:H, beforeStatSha256:H,
afterStatSha256:H, beforeOffset:U64, afterOffset:U64, sameGeneration=true}.
Uncertain observations retain subject/observer/deadline evidence but detail is null
unless that exact partial detail was independently observed; they prove no closure.

MissingServiceTerminalReceiptV2 is a distinct wrapper, not an alias:
{planCoreSha256:H, executionBindingSha256:H, missingLayerReceiptSha256:R(MissingLayerTerminalBodyV2), serviceIdentity:
R(ProcessIdentityV2), supervisorIdentity:R(ProcessIdentityV2), outcome=uncertain}.
It may reference only missingLayer=service. VerifierCrashRequesterBodyV2 has exact
fields planCoreSha256:H, executionBindingSha256:H, serviceObservation:
ServiceObservationV2, missingVerifierReceiptSha256:R(MissingLayerTerminalBodyV2),
verifierAcquisitionState:AcquisitionStateV2, registryGeneration:I,
lastLogicalReceiptSha256:H?, outerOwnerIdentity:R(ProcessIdentityV2),
cleanupDeadlineNs:T, requesterOutcome=uncertain, terminal=true.

Every signed/MAC envelope uses SMALL metadata and a separate raw body. The exact
metadata is the field list already specified for that named envelope; where not
previously specified, it is {planCoreSha256:H, executionBindingSha256:H?,
bodySchema:the single designated body tag, bodyByteLength:U,
bodySha256:H, algorithm:fixed Ed25519 or HMAC-SHA256, keyId:H,
keyAttestationSha256:H?, signatureOrTag:canonical base64}. Concrete schemas use
exactly one fixed algorithm and one exact body pairing: SupervisorKeyAttestation
(root, no E); ChildStreamKeyAttestation and LogicalAttachBinding (supervisor,
E required); CapabilityTerminal/CapabilityQuiescence (lane HMAC, E required);
InlineTerminal/BulkManifest (transfer terminal HMAC, E required).
For HMAC keyAttestationSha256 is the exact E-bound lane/factory digest, not null;
for signatures it is the earlier root/per-run attestation. Encoded base64 is
strict RFC 4648 padded standard alphabet, no whitespace/noncanonical pad bits.
Metadata `body`, nested body copies and recursive envelope fields are forbidden.

### Bootstrap, operation and terminal registry completions

These exact SMALL bodies use the common header. FirstFailureV2 fields are
layer (construction/authority/frida/guardian/transcript/service/supervisor/requester),
state:exact state-machine token, operation:exact operation token or null before
dispatch, cursor:U, code:exact code below, evidenceSchema:registered schema or null,
evidenceSha256:H or null, observedHostNs:T, retryable=false.
Evidence schema/hash are both null or both nonnull; no exception text/raw bytes.
Closed codes are invalid-schema, invalid-identity, invalid-provenance, replay,
out-of-order, deadline-expired, clock-invalid, not-created, acquisition-uncertain,
bootstrap-invalid, gate-unavailable, peer-unavailable, malformed-frame, trailing-data,
hash-mismatch, callback-failed, callback-timeout, callback-reentrancy, closure-unproved,
publication-uncertain, forbidden-operation, and internal-invariant.
The first independently observed failure wins; later cleanup failures are separate
acquisition observations, never a rewrite of firstFailure or a retry.

PrePlanAbortBodyV2 exact fields: constructionId:I, outerOwnerIdentity:
R(ProcessIdentityV2), outerImageSha256:H, constructionCursor:exact construction
token, acquisitionSnapshotRef:AcquisitionSnapshotRefV2, firstFailure:FirstFailureV2,
settlementDeadlineNs:T, observedNs:T, prePlanCleanupExpiryEnvelopeSha256:H?,
outcome in settled-abort/retained-uncertain.
Its class is LARGE. There is no P/E field. Its ConstructionSettlementEnvelopeV2
sibling is P-rooted; PrePlanAbortEnvelopeV2 instead binds the construction ID and
externally provisioned outer-root key. Both use separate Ed25519 envelope signature
domains, and their bodies have distinct schemas and external hashes. The exact
outer trust anchor/image must be provisioned to the verifier before any construction;
PlanCore includes those same pins. This is not self-authentication by the document.

ProcessResumeReceiptV2 exact fields: planCoreSha256:H, executionBindingSha256:H,
assignmentReceiptSha256:H, bootstrapResumeAuthorizationSha256:H,
processIdentity:R(ProcessIdentityV2), jobIdentity:R(JobIdentityV2),
preSuspended=true, postSuspended:B, resumeGeneration:I,
capturedMonotonicNs:T, outcome in resumed-bootstrap-only/uncertain.
BootstrapResumeReceiptV2 is the pre-resume authorization; this post-syscall receipt
is its observed effect. BootstrapValidationReceiptV2 names the latter receipt.
No successful validation can be inferred from a resume result.

ServiceKeyBootstrapReceiptV2 exact fields: planCoreSha256:H,
serviceBootstrapEffectReceiptSha256:H, serviceImageSha256:H, serviceProcessIdentity:R(ProcessIdentityV2),
jobIdentity:R(JobIdentityV2), zeroAuthorityHandleSetSha256:H,
servicePublicKey:canonical base64(32), serviceKeyId:H,
signingHandleIdentitySha256:H, nonexportable=true, executionGateIdentitySha256:H,
outcome in bootstrap-waiting/uncertain. No E or lane/future gate digest.
CONTROL BootstrapResume/WorkGate/GuardianLease bodies are authenticated as exact
subjects of SupervisorDetachedAttestationEnvelopeV2; their attestationKind is the
exact subject schema name. The attestation refers to the already-created body,
not the body's future envelope hash. Validation receipts use the pinned bootstrap
control MAC followed by a distinct supervisor observation.

GuardianStreamKeyAttestationBodyV2 (SMALL) exact fields: planCoreSha256:H,
executionBindingSha256:H, authorityLaneBodySha256:H,
guardianProcessIdentity:R(ProcessIdentityV2), guardianImageManifestSha256:H,
guardianSessionId:I, childProcessIdentity:R(ProcessIdentityV2), childSessionId:I,
childChallenge:I, fileRole:exact guardian role, phase in before/after,
readEpoch:U in 0..1, fdAcquisitionReceiptSha256:H,
guardianStreamPublicKey:canonical base64(32), keyId:H, workGateSha256:H,
supervisorObservedNs:T, operationDeadlineNs:T.
GuardianStreamKeyAttestationEnvelopeV2 is supervisor-signed with the exact
common signed-envelope profile. It contains no Child key-attestation digest:
both key attestations depend on prior independent challenges/acquisition receipts,
then GuardianKeyContextV2 commits both. This avoids a reciprocal signature cycle.
Guardian process/image/credential attestation precedes FD reservation; its subject
is GuardianProcessSubjectV2 (CONTROL): guardianSessionId:I, processIdentity:
R(ProcessIdentityV2), imagePinSha256:H, credentialPolicySha256:H, rolePolicySha256:H,
bootId:I, transportBindingSha256:H, challenge:I. It contains no future stream key.
GuardianTransportBindingV2 (CONTROL) fields: planCoreSha256:H,
executionBindingSha256:H, guardianSessionId:I, guardianProcessIdentity:
R(ProcessIdentityV2), authorityChildIdentity:R(ProcessIdentityV2),
deviceTransportFactorySha256:H, hostRelayFactorySha256:H,
rolePolicySha256:H, immutableOwnerBoundaryReceiptSha256:H.
Dynamic inner epochs then bind their exact two-hop acquisition/offer/ACK/close
records. No process attestation includes a transport receipt that includes itself:
the transport binding commits already-observed process identity, not its future
GuardianProcessSubject attestation hash.

EndpointAcceptV2 exact names: planCoreSha256:H, executionBindingSha256:H,
offerReceiptSha256:H, transferId:I,
senderProcessIdentity:R(ProcessIdentityV2), retainedDuplicateIdentitySha256:H,
offerNonce:I, accepted=true. EndpointFirstWriteGrantV2 exact names:
planCoreSha256:H, executionBindingSha256:H, dataEndpointBindingSha256:H, transferId:I, offerReceiptSha256:H,
acceptReceiptSha256:H, grantOrdinal=0.
TranscriptAbandonmentV2 (CONTROL): planCoreSha256:H, executionBindingSha256:H,
reservationSha256:H, transcriptIndex:U in 0..15, firstFailure:FirstFailureV2,
acquisitionSnapshotRef:AcquisitionSnapshotRefV2, outcome=abandoned, terminal=true.
TranscriptForwardReceiptV2 (SMALL): planCoreSha256:H, executionBindingSha256:H,
transcriptRefSha256:H, routeIndex:U in 1..2, hopNamespace:exact selected route token,
previousHopTerminalEnvelopeSha256:H, nextHopTerminalEnvelopeSha256:H,
forwardedCanonicalByteLength:U in 1..4194304, forwardedTranscriptSha256:H.
TranscriptHopClosureV2 (CONTROL): planCoreSha256:H, executionBindingSha256:H,
transcriptRefSha256:H?, reservationSha256:H, routeIndex:U in 0..2,
hopNamespace:exact route token, terminalEnvelopeSha256:H?,
sendEndpointState:AcquisitionStateV2, receiveEndpointState:AcquisitionStateV2,
payloadKeyState:AcquisitionStateV2, ackKeyState:AcquisitionStateV2,
terminalKeyState:AcquisitionStateV2, masterKeyState:AcquisitionStateV2,
spoolState:AcquisitionStateV2, independentObserverReceiptSha256:H,
outcome in closed/uncertain. Reference is null iff admission never occurred;
terminal is null iff no complete authenticated terminal was emitted. Master-key
final closure is one owner-factory observation after all objects, referenced by
each relevant hop; repeated references are not duplicated acquisitions.

A transfer's receiver destroys its payload verification key after exact EOF/hash
validation and before its ACK. SettlementAckV2 additionally requires
receiverPayloadKeyDestructionReceiptSha256:H. The sender destroys its own payload
key after authenticating that ACK. Both sides' ACK/terminal keys and control
endpoints are then settled under next-layer observations; no terminal validates
itself under a destroyed terminal key.

InlineTerminalEnvelopeV2 and BulkManifestEnvelopeV2 have exactly the common
header plus planCoreSha256:H, executionBindingSha256:H, bodySchema:their one
corresponding body tag, bodyByteLength:U, bodySha256:H, authorIdentity:
R(ProcessIdentityV2), dataEndpointBindingSha256:H, algorithm=HMAC-SHA256,
keyId:H, keyAttestationSha256:R(HopFactoryBindingV2), signatureOrTag:base64(32).
This explicit profile, not the generic envelope default, includes sender/binding.
ConstructionSettlementEnvelopeV2 and PrePlanAbortEnvelopeV2 use the signed default
with respectively P/non-E and constructionId/non-P/non-E metadata; their external
outer-root attestation digest is required. Their unique domains are
D(exactEnvelopeName,signature) and D(exactEnvelopeName,envelope-hash).
The same unique supervisor signature domain rule registers
GuardianStreamKeyAttestationEnvelopeV2. No implicit extra crypto algorithm exists.

### Registry semantic completion tables

These rules are mandatory field definitions, not discretionary implementation
fallbacks. The one-row schema index below includes these context/type completions.

orchestrationPolicy is O(OrchestrationPolicyV2), with its exact common header and
fields {visualOnly:true,retryAllowed:false,
brokerCount:1,laneCount:2,authoritySlotCount:24,fridaCompositeCount:1,
requireExactClosure:true,physicalOrder:["before","frida","after"]}.
No extra member, integer-bool alias, other order or additional physical stage.
Rectangles are exactly [x,y,width,height] of four exact integers, x/y>=0,
width/height>0, all <=2147483647, checked sums inside the canvas. Host policy and
placement use this same coordinate order; no right/bottom or object alternative.

callbackPolicy is none or isolated-two-records, the latter only on load.
callbackRange is null for non-load and [firstIndex,lastExclusive] for load, with
0<=firstIndex<=lastExclusive<=2 and lastExclusive-firstIndex=deliveredCallbackCount.
A zero delivered prefix is [0,0], never null after load dispatch. callbackIndex is
null for non-callback failures; for callback-failed/callback-timeout/
callback-reentrancy it is the first incomplete index 0..1. LogicalFailureBodyV2.code
uses exactly FirstFailureV2's closed code registry. LocalFailureMappingV2's
publicFailureCode is exactly one frozen runner class name:
GraphRunnerError/HardwareAdmissionBlocked/DeadlineExceeded/SnapshotRejected/
ProviderQuiescenceFailure/AuthorityProviderQuiescenceFailure/
FridaProviderQuiescenceFailure/AuthorityReceiptFailure. Field/method-specific
mapping is pinned by the bridge templates and cannot demote quiescence uncertainty.

| successPhysicalBindingKind | Exact reference target |
|---|---|
| authority-admission / frida-admission | AdmissionProjectionV2 with exact provider |
| stage-before / stage-after | StageProjectionV2 with exact phase |
| logical-attach | LogicalAttachBindingV2 |
| frida-settlement | FridaPhysicalSettlementEnvelopeV2 |
| callback-seal / script-unload / session-detach | FridaPhysicalStepReceiptV2 with exact step token |
| physical-closure | PhysicalClosureProjectionV2 |
| local-closure | RequesterTerminalBodyV2 predecessor proof only; no self/future terminal |

WindowsObjectIdentityV2.objectKind is process/thread/job/pipe-read/pipe-write/
key/store/spool/gate/drain. grantedRights is a nonempty unique lexically ordered
array of tokens read/write/synchronize/query/duplicate/terminate/assign/read-control;
the closed acquisition role policy fixes the exact allowed subset (never ALL_ACCESS).
inheritanceDisposition is noninheritable. duplicateOrdinal=0 denotes original:
sourceObjectIdentitySha256 and duplicatedIntoPid null. A duplicate has positive
ordinal, nonnull source and destination PID, exact destination process-start identity
inside creationReceiptSha256, same underlying object and no rights amplification.
Numerically equal handles across owners never alias these identities.

Resource roles are the finite product of owner role
outer/verifier/supervisor/service/authority-child/frida-child/guardian/callback
and resource role process/thread/job/signing-key/stream-key/payload-key/ack-key/
terminal-key/control-send/control-receive/data-send/data-receive/file-fd/directory-fd/
spool/store/gate/drain. Guardian role additionally binds exactly one of the five
fileRole tokens; stream/hop roles bind the already reserved hop/epoch. The wire
resourceRole is exactly owner-role + one ASCII colon + resource-role from the
finite Cartesian product listed above. This is a closed enum, not a parser for
arbitrary concatenation. The guardian fileRole and hop/epoch remain bound by the
reserved identity and its immutable acquisition table, not by an optional suffix;
 table membership/ordinal is checked before reserve.
resourceKind→identitySchema is process→ProcessIdentityV2; job→JobIdentityV2;
endpoint→WindowsObjectIdentityV2 or GuardianEndpointIdentityV2 according to platform;
key→AcquisitionTokenV2 plus the separately attested key ID; fd/directory-fd→
GuardianFdIncarnationV2; spool→SpoolIdentityV2. firstUncertainty is FirstFailureV2
or null, never an untyped diagnostic. AcquisitionReservation expectedRole/kind
must match its exact table row. Receipt proof of not-created is independent of
publication absence.

GuardianEndpointIdentityV2 exact fields: ownerProcessIdentitySha256,
guardianSessionId,deviceBootId,nativeFd:U64,generation:I,
direction in send-only/receive-only,device:U64,inode:U64,
acquisitionReceiptSha256:H,noninheritable=true.
It is a scalar identity nested only in a P/E-bound retained observation, never
accepted standalone. No Windows handle type may masquerade as this device FD.

BootstrapResumeReceiptV2.outcome is authorized/uncertain; ProcessResumeReceipt
proves the actual effect, so authorization does not assert a resumed process.
JobAssignmentReceiptV2.receiptOutcome is assigned/uncertain; only assigned plus
the independent exact membership query permits resume. LaneNeverStartedReceiptV2
epochAdmissionState is not-admitted/revoked/uncertain; outcome is closed-failure/
uncertain. Not-created requires processCreated=false and null assignment/join,
but independently proved endpoint/key not-created/closed states remain mandatory.
Created-but-never-admitted requires exact assignment/close/join or uncertainty;
resumed=false is true only if no bootstrap resume occurred. A bootstrap-resumed
but work-never-admitted lane uses a started unquiesced/missing closure, never this
never-started body. All body fields exist even when their permitted value is null.

GuardianReadEpochTerminalBodyV2.outcome is read-complete/read-failed/read-uncertain.
Complete requires the exact byte/count/EOF/stat/confirmations/both-hop proofs.
Failed/uncertain bodies contain only complete observed prefix fields; any absent
proof is null and cannot be consumed as file digest authority. GuardianCloseBodyV2
closeOutcome is closed/uncertain; GuardianProcessClosureReceiptV2.outcome is
proved-closed/uncertain; GuardianHopTerminalBodyV2.outcome is closed/uncertain.
Closed requires every named close/EOF/key proof; uncertain preserves the prefix
and snapshot and never supplies placeholder zero hashes.
previousReadEpochTerminalSha256 is null at BEFORE readEpoch=0 and exact accepted
BEFORE terminal at AFTER readEpoch=1. previousAbsenceBodySha256 is null for BEFORE,
exact accepted BEFORE absence for AFTER. No third epoch or phase inversion.

PhaseOpenEvidenceV2.phasePredecessorRootSha256 is null at BEFORE and the exact
BEFORE phase root at AFTER; AFTER also requires its exact Frida barrier/settlement.
EvidenceMapV2.failed-prefix uses firstSlot=null,lastSlot=null when entries is empty;
otherwise both are exact first/last included slot (not next cursor). Other map kinds
require their fixed nonempty ranges.

AuthoritySnapshotFailureReceiptV2 masks are defined by independently accepted
prefixes, not the event that happened to raise an exception:
beforePhaseRoot exists iff slot 11 was accepted; fridaBarrier and settlement exist
iff their authenticated barrier was accepted; afterPhaseRoot exists iff slot 23
was accepted. A later failure never backfills these. firstFailureSlot is null for
non-slot/control/closure failure, else the failed slot in 0..23, which is not in
completedSlotRecordDigests. That list is exactly slots [0,brokerSlotCursorAtFailure).
partialEvidenceMapSha256 always names a typed failed-prefix map, including the empty
map. stabilityResultSha256 is nonnull iff comparison actually produced a complete
typed result; never infer comparison from cursor alone. Frida composite closure
and lane closure are finalization observations required after failure and not
treated as completed normal slot evidence. Each of the BEFORE/barrier/AFTER/stability
booleans is derived from that authenticated prefix; inconsistent masks reject.

FridaPhysicalStepReceiptV2.outcome is step-success/step-failure/step-uncertain.
The seven fixed dispositions attach/selector/load/callbacks/seal/unload/detach
each have succeeded/failed/uncertain/not-reached. A succeeded disposition requires
one exact step receipt and its result; failed/uncertain requires its attempted
step receipt plus firstFailure and only complete observed result prefix;
not-reached requires both receipt/result null. Later cleanup steps may be attempted
after earlier failure but never change earlier disposition. Physical settlement's
attach/selector/load/callback/seal/unload/detach fields exactly mirror those seven
masks. callback count/root/ref are null/0/null before a complete callback transcript,
and callback outcome alone cannot prove unload/detach. observerResultCode is
success or a token from the fixed FirstFailureV2 code registry.
resultBindingSha256 targets: attach/selector→SelectorSubjectV2;
load→PreAttachSelectorCommitV2 plus exact loaded-source proof in the step body;
callbacks→TranscriptRefV2; seal/unload/detach→OwnerQuiescenceReceiptV2 with step
subject identity and only that step's effect (not whole-owner cleanup).

ServiceTerminalBodyV2.physicalSuccessCandidateSealedNs is nonnull only if a complete
candidate was sealed before original deadline; service failure may preserve that
valid candidate time but cannot invent it. Success requires it nonnull.
Supervisor missing/unobserved predecessor arms require absent service-envelope/
provenance-verification fields null. Each EOF/key-close/join/job-empty field is
nonnull iff an independent proved observation exists, whether or not an envelope
was received; missing/uncertain observation is represented in the acquisition
snapshot, never by a success receipt. closureOutcome cannot be success if any
required proof is null. Requester mirrors these rules for supervisor observations.
Bridge fields are both nonnull only after complete bridge construction+validation;
constructed-but-unvalidated bridge retains body digest, validation null and failure.
localQuiescenceReceiptSha256 is nonnull only after exact logical/callback closure.
ServiceObservationV2.present permits supervisor envelope with missingSupervisor=null,
or no supervisor envelope with a mandatory typed missingSupervisor observation;
it never contains both. VerifierCrashRequesterBodyV2 additionally requires
reservedSlotId,callbackWorkerAcquisitionState,firstFailure.

Cleanup tokens are exactly seal-normal-ingress/revoke-lane/fence-callbacks/
seal-script/unload-script/detach-session/cancel-guardian/close-file/close-endpoint/
destroy-key/join-process/check-job-empty/close-job/close-spool/close-store/
seal-preterminal/publish-terminal/observe-terminal/commit-requester.
No cleanup token grants an operation absent from the retained owner role policy.


### Guardian pre-binding control dispatch

Control creation must not refer to a future hop binding. Reserve
GuardianStreamReservationV2 before endpoint/key creation: exact fields P/E,
guardianSessionId,fileRole,phase,readEpoch,hopNamespace,
guardianTransportBindingSha256,senderIdentitySha256,receiverIdentitySha256,
reservationNonce,generation,hostOperationDeadlineNs.
GuardianControlBodyV2 and GuardianControlEnvelopeV2 additionally contain
streamReservationSha256. hopBindingSha256 is null before stream-grant, then exact
and immutable. Their genesis uses reservation digest, direction and control class,
NOT the future binding digest. Bootstrap controls use only previously pinned
bootstrap keys. The first grant carries the completed binding and fixes it; derived
post-binding control-key admission occurs at an authenticated switch receipt with
the exact previous bootstrap control digest, without resetting ordinals.

GuardianKeyChallengeV2 fields P/E,streamReservationSha256,guardianSessionId,
authorRole in child/guardian,peerIdentitySha256,challenge,fileRole,phase,readEpoch,
fdAcquisitionReceiptSha256. No public key or future attestation/context digest.
GuardianStreamOfferV2 fields P/E,streamReservationSha256,offerNonce,
sendAcquisitionReceiptSha256,receiveAcquisitionReceiptSha256,
duplicateReceiptSha256,senderIdentitySha256,receiverIdentitySha256.
GuardianStreamAcceptV2 fields P/E,streamReservationSha256,offerReceiptSha256,
offerNonce,retainedSendIdentitySha256,senderIdentitySha256,accepted=true.
GuardianStreamGrantV2 fields P/E,streamReservationSha256,hopBindingSha256,
offerReceiptSha256,acceptReceiptSha256,creatorAliasCloseReceiptSha256,
grantOrdinal=0,previousBootstrapControlSha256.
GuardianHalfCloseV2 fields P/E,streamReservationSha256,hopBindingSha256,
frameCount,totalInnerBytes,finalRelayRecordSha256,halfCloseReceiptSha256.
GuardianCancelV2 fields P/E,streamReservationSha256,guardianSessionId,
cancelSequence,reason (deadline/peer-loss/first-failure),firstFailureSha256,
normalIngressSealed=true. GuardianControlCloseV2 fields P/E,
streamReservationSha256,hopBindingSha256?,lastControlSequence,
lastControlRecordSha256,acquisitionSnapshotRef,remainingEmitterStateSha256,
outcome in closed/uncertain,terminal=true.

| Guardian control kind | Exact payload schema | Binding rule |
|---|---|---|
| key-challenge | GuardianKeyChallengeV2 | Reservation required, hop binding null. |
| child-key-attestation | ChildStreamKeyAttestationEnvelopeV2 | Prior FD/reservation; binding null. |
| guardian-key-attestation | GuardianStreamKeyAttestationEnvelopeV2 | Prior FD/reservation; binding null. |
| key-confirmation | GuardianKeyConfirmationV2 | Both attestations/context known; binding null. |
| stream-offer | GuardianStreamOfferV2 | Reservation only; no future binding. |
| stream-accept | GuardianStreamAcceptV2 | Prior offer; binding null. |
| stream-grant | GuardianStreamGrantV2 | Exact newly completed binding; no future first-write receipt. |
| half-close | GuardianHalfCloseV2 | Exact admitted binding. |
| eof-ack | GuardianHopSettlementAckV2 | Exact admitted binding; both-part validation. |
| stream-terminal | GuardianHopTerminalEnvelopeV2 | Exact binding, ACK/close predecessor. |
| cancel | GuardianCancelV2 | Binding null iff never admitted. |
| close | GuardianControlCloseV2 | Exact known binding or null with unresolved reservation. |

These file-specific offer/accept/grant schemas never accept TranscriptReservationV2
or transcript index fields. They share only the reviewed endpoint ownership
algorithm, not a wire schema. Each kind's payload has direct P/E and reservation/
session equality; unknown kinds reject. No canonical file bytes are a control body.

PendingTransferSnapshotV2 (CONTROL) fields P/E,ackControlBindingSha256,
transferReservations:ordered unique TranscriptReservationV2 references (0..16),
acquisitionSnapshotRef,firstFailureSha256,outcome=unresolved.
AckControlCloseBodyV2.pendingTransferSnapshotRef is null iff all reservations
settled and no pending transfer; otherwise it is R(PendingTransferSnapshotV2).
Missing snapshot delivery cannot prove empty, and references already proved invalid
never participate in the settled or pending authority sets.

### Context phase registry rule

All wire rows carry authority/schemaVersion. The phase-column fixes additional
mandatory fields, never an optional inference:
S (static/scalar) has neither P nor E; N (pre-plan) has constructionId and neither;
P (pre-E) has exact P and no E; E (post-E) has direct P and E; X has contextPhase,
constructionId,P?,E? with the exact pre-plan/pre-E/post-E masks.
Existing field lists that omit mandatory phase members are completed by this
rule; duplicate serialized members still reject. Caller-dependent omission is
forbidden. No scalar identity becomes standalone authority by being phase S.

S is exactly PlanCoreV2,TrustAnchorPinV2,ProcessImagePinV2,WorkerImagePinV2,
GuardianImagePinV2,DependencyPinV2,TargetPolicyV2,HostPolicyV2,FilePolicyV2,
GuardianFilePolicyV2,AdapterLimitsV2,StabilityPolicyV2,ProcessIdentityV2,
JobIdentityV2,FileStatV2,GuardianEndpointIdentityV2,ExitObservationV2,
JobMemberSetV2,StreamEndObservationV2,KeyDestructionObservationV2,
OwnerActivityObservationV2,PathResolutionObservationV2,SameFdObservationV2,
CodecFixtureV2. PlanCore's static closure permits only its actual static policy/
image subset, NOT those scalar process/object/job identities.
N is PrePlanAbortBodyV2,PrePlanAbortEnvelopeV2,PrePlanCleanupExpiryReceiptV2,
PrePlanCleanupExpiryEnvelopeV2.
P is SupervisorKeyAttestationBodyV2,SupervisorKeyAttestationEnvelopeV2,
JobAssignmentReceiptV2,ServiceBootstrapResumeReceiptV2,
ServiceBootstrapEffectReceiptV2,ServiceKeyBootstrapReceiptV2,
PBoundObservationEnvelopeV2,LaneBindingBodyV2,LaneControlTransportV2,
ExecutionBindingBodyV2,HopFactoryBindingV2,
AckControlFactoryBindingV2,ConstructionSettlementBodyV2,
ConstructionSettlementEnvelopeV2.
X is AcquisitionTokenV2,AcquisitionReservationV2,AcquisitionResultV2,
AcquisitionSnapshotBodyV2,AcquisitionSnapshotRefV2,AcquisitionStateV2,
FirstFailureV2,PublicationUncertainReceiptV2,WindowsObjectIdentityV2,
CleanupExpiryReceiptV2,CloseReceiptV2,JoinReceiptV2,JobEmptyReceiptV2,EndpointHalfCloseReceiptV2,
EndpointEofReceiptV2,EndpointCloseReceiptV2,KeyDestructionReceiptV2,
OwnerQuiescenceReceiptV2,PathResolutionReceiptV2,SameFdReceiptV2.
Every other individually registered wire name is E, including all dynamic evidence,
subjects, logical failures/projections, key confirmations and scalar result records.
Any new name requires its own row and reviewed phase; it is not automatically E.
Construction-only close receipts may use X; post-E callers must require X.post-E,
not accept a pre-plan receipt sharing the same numeric object identity.
CleanupExpiryReceiptV2 permits only X.pre-E and X.post-E; pre-plan expiry uses
PrePlanCleanupExpiryReceiptV2. RequesterTerminalRegistryV2 is E only: its reserved
post-E terminal slot cannot represent a pre-plan/pre-E abort, whose outer owner
uses the separate construction settlement/abort chain. S observation details are
non-authoritative scalar descriptions and require their enclosing X receipt.
ExecutionBindingBodyV2 is P, and its external body digest is E; it never contains E.


### Size and codec known-answer fixtures

All concrete schemas in the completion tables carry their stated class.
Remaining scalar-only schemas above are SMALL; schemas with vectors are CONTROL,
except the explicitly listed LARGE and PROJECTION types. A type's declared class
is fixed at review, not chosen by the sender from payload size. Guardian chunks
and transcript bytes use their separately calculated binary bounds.
Every schema's maximal fixture is generated from its exact field/union grammar,
with all bounded vectors at their limits and scalar strings at their stated limits;
if the combination exceeds its encoded class it is a required reject fixture, not
an enlarged allocation. A second admitted fixture fills the lexicographically
first variable-length field to the largest length within the class; if no variable
member can reach the class cap, the exact smaller encoded maximum is recorded.
There is no unbounded "max fixture" and no claim that every field maximum fits
simultaneously. Implementations must emit the per-schema measured byte table and
digest corpus; their absence blocks implementation freeze.

The machine-checkable design KAT below fixes codec/LD/crypto arithmetic independent
of any production key, device, or process. `CodecFixtureV2` is a test-only SMALL
schema with common header plus `a`:S, `n`:U, `z`:B; it is never admitted as
production authority. Its fixture uses a=the five characters quote, backslash,
linefeed, e-acute, slash; n=0; z=false. Expected bytes/hash and crypto vectors are
listed below. A copied numeric digest without reproducing these bytes is not a KAT.

Required mutation corpus for EVERY schema/arm: each key omitted/duplicated/unknown;
each exact type replaced by null/bool/int/string/array/object; every enum swapped;
every null arm crossed; adjacent range boundaries; vector missing/extra/duplicate/
reorder; same payload retagged as each other schema; schemaVersion 1/3; UTF-8
overlong/invalid/BOM/non-NFC, surrogate/NUL, alternate escapes, whitespace, key
ordering and trailing bytes; encoded class cap and cap+1. Domain corpus mutates T,
case, purpose, slash, length endian/count, raw-versus-hex digest, field order,
body-versus-envelope, and key role. Crypto corpus mutates each challenge/identity/
epoch/phase/FD, rejects low-order/all-zero X25519, reuses nonce/key/generation,
swaps ACK/payload/terminal keys, and changes one AAD/tag/ciphertext bit.


### Fixed local calculator vectors

These are primitive KATs, not forged production authorities or complete runtime
fixtures. K is the ASCII byte string `guardian-context-fixture-v2` and the raw
AAD-body test input is `guardian-aad-fixture-v2`; those test strings are NOT
admissible GuardianKeyContextV2/GuardianChunkAadV2 wire bodies. The KAT deliberately
tests LD/HKDF/AEAD independent of a production schema constructor. A complete
schema-derived guardian end-to-end corpus remains an implementation-freeze gate.

Private X25519 A is bytes 00..1f and B bytes 20..3f, each supplied to the fixed
X25519 primitive. Ed25519 uses seed 00..1f. Its fixture signature input is
LD(D(ServiceTerminalEnvelopeV2,signature),
[32 zero bytes, 32 bytes of 01, UTF8("ab" repeated 32 times),
raw32(TYPED_SHA), u64be(125), CodecFixture bytes]).
This intentionally tests exact signature framing, not a valid service body.
The AEAD plaintext is ASCII `fixture`, chunk index 0; CT_TAG is ciphertext followed
by the 16-byte tag. X_BYTES hashes repeated ASCII x bytes, not JSON.

```text
CODEC_HEX 7b2261223a225c225c5c5c7530303061c3a92f222c22617574686f72697479223a2272746c2d7265616465722f6e61746976652d706167652f616461707465722d76322f736368656d612f436f646563466978747572655632222c226e223a302c22736368656d6156657273696f6e223a322c227a223a66616c73657d
CODEC_LEN 125
CODEC_RAW_SHA d26529a123460be8b78ac06e8b527cc9d02a634171e38337690c00815a166a8f
LD_LEN 199
TYPED_SHA d12219cf9cdd2b3f84cc4e9c6bf57c0b7553c5ffe928d6acad68653f0c0a5f93
X_PUB_A 8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f
X_PUB_B 358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254
X_SHARED 9663aa1da97e848a914a436d04163dfbb89178f107f1b5b77ed3854203382854
HKDF_SALT ea94e7ab517c2dfbff500c4e9cb9ffad3fa20a09c6e96658dd85eaaefae1e296
HKDF_OKM ae383ac086dc07a979f3869dc34c8155edba64a62aeb8583c373795a90d2a61e2fbde073139669a323c6aaa7a84a5b5252d4f1d1b0dc4d385ef4d297bf031841b7ce5a45
AEAD_NONCE 2fbde0730000000000000000
AEAD_CT_TAG 5bbec3478335b7fd28d3cdccdd1a69ef19222557bd963d
ED_PUBLIC 03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8
ED_INPUT_SHA 3820db3570c74dffb95c0cbf019bf1656d868de44b83a089755a6344d07b1667
ED_SIGNATURE 75d39fe8fe7d33cdd54ce75aee539546a0011bb38e2da8dcdb695320bd8cc21947176c85f522aa837a4319c5bdd93ad51d4f9b05ac4a6b5f1d40a39f73037705
X_BYTES 0 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
X_BYTES 65536 1f8745f0d2d1387ec1af2211a3cf417b2e9e885e853472649c1d979d0e9370e3
X_BYTES 65537 1abe08ebecf1c18cab71f6fe28aaddf20268f85bad78bb9a72f88ca47c874662
X_BYTES 4194304 baa7a6d36ffa957552df230235c2d51d735f28d49c58a5f3438a3a973a25a37d
LOW_ORDER_REJECTED 7
FRAME_MAXIMA 8232 69672 1052680 69656
```

CodecFixtureV2's bounded-string maximum fixture sets a to exactly 128 U+0001
characters (each encodes as six ASCII bytes), n=9007199254740991, z=false.
Common header and sorted keys are unchanged. The exact encoded size is 895 bytes and raw SHA-256 is
`a68ba43ce45fa4c9338e4bcdcd00fff6387cfe5b83f3bede36390c8ccf8fb74f`;
129 such characters is rejected before
encoding even if the body still fits SMALL. A raw untagged fixture
`{"a":1,"a":2}` is always duplicate-key rejection, never last-key-wins.
Signed-decimal test values are -9223372036854775808, -1, 0, 1,
9223372036854775807; reject +1, 01, -0, whitespace and either out-of-range neighbor.
All platform-to-millisecond conversions require original-clock identity and checked
subtraction before quotient/remainder ceiling; boundary 0 expires, 1 maps to 1ms,
1000000 maps to 1ms, 1000001 maps to 2ms.

### Review-finding structural and implementation test map

These IDs are acceptance obligations, not claims that runtime tests already ran.

| ID | Finding and controlling section | Required check / failure result |
|---|---|---|
| V2-01 | PhaseSealEvidenceV2 / exact snapshot | Slot 11 payload has only 0..10; slot 23 only 12..22 plus prior BEFORE/barrier; external record root, distinct final maps, active checkpoint does not claim own quiescence. Mutate every self-reference; reject before cursor advance. |
| V2-02 | Bootstrap and pre-E settlement | Every resume/descriptor/receipt/gate boundary: validation-only execution is possible while normal authority remains sealed; invalid receipt/gate never admits an operation. |
| V2-03 | Construction / acquisition / service-observation unions | Fault at every construction cursor, before/after E durable publication and every terminal envelope/next-layer close. Select exactly P-rooted pre-E or post-E; retain quiescent, unquiesced, missing and unknown arms without invented evidence. |
| V2-04 | Shared session cleanup | Seal normal ingress, permit only bounded terminalization, append composite/snapshot/closure, then seal root and sign; early chain seal and post-root append reject. |
| V2-05 | Envelope / domain registry | Only E-rooted Ed25519 service provenance; requester-known or unrooted MAC alternatives reject. |
| V2-06 | Capability operation / barrier | Every cursor/result/bulk/predecessor/lastOperationReceipt field; replay/failure-after-dispatch/early barrier; no terminal before exact last operation and callback/transfer settlement. |
| V2-07 | Frida logical attach | Post-attach challenge/selector/load-source/observer/cursor/deadline binding; changed selector, intervening operation or stale signed binding produces zero load. |
| V2-08 | Exact current interfaces | Trace fixtures for admission/capture/cancel/fail-stop/stage/read-only/assert and session permit/load/seal/unload/detach; no v1 authority relabeling or physical I/O by receipt facades. |
| V2-09 | Codec / typed completions / vectors | Every concrete schema and closed arm gets canonical byte/digest and measured encoded maximum; reject unknown/duplicate/type/size/escape/domain swaps. Complete generated corpus remains mandatory. |
| V2-10 | Endpoint offer and hop registry | Exact factory → offer → duplicate ACK → creator alias close → grant → first write; all four namespace variants and both three-transfer routes; wrong owner/key/binding or leaked alias rejects. |
| V2-11 | Guardian absence evidence | BEFORE has no AFTER data; AFTER names exact BEFORE lookup/directory; appearance/disappearance/replaced directory or reordered phase fails. |
| V2-12 | Outer S2b owner / callbacks | Hang, throw, reentrancy, disconnect and late ACK in isolated callback process; revoke before waits; outer finite return with exact uncertainty if kill/join not proved. |
| V2-13 | Topology | Windows job membership excludes Android guardians; empty job cannot imply guardian closure. |
| V2-14 | Guardian key attestation / crypto | Both supervisor-attested challenged public keys; P/E/image/process/lane/session/FD/role/phase/epoch mutation; all-zero X25519, HKDF purpose, nonce reuse, AAD/tag/ciphertext mutation. |
| V2-15 | FD reservation/acquisition | Before-open reservation → observed syscall result → incarnation → key/open bodies; crash at each publication, no GuardianOpen or key-context back-edge. |
| V2-16 | Guardian closure refs | Normal/never/missing even without service terminal; EOF/cancel/BOOTTIME/suspend/watchdog loss leaves explicit closure or recovery-required. |
| V2-17 | Transcript admission | Reservation → prior-only admission body → global record → immutable ref; copied index/ref/body, gap, abandonment or future-ref self-cycle rejects. |
| V2-18 | Two-party inline/bulk settlement | 65536/65537, offer/payload/half-close/EOF/hash/receiver key-close/ACK/sender key-close/terminal/validation; both-party crash at every edge, separate terminal key, bounded spool cleanup. |
| V2-19 | Acquisition / missing-layer / registry | Every key, endpoint, output, FD, process/job/spool has not-created/closed/uncertain; post-envelope next-owner closure; verifier crash and competing registry commit cannot invent CLEAN. |
| V2-20 | Deadlines | Host success acceptance only; conservative Android BOOTTIME lease; overflow-safe ceil, suspend/delay, cleanup 24/25/26ms and total 250ms boundaries; timeout observation/durability failure yields finite uncertain return. |
| V2-21 | Unique typed schema/domain | Exhaustively enumerate registered names and allowed purposes; injective schema/D strings, all cross-type/key-purpose mutations fail. Primitive KATs must reproduce exactly; full implementation vectors are separately reviewed. |

## Explicit implementation blockers and freeze checklist

Independent review is NOT CLEAN. Implementation and device admission remain blocked
until every item is frozen with exact canonical fixtures and negative tests:

- complete public API/type/exception/threading contract for
  `native_page_worker_capability_ipc_v2.py` and proof the two final D03
  post-operation-scope-narrowing baseline bytes, API, registry, and tests remain
  byte-for-byte unchanged by v2;
- immutable v2 factory registry, exact 24 operation tokens, Frida operation token,
  resource IDs/rights, callback grammar, close/revoke/quiescence algorithms;
- final spelling and exact nested schema for every PROPOSED field/type/enum in this
  document, including no extension maps or implicit structural aliases;
- `TrustAnchorPinV2`, supervisor per-run key attestation, key algorithms/sizes,
  secure key-handle lifecycle, service-key attestation, rejection of MAC provenance, and
  exact signature fixtures;
- `ProcessImagePinV2`, both distinct `WorkerImagePinV2` dependency closures,
  guardian images/credentials, interpreter/loader/environment/mitigation policies;
- `TargetPolicyV2`, `HostPolicyV2`, `FilePolicyV2`, `AdapterLimitsV2`, and exact
  stability policy/result schemas including every compared or permitted-drift field;
- acyclic PlanCore/lane/execution construction, all length-delimited hash/HKDF/MAC/
  signature inputs, and canonical known-answer digests;
- `WindowsObjectIdentityV2`, duplicate lineage, acquisition tokens, process/job
  identity, suspended-create/job-assignment/never-started/close/join receipts, and
  numeric reuse behavior;
- real capability-v2 Parent/Child control and bulk endpoints, epoch
  admission/revocation, callback drain, detached terminal/quiescence proof, and all
  four per-hop transcript close protocols;
- supervisor detached placement, pen, checkpoint, tool, private-ADB, selector, and
  service/worker/guardian process attestations with exact provider trust roots;
- every authority evidence schema/parser/source receipt, transcript kind, parsed
  authority schema, evidence-map ordering, slot/barrier/global-cursor rules,
  `AuthoritySnapshotReceiptV2`, and its failure/nullability rules;
- guardian process privilege model, Android binary/provenance attestation,
  path/openat/URI serialization, same-FD/stat/hardlink/seek/EOF/size rules,
  end-to-end key agreement/AEAD, chunk protocol, absence proof, key destruction,
  close/join/staging cleanup, and raw-byte non-disclosure proof;
- Frida logical-attach binding, physical step receipts, after-attach load selector
  oracle, observer callback success/failure schemas, conditional cleanup suffix,
  exact `FridaPhysicalSettlementEnvelopeV2` barrier schema, and post-lane-close
  `FridaCompositeReceiptV2` nullability/topology;
- exact inline/bulk partition, hop owners/keys/endpoints, transcript/global/local
  ordinal allocation, `previousChunkRecordSha256`, manifest/control-reference
  settlement, spool limits/identity/encryption/cleanup, and crash recovery;
- unsigned service/supervisor bodies, exact envelopes, envelope external digest,
  separate service/supervisor/requester terminal topologies, next-layer
  signing/output/process closure proofs, and pinned supervisor trust-anchor rotation;
- requester bridge validator isolation, construction timing, canonical
  compatibility success/failure projection bytes and size, logical receipt
  template bundle,
  callback replay/failure, method order/cursors, teardown/quiescence/failure mapping,
  and explicit rejection of legacy live leases;
- signed-int64 deadline parsing/addition, clock-incarnation proof, Windows wait
  conversion/polling, success-candidate cutoff, cleanup deadline, and after-closure
  bridge timing; and
- closed failure-code registry, first-failure precedence, diagnostic redaction,
  cleanup ledger durability, terminal-count assertions, and admission blockers.

The **PROPOSED named freeze inventory** below is closed for this review: every
item now has a proposed schema/codec/size profile in the sections above; the
implementation still needs independently reviewed generated exact per-schema
fixtures, exhaustive member/union validators and reject-unknown-key tests.
The historical grouped index below is not a second field-definition authority;
the completion registry and additions above also belong to the closed inventory. An implementation may not silently invent an omitted member.

- plan/trust/image: `PlanCoreV2`, `TrustAnchorPinV2`, `ProcessImagePinV2`,
  `WorkerImagePinV2`, `GuardianImagePinV2`, `DependencyPinV2`,
  `TargetPolicyV2`, `HostPolicyV2`, `FilePolicyV2`, `AdapterLimitsV2`,
  `StabilityPolicyV2`, and `StabilityResultV2`;
- execution/OS: `SupervisorKeyAttestationBodyV2`,
  `SupervisorKeyAttestationEnvelopeV2`, `ServiceKeyBootstrapReceiptV2`,
  `LaneBindingBodyV2`, `ExecutionBindingBodyV2`,
  `ExecutionAttestationEnvelopeV2`, `WindowsObjectIdentityV2`,
  `ProcessIdentityV2`, `JobIdentityV2`, `AcquisitionTokenV2`,
  `JobAssignmentReceiptV2`, `ProcessResumeReceiptV2`,
  `LaneNeverStartedReceiptV2`, `LaneClosureRefV2`, `CloseReceiptV2`, `JoinReceiptV2`, and
  `JobEmptyReceiptV2`;
- capability-v2/control: `CapabilityBindingBodyV2`, `OperationLeaseV2`,
  `DetachedPayloadV2`, `DetachedBulkReferenceV2`,
  `CapabilityTerminalBodyV2`, `CapabilityTerminalEnvelopeV2`,
  `CapabilityQuiescenceBodyV2`, `CapabilityQuiescenceEnvelopeV2`,
  `LaneControlTransportV2`, `ControlEnvelopeV2`, `DataEndpointBindingV2`,
  `EndpointHalfCloseReceiptV2`, `EndpointEofReceiptV2`,
  `EndpointCloseReceiptV2`, `KeyDestructionReceiptV2`, and
  `OwnerQuiescenceReceiptV2`;
- supervisor evidence: `SupervisorDetachedAttestationBodyV2`,
  `SupervisorDetachedAttestationEnvelopeV2`, `PlacementSubjectV2`,
  `PenLeaseSubjectV2`, `CheckpointSubjectV2`, `ToolBundleSubjectV2`,
  `PrivateAdbSubjectV2`, `SelectorSubjectV2`, and every named provider receipt;
- authority: `SlotEvidenceEnvelopeV2`, `PhaseOpenEvidenceV2`,
  `DeviceStateEvidenceV2`, `TargetProcessEvidenceV2`,
  `GuardianFileDigestEvidenceV2`, `GuardianAbsenceBeforeEvidenceV2`,
  `GuardianAbsenceAfterEvidenceV2`,
  `ParsedTranscriptEvidenceV2`, `PhaseSealEvidenceV2`,
  `AuthoritySnapshotReceiptV2`, `AuthoritySnapshotFailureReceiptV2`,
  `EvidenceMapV2`, and `ParsedAuthorityV2`;
- guardian: `GuardianFdIncarnationV2`, `FileStatV2`, `FileUriBindingV2`,
  `GuardianOpenBodyV2`, `GuardianStreamChunkBodyV2`,
  `GuardianReadEpochTerminalBodyV2`, `GuardianAbsenceBodyV2`,
  `GuardianCloseBodyV2`, `GuardianProcessClosureReceiptV2`,
  `PathResolutionReceiptV2`, `SameFdReceiptV2`, and `GuardianTransportBindingV2`;
- Frida: `LogicalAttachBindingV2`, `FridaPhysicalStepReceiptV2`,
  `FridaStepDispositionV2`, `FridaCallbackRecordV2`,
  `FridaPhysicalSettlementBodyV2`, `FridaPhysicalSettlementEnvelopeV2`,
  `FridaBarrierRecordV2`, and `FridaCompositeReceiptV2`;
- transcripts: `TranscriptRefV2`, `InlineTranscriptBodyV2`,
  `InlineTerminalBodyV2`, `InlineTerminalEnvelopeV2`,
  `BulkChunkHeaderV2`, `BulkManifestBodyV2`, `BulkManifestEnvelopeV2`,
  `ServiceGlobalRecordV2`, `SpoolIdentityV2`, and `TranscriptHopClosureV2`;
- terminals/bridge/logical: `FirstFailureV2`, `ServiceTerminalBodyV2`,
  `ServiceTerminalEnvelopeV2`, `MissingLayerTerminalBodyV2`,
  `SupervisorClosureBodyV2`, `SupervisorClosureEnvelopeV2`,
  `RequesterBridgeBodyV2`, `CompatibilityProjectionDescriptorV2`,
  `NativePageCompatibilityProjectionV2`,
  `NativePageCompatibilityFailureProjectionV2`, `AdmissionProjectionV2`,
  `StageProjectionV2`, `FridaLogicalProjectionV2`,
  `PhysicalClosureProjectionV2`, `LocalFailureMappingV2`,
  `LogicalReceiptTemplateV2`, `LogicalMethodReceiptBodyV2`,
  `LogicalFailureBodyV2`, `RequesterTerminalBodyV2`, and
  `RequesterTerminalRegistryV2`.

No unlisted nested object may be deferred to implementation judgment. If a schema
referenced above remains only a name or field list without frozen types/ranges/null
rules, this checklist remains open.

## Dependency and review order

1. Freeze terminology, threat model, PlanCore/lane/execution DAG, canonical codec,
   length delimiter, crypto profiles, and proposed domain/field registry.
2. Freeze both worker image/dependency closures, supervisor root/key lifecycle,
   Windows identity/assignment primitives, and deadlines.
3. Implement/test the separate capability-v2 engine/registry and real retained
   control/bulk/quiescence transports while proving v1 byte-for-byte non-regression.
4. Implement/test supervisor detached attestation providers and process/job/service
   closure chain.
5. Implement/test device guardian provenance, privilege, same-FD stream/absence,
   URI policy, and raw-byte non-disclosure.
6. Implement/test Authority 24-slot/barrier machine and exact snapshot success/
   failure receipts.
7. Implement/test Frida one-composite worker, selector freshness, callbacks, and
   exact failure cleanup.
8. Implement/test every inline/bulk forwarding hop, spool, chain, reference, and
   crash boundary.
9. Implement/test single orchestration entry, service terminal, supervisor closure,
   and requester settlement/bridge.
10. Implement/test receipt-only facades, exact method mapping, compatibility bytes,
    requester-local failures, and closure.
11. Run the complete deterministic matrix and independent subsystem/integrated
    review before any device request.

## Deterministic test matrix

| Area | Required deterministic cases | Pass condition |
|---|---|---|
| V1 isolation | Source/API/test hashes before/after v2; attempted v2 import/subclass/registry injection/receipt use in v1. | V1 byte-for-byte and behavior fixtures unchanged; all cross-version values reject. |
| Plan DAG | Mutate each PlanCore field; inject self digest; reorder DAG; lane digest in own body; service key in core; sign wrong `P`/`E`; cyclic fixture. | Only exact acyclic construction validates; stable known-answer hashes. |
| Signature inputs | Domain/length/count/order/raw-vs-hex digest/body mutation; key/attestation swap; requester-known MAC forgery. | Exact fixtures validate; every mutation fails; root chain ends at pinned supervisor anchor. |
| Image pins | Authority/Frida image swap; one dependency missing/extra/reordered/replaced/late-loaded; guardian/service/supervisor replacement. | Exact distinct image/dependency closures required before resume. |
| Windows identity | PID/owner-start/native-value/generation/rights/duplicate-lineage mutation; same numeric handle across owners; partial close/reuse. | No bare numeric authority or foreign-generation action. |
| Job assignment | Fault before/after CreateProcess, assignment, query, receipt, resume; assignment uncertainty; never-started lane in every partial state. | No uncertain process resumes; exact assignment/never-started terminal and cleanup. |
| Lane independence/shared list | Collision/swap of every key/session/epoch/endpoint/owner/cursor/receipt; both cursors legitimately zero; mutate each intentionally shared value. | Namespace-scoped zeros accepted; aliases/cross-lane use rejected; exact shared list only. |
| Capability-v2 lifecycle | Success close and failure revoke at every state; callback/bulk active at close; epoch/transport/drain/owner quiescence failure; post-terminal frame. | One detached lane terminal and quiescence receipt; no failure-to-success transition. |
| Broker slot cursor | Exact 0..23; every missing/duplicate/reorder/retry/wrong phase; barrier skipped/replayed/wrong receipt; independent lane cursor mutations. | Only 0..11 -> barrier -> 12..23 reaches snapshot candidate. |
| Slot schemas | Missing/extra/wrong type/range/null for every field in every exact evidence schema; fresh-capture and transcript constraints. | Rejected before cursor advance/publication. |
| Snapshot receipts | Mutate 24 list/order/root/barrier/Frida/evidence/transcript/stability/cursor/terminal/quiescence; failure at every cursor/null combination. | Exact success or exact prefix failure receipt, never both. |
| Supervisor attestations | Requester-supplied, stale, replayed, wrong challenge/provider/key/phase/time placement/pen/checkpoint/selector evidence. | Only exact detached root-valid fresh subject accepted. |
| Guardian privilege/provenance | Wrong binary/dependency/UID/GID/capability/SELinux/path role; auto-root fallback; shell/write/enumeration operation. | Fail before open/stream; no privilege broadening. |
| Guardian same-FD | Symlink/reparse/dot/encoded separator/hardlink; nonregular/nonseekable; lseek not zero; short/extra read; wrong size/offset/EOF; stat drift; reopen/substitute FD; close/key-destruction uncertainty. | Exact same-FD two-epoch digest or failure/uncertainty; no raw fallback. |
| URI/absence | Canonical file URI boundaries; `content://`; authority/query/fragment; UTF-8/percent normalization; URI/path/(dev,ino) mismatch; mark appears/disappears/directory changes. | Only frozen `file://` mapping and exact absence proof pass. |
| Raw-byte canaries | Unique PDF/APK/framework/module/mark canaries monitored in service/supervisor/requester memory, all transcript/control/log/error/spool/receipt paths. | Plaintext appears only in guardian and Child fixed buffers; buffers cleared; no serialization. |
| Frida selector | Change before attach, after attach/before selector, after selector/before load; PID reuse; server replacement; wrong attach receipt/challenge/time/provider. | No load without exact post-attach fresh supervisor attestation. |
| Frida physical composite | Fault before/after every attach/load/callback/seal/unload/detach/quiescence receipt; physical call count >1. | One composite, exact conditional cleanup, success only detached/quiescent. |
| Callback grammar | Exact success/failure pair; 0/1/3 records; partial/duplicate/order/size/late/post-terminal; binary encoding mutation. | Exact physical callback chain or Frida failure. |
| Carrier partition | Length 0,1,65535,65536,65537,4194304,4194305; wrong inline/bulk choice. | Exact boundary and deterministic digest. |
| Per-hop transcript | Every key/endpoint/owner/direction swap; local/global ordinal and transcript index mutation; predecessor raw-chunk-vs-record confusion; chunk/order/offset/length/MAC/digest/manifest/EOF/reference fault. | No partial reference; exact final root at every hop. |
| Per-hop crashes | Every create/publish/header/payload/tag/chunk/manifest/half-close/EOF/ref/spool/forward/close boundary for sender and receiver. | Exact cleanup or owning layer uncertainty; no success bridge from partial data. |
| Service terminal | Body/envelope self-reference; two terminals; success+failure; wrong lane/snapshot/Frida/transcript/close root; crash before/after sign/output/key close. | One valid signed terminal or explicit missing terminal at supervisor layer. |
| Supervisor closure | Wrong service envelope/outcome; missing service key/output/join/job-empty/handle proof; two closures; crash around sign/key/output/exit. | One root-valid closure or supervisor uncertainty; service chain unchanged. |
| Requester chain | Supervisor success/uncertainty after service success; missing EOF/join/key closure; bridge before closure/after deadline; bridge/projection mutation/replay. | Bridge only after complete closure in fixed window; prior chains immutable. |
| Compatibility projection | Every key/type/order/size/transcript ref; success/failure schema mixing; v2 bytes relabeled as v1. | Exact detached v2 projection only; no legacy acceptance. |
| Logical methods | Exact proposed order; each success/failure receipt; independent facade zeros; skip/replay/concurrency; callback throws at every index; physical-I/O spy on every method; failure/cancel/teardown/quiescence/stage mapping. | One cursor chain; zero physical I/O; exact requester-local terminal; signed physical chains unchanged. |
| Legacy lease exclusion | Inject v1 permits/tickets/leases/providers/handles into PlanCore, service, bridge, projection, or facade. | Rejected; no serialization or process crossing. |
| Deadline arithmetic | Int64 min/max/overflow; leading zero/sign; clock swap/regression; wait ceil/cap/DWORD wrap; boundary before/at/after physical seal, service close, supervisor close, bridge. | No rebase/overflow; physical success sealed before operation deadline; bridge only before cleanup deadline. |
| Shared cleanup | Each lane/guardian never starts/hangs/crashes; sibling cleanup after first error; transcript/service/supervisor output close failures; nonempty job; staging/key/spool/descriptor uncertainty. | Exact layer terminal; overall success impossible with unresolved obligation. |
| Terminal counts | Zero/two/post-terminal records independently at service, supervisor, requester layers, including process death before emission. | Exactly one emitted or next-layer-proved-missing union arm per completed layer chain; no layer overwrites another. |

All fixtures use fixed bytes, clocks, keys, process/handle generations, transcripts,
and expected hashes. Fuzz/property tests supplement but never replace every listed
boundary and per-transition fault.

## Admission conclusion

The corrected architecture is specified, but the independent review remains NOT
CLEAN because every proposed wire/API/crypto/nested schema must still be frozen and
implemented. No current v1 code is changed or repurposed. No production adapter,
device interaction, injection, APK transfer, PDF read, pen action, or hardware gate
is authorized by this document.

## Executable registry normalization (candidate, NOT CLEAN)

The companion `native_page_adapter_v2_schema_registry.py` is the closed proposed
wire-definition authority for this candidate. Its entries give every ordered
member, exact type, phase, encoded class, null/state arm, referenced schema,
authentication container, key role, and permitted purpose. Earlier field lists
are explanatory projections only; they do not create optional members or aliases.
A name absent from that registry is rejected, not inferred from a suffix.
The generated inventory and corpus below replace the historical grouped index.

### Exact containment and authentication

R(T) is a 64-character lowercase typed-body digest reference, never an inline
object; O(T) is the complete canonical object. Hashes of signatures/envelopes
reference that exact envelope's external typed-envelope digest instead. Raw file,
image, canonical payload and transcript hashes are raw SHA-256 only where the
field type is H. No untyped H may substitute for an R(T) authority edge.
Every reference must resolve to one admitted byte string of the declared schema;
the complete per-instance reference graph must be acyclic, including predecessor
edges. Schema type graphs may contain reference cycles because separate instances
can be earlier/later; that does not permit an instance cycle or self-reference.

All unsuffixed identity fields in the registry are R(ProcessIdentityV2),
R(WindowsObjectIdentityV2), R(JobIdentityV2), or R(GuardianFdIncarnationV2), as
individually declared. Only explicitly O(T) members embed an object. FileStat,
acquisition states/snapshot references, lane/guardian closure references and
projection subobjects use O(T) where specified. There is no structural duck typing.

PBoundObservationEnvelopeV2 has the exact member `planCoreSha256`, never `P`.
Its closed body union is ServiceBootstrapResumeReceiptV2,
ServiceBootstrapEffectReceiptV2, ServiceKeyBootstrapReceiptV2,
JobAssignmentReceiptV2, AckControlFactoryBindingV2, HopFactoryBindingV2.
These receipts are P-supervisor-signed before E; references to their bodies are
admitted only with that envelope. Their evidence cannot claim future execution.

SupervisorDetachedAttestationBodyV2 includes exact `subjectSchema` and
`subjectBodySha256` members with a discriminator-bound target. Its closed subject
union is PlacementSubjectV2, PenLeaseSubjectV2, CheckpointSubjectV2,
ToolBundleSubjectV2, PrivateAdbSubjectV2, SelectorSubjectV2,
GuardianProcessSubjectV2, GuardianLeaseGrantV2, WorkGateBodyV2,
BootstrapResumeReceiptV2, ProcessResumeReceiptV2,
InitialFileObservationV2, LiveTargetBindingV2, LiveHostBindingV2,
PreAttachSelectorCommitV2, GuardianProcessClosureReceiptV2 and
PlatformObservationV2. The envelope uses the E-attested supervisor key; a subject
body alone is not an attestation. `attestationKind` is exactly the subject schema
name, not an additional alias vocabulary. Subject and wrapper P/E must agree.

BootstrapValidationReceiptV2 and ServiceExecutionValidationReceiptV2 are carried
in the existing ControlEnvelopeV2 validation class and then explicitly named by
the supervisor WorkGate attestation. The worker validation uses its lane bootstrap
key fixed in P; the service validation uses the service bootstrap control key
fixed by the P-bound service key receipt. Neither key authorizes normal work.
CapabilityOperationReceiptV2 and AuthorityBarrierAcceptanceV2 are carried in the
lane's ControlEnvelopeV2 normal/terminalization class under its E-bound lane key.
Acceptance is a supervisor-signed PlatformObservationV2 of that exact receipt,
not a requester-authored digest. ProcessResumeReceiptV2 is a separate supervisor
subject; it is never a worker's self-observation.

GuardianFdReservationBodyV2, GuardianFdAcquisitionBodyV2, GuardianOpenBodyV2,
GuardianReadEpochTerminalBodyV2, GuardianAbsenceBodyV2 and GuardianCloseBodyV2 are
exact payload alternatives of GuardianControlBodyV2; GuardianControlEnvelopeV2
authenticates them. Control direction, class and ordinal are explicit in both
body and metadata, equal, and included in the MAC. The pre-confirmation key is
the supervisor-attested guardian bootstrap-control key. The one-shot
GuardianControlKeySwitchV2 payload binds the reservation, exact hop binding,
previous bootstrap record, key context, both confirmations, derived key ID and
next ordinal. It is authenticated by the old key; only the following record uses
the derived file-ack-control key. Replay, premature switch, direction reuse,
wrong next ordinal or a second switch aborts. Derived keys do not authenticate
their own bootstrap attestation.

AcquisitionSnapshotBodyV2 is detached canonical data, not its own authority.
Its reference is admitted only as an exact member of the responsible owner's
authenticated terminal/observation body (P/N outer signature, E lane control,
guardian control, service signature, or supervisor signature as the owning
context requires). The authenticated member binds the delivered bytes, length,
count, source ledger and owner. Missing delivery, wrong owner/context, partial
bytes or a reference without that enclosing authentication remains unresolved.
A snapshot reference cannot authorize acquisition or cleanup on its own.

SlotEvidenceBodyV2 contains the former inline slot-record members.
SlotEvidenceEnvelopeV2 is now only detached metadata plus that exact raw body,
authenticated by the authority lane MAC with direct P/E, lane binding, key ID,
body schema/length/hash. The external envelope-record digest is the slot root.
SlotEvidenceBodyV2.typedEvidenceSchema fixes its typedEvidence O(T) alternative.
Its typedEvidenceSha256 must equal the corresponding typed body digest.
Neither body nor evidence contains the digest of its own envelope.

PlatformObservationV2 is a bounded supervisor-attested observation, never a
generic execution command. Its closed operation tokens are capture, parse,
provider-proof, acceptance, causal-launch, causal-attach, durability,
canonical-validation, transport-close, bridge-validation, closure-observation,
terminal-commit, immutable-owner-boundary, fd-syscall, staging-delete, exit-intent.
It binds exact owner, subject schema/digest, fixed operation ID/ordinal,
previous observation, source image/policy, captured host instant, original
deadline, and proved/uncertain outcome. The registry's subject target union is
closed. Each operation additionally requires its independently reviewed native
observer implementation; the schema does not supply that implementation.
No generic `perform`, arbitrary path, shell, evaluator or mutation operation is
introduced. Device fd-syscall observations instead carry the exact guardian
syscall receipt described next and are merely supervisor observations of it.

GuardianSyscallReceiptV2 is guardian-control authenticated and binds exact
incarnation/reservation, syscall sequence, operation from
seek-zero/stat/read-eof/offset/path-revalidate/decrypt-count-hash/fd-close/key-destroy/
endpoint-close/staging-delete/exit-intent, before/after offset, byte count,
raw digest nullable by operation, previous receipt, Android BOOTTIME and
proved/failed/uncertain outcome. It does not grant a new syscall or reopen a file.
The guardian policy still admits only the fixed read-only operations and exact
owned cleanup actions. No requester can mint a syscall receipt.

FridaStepResultV2 is lane-authenticated step-local evidence, not whole-provider
quiescence. It binds the exact physical operation, step ordinal/token, target
identity, server/session, optional script identity, callback generation/count,
source image digest, operation-local handle/endpoint closure receipts where
applicable, original deadline and proved/failed/uncertain result. Attach names the
exact attached session; load names the exact script and observer bytes; seal
records the callback publication fence; unload closes that script only; detach
closes that session only; operation-quiescence covers that operation. Full lane
closure is separately required. A step result cannot assert provider CLOSED.

### Closed terminal and failure arms

FridaStepDispositionV2 retains exactly completed, failed, not-reached,
cleanup-completed, cleanup-failed, cleanup-not-required. Only completed,
failed, cleanup-completed and cleanup-failed carry a nonnull step receipt.
The failure/uncertain state is encoded in that receipt's outcome, not a second
disposition spelling. Seven ordinal/token pairs are fixed; cleanup dispositions
are allowed only in the conditional seal/unload/detach/quiescence suffix.
CapabilityTerminalBodyV2.outcome is closed-success/closed-failure/closed-uncertain.
Every uncertain or failure outcome has FirstFailureV2; success has null.
No null-prefix arm can authorize lifecycle success or physical cleanup.

GuardianClosureRefV2 common acquisitionSnapshotRef and guardianAcquisitionState
are always present. Remaining fields are fdAcquisitionReceiptSha256,
guardianCloseBodySha256, supervisorProcessClosureReceiptSha256,
missingLayerReceiptSha256. Their required/nonrequired masks, respectively, are:
normal=(nonnull,nonnull,nonnull,null);
never-started=(null,null,nonnull,null);
started-not-acquired=(null,nullable,nonnull,null);
open-failed=(nonnull,nonnull,nonnull,null);
open-uncertain=(nonnull,nullable,nullable,nonnull);
missing-crashed=(nullable,nullable,nullable,nonnull).
Nullable values in uncertain arms are authenticated earlier prefix evidence only.
No missing receipt is synthesized. normal/open-failed/never-started require
proved closure; all uncertain/missing arms forbid success and retain obligations.
Started-not-acquired is failure with proved process closure; acquisition state
must prove no descriptor acquisition, or the arm becomes open-uncertain.

Guardian read/hop terminal prefix failure uses the same complete keyset as success:
prefix-dependent receipts are nullable, firstFailure is nonnull, and outcome is
read-failed/read-uncertain or closed/uncertain as its exact schema declares.
A successful read requires all seek/stat/EOF/offset/revalidation/decrypt/transport
receipts, exact total/count/hash, both key confirmations and both hop terminals;
only zero-chunk first/final record hashes and BEFORE predecessor are null.
A successful hop requires all ACK/half-close/key-destruction/endpoint-close
receipts; only zero-frame finalRelayRecordSha256 is null. Failed prefixes cannot
be interpreted as a zero-byte success.

PhysicalClosureProjectionV2 is success-only: every closure field is nonnull and
independently verified. NativePageCompatibilityFailureProjectionV2 instead has
nullable physicalClosureProjection; it is nonnull only if full closure was proved.
Early service/supervisor/lane/guardian/transcript failures have no success closure
projection and no receipt-only success bridge. They remain representable by the
explicit service-observation, lane-closure and missing-layer unions in signed
terminal chains. Failure compatibility projection is produced only after an
available service terminal plus supervisor closure; if either is missing, it is
null and requester terminal carries its existing missing-layer arm. This is not
an omission of the failure: the outer terminal is the authority for that failure.

RequesterTerminalBodyV2 pre-bridge arm has bridgeBodySha256,
bridgeValidationReceiptSha256, logicalReceiptChainRootSha256,
authorityFacadeTerminalReceiptSha256, fridaFacadeTerminalReceiptSha256,
callbackDeliveryRootSha256, localQuiescenceReceiptSha256 all null,
globalConsumptionCursorFinal=0, firstRequesterFailure nonnull and outcome not
success. After bridge construction, logical-chain and callback roots are explicit
typed genesis or completed prefixes, never invented receipts; facade terminals
remain null until actually emitted. Success requires all exact terminal/quiescence
references and null firstRequesterFailure. Failure/uncertainty may retain only
the authenticated completed prefix and cannot expose a success projection.

RequesterTerminalRegistryV2 winnerBodySchema/target is exactly:
verifier-terminal→RequesterTerminalBodyV2;
outer-verifier-crash→VerifierCrashRequesterBodyV2;
publication-uncertain→PublicationUncertainReceiptV2.
Only publication-uncertain permits null commitReceiptSha256; it requires
outcome uncertain and cannot later be rewritten as success. The registry is
post-E only. Construction settlement has its own disjoint outer slot.

TranscriptAbandonmentV2 contains only acquisitionSnapshotRef, never an inline
acquisition vector. Every signed/MAC envelope's bodySchema and key-role pairing
is fixed by the executable registry, including SettlementAckEnvelopeV2,
GuardianStreamKeyAttestationEnvelopeV2, all outer/P-bound signatures and lane
terminal/quiescence envelopes. TrustAnchorPinV2.publicKeySha256 is raw SHA-256 of
the decoded public key. rootSigningKeyId is the separately domain-derived key ID
D(TrustAnchorPinV2,key-id) over the raw public key; it is NOT that raw hash.
The caller pins both and verifies this exact relation before construction.

### Closed operational additions and deadline publication

CapabilityTerminalizationRequestV2 and CapabilityTerminalizationReceiptV2 are the
only post-E close/revoke protocol. They use the existing lane's separately derived
terminalization-control key, never a normal operation lease. The independent
chain has typed genesis D(CapabilityTerminalizationRequestV2,genesis) over P/E,
lane/session/epoch and both prebound control endpoints. Exactly one request at
cursor 0 wins a durable owner CAS; receipt cursor 1 names that request and the
actually emitted terminal/quiescence, or explicit uncertainty. The terminal body
commits the earlier request (not the later receipt); the next owner commits the
receipt, endpoint closure and key destruction. Identical retransmitted bytes may
return the same already committed receipt, but never redispatch close/revoke.
Different ID/action/generation or reordered bytes fail closed. Before emission
the retained owner has the unresolved intent; after emission it has the exact
request; after acceptance it has the fixed winner; after terminal only closure
remains. The terminalization key survives until the receipt is authenticated,
then the next owner proves its destruction. Pre-E uses outer-owned construction
settlement only, not this post-E chain or a nullable E command.

SuccessSealV2 is the sole success-candidate predicate and original-clock timestamp.
It may be committed only after slot 23, exact snapshot success, both lane terminal
and detached-quiescence envelopes, all guardian read/absence and proved closure
references, every selected transcript's three physical transfers and final
closures, and Frida detached settlement have been accepted. No FirstFailure or
uncertain owner may be latched. The final accepted-evidence root is immutable.
Immediately before its one-shot CAS, sample the trusted host clock and require
strictly sealedHostNs < operationDeadlineNs. ServiceTerminalBodyV2 commits the
seal's digest and identical timestamp. After expiry, grace cannot supply, replace
or newly accept a success-contributing reference. It may only settle failure/
uncertainty or close the success candidate's explicitly represented terminal
output/signing/process obligations. No success seal exists if any conjunct was
missing at expiry.

Construction/pre-plan LARGE snapshots use the separate X-context snapshot
transport below, not the E-only transcript carrier and not a digest-only handoff.
Its namespace is construction-snapshot-v2 (not one of the four execution
transcript namespaces). SnapshotTransportBindingV2 is fixed before snapshot
serialization and names no snapshot hash: this avoids a snapshot/carrier
self-cycle. It binds construction/context, exact sender/receiver process and
retained one-way data/control endpoints, original deadline, generation, key IDs,
prior acquisition/secret-delivery receipts and the pinned outer owner.
The outer owner signs SnapshotTransportAttestationEnvelopeV2 with its provisioned
key. The 32-byte random per-direction master secret is delivered only through
these already-retained isolated OS handles before the binding is attested;
a hash alone does not establish key delivery. The source acquisition snapshot
records that already-created carrier, not its future terminal.

Use the same bounded bulk framing and two-party lifecycle, with distinct
D(SnapshotTransportBindingV2,hkdf-salt/hkdf-info) and purposes snapshot-payload,
snapshot-ack, snapshot-terminal. HKDF-SHA256 derives independent 32-byte keys
from the fixed 32-byte random secret, context hash, direction and generation.
X framing encodes constructionId, contextPhase, and P/E as raw32 or zero-length
when absent, so the exact phase token distinguishes all masks. There is no E
requirement before E exists. Raw snapshot length is 1..2101761, chunks are
1..65536, maximum ceil(2101761/65536)=33 chunks. Chunk ordinal, offset, header
length, raw bytes and previous complete record are MAC-bound under the payload
key. Binding plus typed genesis precedes the first chunk.

SnapshotTransportSettlementV2 authenticates exactly the reconstructed snapshot,
count/length/hash, receiver EOF/zero trailing data, canonical-schema validation,
receiver data close and payload-key destruction; it cannot refer to the future
sender terminal. The ACK uses snapshot-ack. Sender validates it, destroys its
payload key, closes its data endpoint, then authenticates
SnapshotTransportTerminalV2 under snapshot-terminal. The terminal names both
directions' actual close/key/ACK evidence and the earlier snapshot digest.
The outer recovery owner independently proves ACK/terminal/control key destruction,
control EOF/close and exact process/handle retirement. A consumer admits a snapshot
reference only after that whole chain, never from a path or a reopened object.
Crash before binding leaves expected roles unresolved; after binding exact
carrier identities are retained; after any chunk only an authenticated prefix
exists; after ACK only original terminalization/closure is allowed; absent terminal
or lost proof remains uncertain. No index/key/generation is reused. This channel
does not carry file plaintext or grant a new acquisition.

OuterControlBindingBodyV2, BootstrapHandleEntryV2, BootstrapHandleSetBodyV2,
ZeroAuthorityHandleSetBodyV2 and PreGateRetainedHandleRootBodyV2 close the former
opaque D07 roots. They enumerate exact typed objects, rights, noninheritance,
generation, acquisition and close owner. A zero-authority proof enumerates the
complete fixed object-kind registry and asserts an empty authority-bearing subset;
it is not SHA256(empty). Every available handle is in exactly one set position;
duplicates, omissions and extra handle classes fail. These X bodies use pre-plan,
pre-E or post-E masks explicitly; PlanCore contains only their static policies,
never these live observations. Their size/entry limits are fixed in the registry.

Before the first pre-plan risky operation the externally pinned outer owner
freezes one monotonic construction deadline and one settlement deadline, reserves
its durable abort/expiry slot, and persists an uncertainty checkpoint plus recovery
owner. That trust is independent of P. Every cleanup call is bounded by
min(original total deadline, sampled-now + 25000000ns), checked without overflow.
No total or per-call deadline is rebased. At/after the deadline no new mutation,
signature, append, close syscall or retry begins. A previously started append may
be observed nonblockingly; the caller then returns finite uncertainty using the
pre-risk durable checkpoint and leaves the exact in-flight append/handle owned by
the outer recovery process. It does not promise an impossible newly durable expiry
receipt after expiry. PrePlanCleanupExpiryReceiptV2 or CleanupExpiryReceiptV2 may
be emitted only by an append begun before expiry; otherwise PublicationUncertain
names the original reserved slot and existing checkpoint. Recovery either proves
that exact append committed or proves missing emission; it cannot issue a second
competing terminal append. Real retained-handle/one-shot durable-CAS support is an
implementation admission requirement, not supplied by this document.

DetachedPayloadV2 uses an inline transcript carrier of kind detached-result and
names its exact carrierTranscriptRefSha256. The result's canonical bytes are
1..65536; its operation receipt names those earlier bytes, then metadata names
both that receipt and the already settled carrier. This is acyclic. Raw bytes
are never inserted into a control metadata object. Receiver canonical validation
is of the staged raw payload and selected schema, not the future terminal.
TranscriptForwardReceiptV2's typed source/destination terminal references resolve
their exact data bindings, owners and endpoint generations; routeIndex 1 is
SERVICE_TO_SUPERVISOR and 2 is SUPERVISOR_TO_VERIFIER. No third/fourth physical
forward is possible. The four namespace vocabulary still means exactly three
physical transfers for one chosen child source. Forwarding preserves identical
canonical bytes and has no reinterpretation, retry or alternate path.

### Final contract scope and remaining admission gates (NOT CLEAN)

The executable registry is the exact field/type/enum/null/size/authentication
definition for this candidate. Historical prose field lists above are explanatory,
not alternate parsers. No implementation may accept an old spelling or implicit
optional field. In particular all Ed25519 envelope metadata uses
signatureAlgorithm/signature, and all HMAC envelope metadata uses
algorithm/keyId/tag. Body selection and reference targets are closed by the
named envelope's registry entry. Wire envelope framing is exactly
u32be(metadata length) || canonical metadata || u64be(body wire length) || body
wire bytes. The external envelope digest commits both exact byte strings.

AcquisitionTokenV2 has the explicit root-origin discriminator ownerKind.
process requires ownerIdentity and null ownerTrustAnchorSha256; provisioned-root
requires the independently provisioned TrustAnchorPinV2 reference, null process
owner, resourceRole=outer:process and pre-plan context. Only this origin arm can
root the first outer-process acquisition; it is not a general bypass for missing
owners. Subsequent process identities and receipts reference earlier acquisitions.
This eliminates an impossible first-process/token identity cycle.

PlatformObservationV2 is X, not inherently post-E. Its pre-plan/pre-E instances
are authenticated by PlatformObservationEnvelopeV2 under the independently
provisioned outer key. Post-E observations additionally require the admitted
supervisor subject chain where the consuming operation prescribes it. Every
enclosing context must equal the observed context; an outer signature cannot
substitute for a required supervisor observation. PreGateRetainedHandleRootBodyV2
is E only; the other bootstrap handle-set bodies are X.

The OOB request and receipt are carried only by
CapabilityTerminalizationEnvelopeV2, using the separately derived
lane-terminalization HMAC key and the exact six-part hmac-E tuple. A generic
ControlEnvelopeV2 may transport that envelope but cannot authenticate a naked
close/revoke body. The request names the exact LaneControlTransportV2,
terminalization generation and prior genesis record. Its genesis and record-hash
purposes are explicitly registered. The receipt requires terminal plus quiescence
for close/revoke; uncertainty permits only actually available prefix receipts.

PublicationUncertainReceiptV2 always names reservedSlotId,
publicationReservationSha256 and a nonnull lastDurableCheckpointSha256.
These are the original pre-risk durable reservation/checkpoint, not a new
post-expiry publication. CleanupExpiryReceiptV2 requires nonnull P and therefore
rejects pre-plan; PrePlanCleanupExpiryReceiptV2 remains the only pre-plan expiry
receipt. No phase conversion manufactures a later plan or execution reference.

SnapshotTransportChunkV2 is the canonical frame header. Its detached frame is
u32be(header length) || header || u32be(payload length) || payload || raw32(HMAC).
The HMAC preimage is LD(D(SnapshotTransportChunkV2,frame-mac), [header, payload]).
The encoded maximum is 4+4096+4+65536+32=69672 bytes; header and payload bounds
are checked before slicing/parsing, and payload length/hash/offset must agree.
The pure frame verifier requires the exact pre-admitted header bytes; it does
not choose an identity, cursor, deadline or replay policy. The retained owner
must admit and consume each header once, under the original absolute deadline.
Wrong header/key, short/extra bytes, payload/tag mutation, zero or 65537-byte
payloads fail. Stateless successful MAC verification alone grants no operation.

The contract suite covers every registered schema's measured maximum metadata
and complete envelope body pairing, every missing/unknown/wrong-type field,
closed discriminated null arms, cross-schema retagging, typed-reference targets,
all signed/MAC envelope roundtrips and key/body mutations, and literal signature
KATs for Child/Guardian stream keys, LogicalAttach, ConstructionSettlement and
PrePlanAbort. Maximum fixtures are codec evidence, not authenticated runtime
object graphs. Per-schema reference-instance provenance, complete guardian
end-to-end operational KATs, and independent literal vectors for every remaining
envelope profile remain explicit pre-production verification obligations.
They are not claimed complete by a codec pass, and production execution stays
blocked until they and the actual adapters pass independent integrated review.

There is no currently executable independent visual-only hardware route.
Existing coordinator/runner hardware entry points remain deliberately blocked;
simulated four-stage success is not permission to bypass them with improvised
ports. This candidate neither enables annotation writing nor weakens PDF/mark/
SavedInk identity, pen lease, exact task/display ownership or rollback evidence.

All syscall/loader/OS-handle, isolated-owner, durable-CAS, native guardian and
wall-clock measurements remain unimplemented hardware-admission blockers.
The formal registry validates contract bytes only; it does not implement those
operations or establish cryptographic key provenance by itself.


### Measured canonical wire corpus (codec fixtures, NOT runtime authority)

Each row is the deterministic maximum fixture produced by the closed registry.
For envelopes, bytes and digest include the exact framed body; signatures/tags
are fixture values, not admitted provenance. The field/type/authentication row
is the same named entry in native_page_adapter_v2_schema_registry.py. The test
suite regenerates every row, validates its class and body pairing, and rejects
unregistered normative names. Detached raw payload framing has its separate
explicit bound; a header-only row does not include external file bytes.

<!-- BEGIN ADAPTER V2 CORPUS -->
| AckControlBindingV2 | E | SMALL | 793 | 73c9d80a89543e46a5c490fba0645b52c6ed86963fe6a9791c08d685fcb0cc2c |
| AckControlCloseBodyV2 | E | CONTROL | 827 | f1f94cb6a5b0043382e8f82dba306c68b0d69b31fa13497e1ef5d5bb1cdad8df |
| AckControlEnvelopeV2 | E | SMALL | 3397 | 21e829ca348315a2186ca3eb38d8510fac5eff41d714bb71a1a3b191bef0162d |
| AckControlFactoryBindingV2 | P | SMALL | 1125 | 511d6b0eb0eb17e07e8a796421af5db44d75af168e0ae5342b8c79ddc53423ec |
| AcquisitionAuthorityObservationV2 | X | CONTROL | 866 | 285b319f3e94b121e2afeb05d63a296c274eef2dafb8967da7e28c3f49775923 |
| AcquisitionReservationV2 | X | SMALL | 688 | e2beb01e17365324a7fe26ae3c21a42d453f52995b8e51dda0207cc90977d393 |
| AcquisitionResultV2 | X | SMALL | 753 | cc49b610fe49c86a5672d2a53f9d50ec20e34b204f1c67433ae79dadcab44c0a |
| AcquisitionSnapshotBodyV2 | X | LARGE-SNAPSHOT | 937693 | 14ac439ee4226e3c3cbbe1062cc368e834d69c7dbdf5c82926f010bb5c634df0 |
| AcquisitionSnapshotRefV2 | X | SMALL | 696 | 76312805cf9a51b00a1270d3269fe8c23b656b711628a0f96785b9790bf25313 |
| AcquisitionStateV2 | X | SMALL | 2203 | 48d89bacd8ec2999ae65e2e31e55e3142e2e106697833182c9505a725fa8031e |
| AcquisitionTokenV2 | X | SMALL | 666 | d875c76598d1f9ff95dc99f3d2899a36c27d083b95d5a8209d23ae0372731dbe |
| ActiveOperationCheckpointV2 | E | SMALL | 680 | 4b91400e855c5c8f7ea1ddc85806affc31b7fbae4103c10b486f6b078e985961 |
| AdapterLimitsV2 | S | SMALL | 438 | 943a7735a3845ca2234d8b5bdd367f78bf37a413a96349e0c4c2318ba4f7abbb |
| AdmissionProjectionV2 | E | SMALL | 683 | a828b87041567b799e00b9072f591950a0460a220315428ca159e2bc7f3b952d |
| AuthorityBarrierAcceptanceV2 | E | SMALL | 1162 | 6431ddadca2dbd47e3744920c00278104dbe55d2152e4a2b1a66885f5fb2b402 |
| AuthoritySnapshotFailureReceiptV2 | E | CONTROL | 4748 | 045184c99345b0979cc95eae5910e220e7d1746769c54eac89d9efba1dfa6cbd |
| AuthoritySnapshotReceiptV2 | E | CONTROL | 4523 | 8dcbe869cfc586034c10402dcd4e78b1aa4656357c0a9224b74ad09fc3130257 |
| BootstrapHandleEntryV2 | X | SMALL | 1033 | 6f27ed98583ca0832499de88c4250c19c314a79420032e8c5f220f406d9b0d8f |
| BootstrapHandleSetBodyV2 | X | LARGE | 530043 | 80d8921772b04b895dae8e7d5d1c780eab30ec6da969d684a7fb1b42d2610009 |
| BootstrapResumeReceiptV2 | E | CONTROL | 867 | c2ead6329f04574cafd78e2e2ad783830d0590fea509b041ef3afd3a7beb30ee |
| BootstrapValidationReceiptV2 | E | CONTROL | 902 | fb1579a8510167d85718469b143137e40e0294e3c961ddef8161a1f42ddde92e |
| BulkChunkHeaderV2 | E | SMALL | 852 | 93bff9b1b3775342c27b4949014376c0c364f140d5ecf987a45ae4f887b8f315 |
| BulkManifestBodyV2 | E | CONTROL | 1665 | c976b2ae2d08bbd74fa74b89bba78b80e7303615e2573cb06daa873afae3276e |
| BulkManifestEnvelopeV2 | E | SMALL | 2509 | bed6f19f5db9bc64962b18923b1ba54323fde343782dae12ce912608f2ee8ac4 |
| CallbackDeliveryAckV2 | E | SMALL | 803 | 71635973fddace064e76c012b43e9cd025da40ef44bbc492959fae1edbcfd5dd |
| CapabilityBindingBodyV2 | E | CONTROL | 767 | f1b107bc64824c5d46b87ff349259ae9a9cb5088e2799fef4c9f54252a53cfea |
| CapabilityOperationReceiptV2 | E | CONTROL | 4626 | 7231395b12e8bf99213f6e5afc78efa0c8b365b57f2f01624fcded808f9723e6 |
| CapabilityQuiescenceBodyV2 | E | CONTROL | 1071 | 87f5d50126fff366314e88b2ed1b661d1c134b8afd5529baef9efda967ec08e4 |
| CapabilityQuiescenceEnvelopeV2 | E | SMALL | 1746 | 0dcbe3ac3cba99a4723b6a1a606a70b1a5fa184ff0eebf0bfdc28e25b2476511 |
| CapabilityResultRefV2 | E | CONTROL | 1542 | 62a3067b2856e913dfa736f4808a134923615933dd9c43424a56d254f678ac57 |
| CapabilityTerminalBodyV2 | E | CONTROL | 1818 | d46f9ea96e84961ae0803c302b952edf64a4f73863d0d0fa905f946035759b95 |
| CapabilityTerminalEnvelopeV2 | E | SMALL | 2489 | c0938195a3c261db5535a12f3e5c5418cc43b80e5bd4740122f3f06a965001b0 |
| CapabilityTerminalizationEnvelopeV2 | E | SMALL | 2858 | 1137ab10904ddd9ce1df86e80328f8c4806a826b4ec824d3659b15fd6d25696a |
| CapabilityTerminalizationReceiptV2 | E | SMALL | 2254 | 8cbd56b763f21c605d48799160c63c992138d95ffbea27a30be3d51fd3cbaa3d |
| CapabilityTerminalizationRequestV2 | E | SMALL | 1944 | 9d465b97840b0a5eb1d8f6aa7ccff7735269df1fc8ca0c44eb875cee7969eee0 |
| CheckpointSubjectV2 | E | SMALL | 658 | 3cbb1b8426e1d1b6a23a330c3d0430372ccf49c175b79f2a7cbe85af1c6f9f1a |
| ChildStreamKeyAttestationBodyV2 | E | SMALL | 1395 | 233e1b9d9d337d61c24f3ad183409ab0c34fdfbd368dde0b5ce18a56ff5a1386 |
| ChildStreamKeyAttestationEnvelopeV2 | E | SMALL | 2158 | f0255334a927ac4098043baf412f8ccdf867e964eba3c992afa4f401bee3f6b8 |
| CleanupExpiryReceiptV2 | X | CONTROL | 1386 | 519c7e3a4d1bf3e690b8fb18a5c242d9926a03619e3b47d8ecbe915955451cc6 |
| CloseReceiptV2 | X | SMALL | 1020 | 70c5b14a26477c562338259c58a19accaa3301df39f6ea36087c360be7510d9d |
| CodecFixtureV2 | S | SMALL | 895 | 0d4922385afd159ee3952ec31dee62c0e8ab6923ecbf8650ae05f1fa954b766d |
| CompatibilityProjectionDescriptorV2 | E | SMALL | 538 | 0b4aed4e4862e7156ec45b0a099728a1413bff130142c8f5c4338e3fb3d820d0 |
| ConstructionSettlementBodyV2 | P | LARGE | 2301 | 9cf0c08f09d0ed7f0d3cb67d5d73efd96557bdcead374425e4cb612eadbef880 |
| ConstructionSettlementEnvelopeV2 | P | SMALL | 2958 | e6a7e6c5d4b6f5bcee178fc5017bb082ac3d1fcab3a7f35e6d08b8c6209d9404 |
| ControlEnvelopeV2 | E | SMALL | 736 | 0cc4c6a21f0b68c607afeb8803608e2db46461887fed2ee4e42bf133ddeb55eb |
| DataEndpointBindingV2 | E | SMALL | 1409 | adb944400ca32ac2f4f1153589bf598035592f2e8f4ee358b6238c11d1ffae7a |
| DependencyPinV2 | S | SMALL | 1380 | 99806b4f2e50608a336ce131f18a3e065e4c5c9787de62a3b255bb465ad2e836 |
| DetachedBulkReferenceV2 | E | SMALL | 577 | 6a358d4a6747b291a18b552bbeb5172d3c0a59b5e4d440d3c32a3ddb2f0cfb48 |
| DetachedPayloadV2 | E | SMALL | 626 | 1ed0087c48ad1afcfe26bac96166124348c6b1e15cd04e07e136fe7e808f0877 |
| DeviceStateEvidenceV2 | E | SMALL | 4096 | a712ed4328f92fedf20c3f5b3e2d4d5ee34b120b6eea3644a77b264c8718296c |
| EndpointAcceptV2 | E | SMALL | 723 | 8dc8a7f73aac47833f48f891190c01ba6ea4568385934b63834c1130a68e1345 |
| EndpointCloseReceiptV2 | X | SMALL | 1030 | 87c8ad0059431b1853817eabde182e477f9378f2dab870715d6aaa4aad63b1a7 |
| EndpointEofReceiptV2 | X | SMALL | 1094 | afd9b5ac50e8a3607695e135a38b6d0bb21dbafeea91e33dd61a0475b3a6b29f |
| EndpointFirstWriteGrantV2 | E | SMALL | 645 | 3bcd449fb9de00e53940115b97b2306145c6d0b3c5504e5f515b53025e52ee4e |
| EndpointHalfCloseReceiptV2 | X | SMALL | 1035 | 7fe2ab431541a4cb4dc650a0c7c555c81fc9a5b9149721ab588f0cf12b4020f1 |
| EndpointOfferV2 | E | SMALL | 1105 | d306bfe1ce7cc8063681bef57048c4e7e57cb211d5902d88a0443d5e081c2573 |
| EvidenceMapEntryV2 | E | SMALL | 565 | c41851f2439681b17731329d9b6643cabfe2a1797e0f8e5c5165011096c6ebbc |
| EvidenceMapV2 | E | CONTROL | 7057 | 983b744bb163badde591498467c31fc5e7e6150d43e010a0021efe12b555c085 |
| ExecutionAttestationEnvelopeV2 | E | SMALL | 2539 | 2181f9e75fc216285c0a33f0269a21669861206ffc9f161b3ad9a2c1a60c2e12 |
| ExecutionBindingBodyV2 | P | CONTROL | 1790 | b5803795be79a0a74c5d69d729c67783675d9d12e009bab24b202ee7bf8b3515 |
| ExitObservationV2 | S | SMALL | 142 | 8417bf087b9cc0de4d4de4fe8e08d5c25d5d859f38e71f98755695824f19c886 |
| FilePolicyV2 | S | CONTROL | 20631 | 3e564e68652df0e49e9eafbf64cb51d4d13bf9786b8cd469e1c10baba3269cbe |
| FileStatV2 | S | SMALL | 459 | dd67d8a17f03aa29ae7897ceb054c9efc583e759eedf47d4cf5a907486e93d3c |
| FileUriBindingV2 | E | CONTROL | 5872 | a8ba545d9e20935ed757f3cfde9ca23db6d0b96c3b79791b64c6b0ae8501200c |
| FirstFailureV2 | X | SMALL | 712 | d76ed0325f750ae3c0ba41e38570ea903a6af6e2e46917ec2bb81990ff49c9cc |
| FridaBarrierRecordV2 | E | SMALL | 703 | fb6297d7569b7ea4eb6a9a1055d0f6844be16fa38e2da5d9faa1e561903ff2c1 |
| FridaCallbackRecordV2 | E | SMALL | 799 | 9716b16a209384ea67ede74566d2903be6e79ee31ddf73d5bbf6659fb8d898b4 |
| FridaCompositeReceiptV2 | E | SMALL | 2778 | df8445b49343861cb2a18b266bcec238f01487e51a6d3b1dfde056e2db89b71e |
| FridaLogicalProjectionV2 | E | SMALL | 1075 | 52dc86e87f52b0100854483c00c10440b98d9eedc13c3d25eb6d764973ac9a61 |
| FridaPhysicalSettlementBodyV2 | E | CONTROL | 6350 | 800ff70f881b2a78a41e26375560178998c370f3b9921e8991f811c065f59e94 |
| FridaPhysicalSettlementEnvelopeV2 | E | SMALL | 7031 | 710636cfa3a42701e0fac6cd00904841b577dd374080acda79023faf15bf1884 |
| FridaPhysicalStepReceiptV2 | E | SMALL | 1609 | 28876c73bb19588dd1564d9934a6016ab4dd58edd75115adb32887374b32562f |
| FridaStepDispositionV2 | E | SMALL | 441 | 170508436dfd26b72150a8a048b10092c01a73bf4b8b18c4ffa7e2c9e1088070 |
| FridaStepResultV2 | E | SMALL | 1187 | 8ced565a9cb45c918c7ad2fae819e4f20473bc22728e59a4174365f5a6c98ca8 |
| GuardianAbsenceAfterEvidenceV2 | E | SMALL | 1488 | 76a2755feef5979ac6a1ba92cde326eeb9da28d7a50c39716db3966c1944288a |
| GuardianAbsenceBeforeEvidenceV2 | E | SMALL | 1389 | 66250a1c0d1a5c303450ba50ab39a3ed748338410e0a0eb0ce5c1e923fed47af |
| GuardianAbsenceBodyV2 | E | SMALL | 1294 | edff3db74422b219fa094393b2bb7d3988b785f0f79c542ade4d7bed688e1b9f |
| GuardianCancelV2 | E | SMALL | 621 | d4a9209caadb344e139ba02e3363d0b7ce67c255f7e3e024692564cc0088031c |
| GuardianChunkAadV2 | E | SMALL | 666 | 323db698693504a12f697d2599494e7735effafed9684afd2878f52b81d5a91f |
| GuardianCloseBodyV2 | E | CONTROL | 1859 | a735900a1eb532c8a0d66e44aac2ba78b7931e648b5e426347cc5910ebb52301 |
| GuardianClosureRefV2 | E | CONTROL | 3692 | be97613c3599d070d887f3bb4a65650d93efb7771294d7359b86b87cc53ce7f9 |
| GuardianControlBodyV2 | E | SMALL | 1091 | c2c48aec651dbf74a1ca44ca98824fc7bc53ad1b179e179c7f3a76f2161e19c2 |
| GuardianControlCloseV2 | E | SMALL | 1441 | c2deb20d05a4b8293f0aca58e60f438cc81efdf7092c80f901dd02a2977a7c25 |
| GuardianControlEnvelopeV2 | E | SMALL | 2037 | 37207ec64cc68050d6e447440c8048364d92d1b7b60b198c62ab905d97d153da |
| GuardianControlKeySwitchV2 | E | SMALL | 1079 | 0067bbf08d661e87998f22627a7a3ebf9b7df431a60d27c0ce984869ca7ada12 |
| GuardianEndpointIdentityV2 | S | SMALL | 699 | c5ebda5bdce6a90970ee8515a15844f03f258652abf937a42cb88eb1243a24fd |
| GuardianFdAcquisitionBodyV2 | E | CONTROL | 1267 | 7a1f237ece2a0d90f22be2877c3d9b2654d5fe776e89505ccbffca87672482f6 |
| GuardianFdIncarnationV2 | E | SMALL | 984 | 7097361abd96ba58c36bcd170f47520e8ad1ea23b49d421b183587f0790615bd |
| GuardianFdReservationBodyV2 | E | SMALL | 890 | 20a559ee075b05554b0b27d67886fbeb584e65385d581e862bd98121950a35d8 |
| GuardianFileDigestEvidenceV2 | E | CONTROL | 7925 | a084927be685dce3a4dd6de15d4fac094afe5a595e5e605e190a9cf1128c14c8 |
| GuardianFilePolicyV2 | S | SMALL | 4096 | c17f48afda2ffb702e99671bd9c5fbfdb099c1993ff77ae6c3187b999198c277 |
| GuardianHalfCloseV2 | E | SMALL | 683 | f1dcbcbcb597b0beda21198834dea1f4d35615d2f0a2e0f486079c3474182c6c |
| GuardianHopBindingV2 | E | SMALL | 1463 | 84f42de149400410ca98f0ae2293292ac221ed8e34291bc868c83e20393fd999 |
| GuardianHopSettlementAckV2 | E | SMALL | 1028 | 401abd063d9f42ba6efaa7b6ee319e7fb40e5c8882feff261d34960a53d7fa26 |
| GuardianHopTerminalBodyV2 | E | CONTROL | 2058 | 4b6171ecbcf8dbc0b0a2e393785f14078a6c0222b4ece12b8bbb7b93b5173568 |
| GuardianHopTerminalEnvelopeV2 | E | SMALL | 2733 | 75fc3171fda3c2627d67128dc56b72c3a2da99380e45b256dd3dc8f779bb0f1f |
| GuardianImagePinV2 | S | CONTROL | 65536 | 40e56136a01469317937c798ec393d9a1865a40fda6a2b927ae2a7a568690d36 |
| GuardianKeyChallengeV2 | E | SMALL | 802 | 47c86a587ac48b228462dfddfa9a57a8e6fdae314cc1c7cba6d892d21e4fe6c0 |
| GuardianKeyConfirmationV2 | E | SMALL | 613 | 95b1f45a70ff670efcb88e5b363763d02b6d13456a051c05013125da439d3871 |
| GuardianKeyContextV2 | E | SMALL | 965 | 1ade034480825f1c941dce7af526379cc3e5f4980b46cd87f692495f50fdfde7 |
| GuardianLeaseGrantV2 | E | SMALL | 829 | 2c8c4d453fa09c1b3bd330b4bb00c21d75cfdcc0416969d66744862dddfa824f |
| GuardianOpenBodyV2 | E | CONTROL | 7472 | c4495d04eb881d26c0ca22111736faf67ed06a595b302bae626ed37547b52f75 |
| GuardianProcessClosureReceiptV2 | E | SMALL | 979 | c76377c0e76957d932bfe6576ce77e79c16b740b4e3f5d155f3e7bcb3097564c |
| GuardianProcessSubjectV2 | E | CONTROL | 956 | dbb07d77b2ea9ca615f11e87b4a8acf5728147a45669bd1bf404b8b10b56fbd6 |
| GuardianReadEpochTerminalBodyV2 | E | CONTROL | 3815 | d870008d1b82960473490c40f5a83c046392bf43343a66e5560a34bfdc13133a |
| GuardianRelayHeaderV2 | E | SMALL | 885 | 68f5fabd1e97e2558f6661e8ed0cb738f5e38a5c7d2a2469e81097190cc39d07 |
| GuardianStreamAcceptV2 | E | SMALL | 736 | 54b2e45ddd6be544f93aa91e940e261a470b78b1ba9c8d3a4ddebb19f3bc3054 |
| GuardianStreamChunkBodyV2 | E | SMALL | 948 | b1c11845b323e09c994af851f7129d06c8429a68a64a68340ade8c667ddc0dae |
| GuardianStreamGrantV2 | E | SMALL | 845 | 90933fedeeb7bfc85c4090ebce7d9bda62d262f236ae1a82b448284bc239fbbd |
| GuardianStreamKeyAttestationBodyV2 | E | SMALL | 1392 | b396af982cac1f88286388bc08a0cc92963460dd500e0b20e945e640e305b919 |
| GuardianStreamKeyAttestationEnvelopeV2 | E | SMALL | 2161 | beb840bcb10076b2cfd716839c3ef56c3123429a213422d31005f38aa19884f7 |
| GuardianStreamOfferV2 | E | SMALL | 918 | a92bee1d7af955f23dc3014123691bb25196a6451a7356474c410dcd1b0eaf9c |
| GuardianStreamReservationV2 | E | SMALL | 961 | c56a1a9806d33a9d383ab67417f2dea953c7980d051ffc8025c6d2e261219790 |
| GuardianSyscallReceiptV2 | E | SMALL | 955 | 08991ea78c485dd983e72b9ed278b62c7773e2bc531c82cbd8179f3b57860a2c |
| GuardianTransportBindingV2 | E | CONTROL | 930 | d3022e69761f6cf9403cfadd79d66968d5145908c1febfdad4503a3eda9c0578 |
| HopFactoryBindingV2 | P | SMALL | 797 | 4e0a0501d372688d98d13bb496a3ebf1a8792da6a465b0468d529188b23e1147 |
| HostPolicyV2 | S | SMALL | 1131 | ce4e60f5e53708866747d706e13d77c1f75e3e6c2b56ffd712c705508d701010 |
| InitialFileObservationV2 | E | SMALL | 792 | ae4844da4ff03a4ea7429999e14c85402b959cc233b3aacbc70581c4c4c529e5 |
| InlineTerminalBodyV2 | E | CONTROL | 1484 | 041ad96ce865ca5149d0bb36a8593ba2fb8cd8b95fb83cbada3e86c8841dc96d |
| InlineTerminalEnvelopeV2 | E | SMALL | 2332 | cdb08ed3d390f4257552ea13423b59dae62031919cc500a6e4f313d9faf7742d |
| InlineTranscriptBodyV2 | E | SMALL | 914 | 2ed5ce19ab6a34e32fba9bbfa25375df34f0302b71421adf4b4bc846fa77998f |
| JobAssignmentReceiptV2 | P | SMALL | 714 | b1bab29c1a1e8c3773061c5d794c3bf479bac9027cb6a9c6a59c7186ce68ff55 |
| JobEmptyReceiptV2 | X | SMALL | 1071 | 8b5e7bd94aff0a12917b4fb3bb7f99ec13e9b10354b97f6137a383258e417707 |
| JobIdentityV2 | S | SMALL | 460 | b42bca9ecb7dad9e081ccd051838ba252e7fd37e70ad3e7c3a77dccfb01be5b1 |
| JobMemberSetV2 | S | CONTROL | 637 | 3083ba3efee61ac5f0984e3dae1b3209256e4fb2b745bd26a2250dfb7d976433 |
| JoinReceiptV2 | X | SMALL | 1076 | 9be122407ddff18da692ac2763a91c942f29dd7dd5d7d19d79a204c9dba6fe4d |
| KeyDestructionObservationV2 | S | SMALL | 298 | a2d36e98b2c44b70b0208d4cf2d3a4125f4d3594bc440bb071892c23436e8063 |
| KeyDestructionReceiptV2 | X | SMALL | 1086 | 9341e1fe3a1cd6a31d770b1ae74e17a8e45d582d86446fc3725bce6ae4b2aade |
| LaneBindingBodyV2 | P | CONTROL | 2708 | ae039251315ae811b3eae30d007b647e8dae773d8e86da566ad2c76d57fe98cc |
| LaneClosureRefV2 | E | CONTROL | 1342 | daccf7103e985a2aecce32bc45073bf324b94641ed75dcbbec8529a36322fd5a |
| LaneControlTransportV2 | P | CONTROL | 595 | c1493cf080118cdd55e2873adb4638ca91e9dd55aa50823cf98b7be34ed9f9d9 |
| LaneNeverStartedReceiptV2 | E | CONTROL | 899 | 56d08bf2cfa68ff241312d8ba6b18ce60236efbd37625ba43c06b02ca2a947eb |
| LiveHostBindingV2 | E | SMALL | 1085 | 994628249594f34aed19eca244bc24112ead7586d13f6f727746990b730f0f8f |
| LiveTargetBindingV2 | E | SMALL | 1025 | 94a749df151e648b74c02768505afcd1e685be753f6073abd58a85274892dd94 |
| LocalFailureMappingV2 | E | SMALL | 599 | 663cd7090ef08741c2a89b703e8d732187d324cfd99d707f50cca046f04ac69d |
| LogicalAttachBindingEnvelopeV2 | E | SMALL | 3268 | 248cde4d197cb9f4e2c91a05454fff1a5d7f280688841f7d677d53f724ee5662 |
| LogicalAttachBindingV2 | E | SMALL | 2519 | 676960f7fa2f3bda7e4f7d487b88988b1c9defcd9fff2a916f9e64b9dbfae182 |
| LogicalFailureBodyV2 | E | SMALL | 603 | 12c470369d2ba89cbe67aa5af2a1db822cfbe5b0b2c5182fd94c9e3f696187a0 |
| LogicalFailurePolicyV2 | E | SMALL | 633 | 1ae5ecff8f49fbb48275cd06a65bad1f6629c1d419826331f2919c67b5b12b6b |
| LogicalMethodReceiptBodyV2 | E | CONTROL | 1889 | 64e59e22e86384f524f77e42ed1d8f4f194b4e8c3d89a2badad37a0f1b86bb9f |
| LogicalReceiptTemplateV2 | E | SMALL | 1221 | 4a67348d823c5f0807b52dd3f911550b180e3e98010873ed070e8243b2c13b0b |
| MissingLayerTerminalBodyV2 | E | CONTROL | 10530 | 08ce822460cf5a3fee4f93f02ddb69cd063ad4f68918b3c96beb220eea72d65f |
| MissingServiceTerminalReceiptV2 | E | SMALL | 572 | 45631910b964fbca544b745811a540fd1e76daf2ed7a07caed78a6ef5d02a0db |
| NativePageCompatibilityFailureProjectionV2 | E | PROJECTION | 22663 | be9c92d7cef228d42a0322ddc214424f1601ff0bf7b2152bd21da68e9551c001 |
| NativePageCompatibilityProjectionV2 | E | PROJECTION | 64865 | 5e1a5b5133c5d81c10746bc8baefcea6f8dd29340e303d0468ef0af6180db724 |
| OperationLeaseV2 | E | SMALL | 656 | db4ee06a4072ec6f60c3c417eb5ed32905d290e4066fff44c8a1a8235c072b83 |
| OrchestrationPolicyV2 | S | SMALL | 283 | 8c90c9c0f33404a7f7802b3831081e2c145ee871ec409b5c96fbd69e746dba2d |
| OuterControlBindingBodyV2 | X | SMALL | 1155 | 7f2736691542aa81fc13143034482275fb89d7e48b3f6c4d1bff70aaa7cd0d60 |
| OwnerActivityObservationV2 | S | SMALL | 201 | 2de6eebd31d15d44a3cfce0ce04786af3d15313943f07ab63a03f817249c6a86 |
| OwnerQuiescenceReceiptV2 | X | SMALL | 1088 | a4f6250b6e0adc0bbcc61ce1ee934ee81d0ccd316665c593a55e932baafeecca |
| PBoundObservationEnvelopeV2 | P | SMALL | 1783 | 8b36e2c55119cd3c83a6075ed75f9519f7fd00d757ebdea8a86d4d588e00c2bc |
| ParsedAuthorityV2 | E | CONTROL | 19478 | d7d26add6b412055e9d99966138ce01111c99493149b7eaa261dca4cdab2a4fb |
| ParsedTranscriptEvidenceV2 | E | CONTROL | 860 | 34b43ef617d57fbb5bc55c343185c1d67808cf7cc6e7732506a2c1a17577ebdf |
| PathResolutionObservationV2 | S | CONTROL | 3552 | 58bdd903fff11ae0a232d853e3c314033fb4e9d182e22df3a58b928881c333f3 |
| PathResolutionReceiptV2 | X | SMALL | 1091 | c731b470dc358ca24b37841e546035c358b7219d6561fce1dbdeb14a9d82539c |
| PenLeaseSubjectV2 | E | SMALL | 825 | 26b386aba28c2defe8634da02569e66f2b72370b241abf7d1883e7277578e1f4 |
| PendingTransferSnapshotV2 | E | CONTROL | 2299 | 91ef11f7885d6e07a8c449ce9777f49b159990852c2dd5ad9397bc2892f802e4 |
| PhaseOpenEvidenceV2 | E | CONTROL | 1239 | 5f31df990686ca2ddcf454c35b7448ac30935b76f34eb8ce66985139d504f2ea |
| PhaseSealEvidenceV2 | E | CONTROL | 1676 | 32ba8d12eaea1f7eb58849e98db8af3f82a7081cf06c69b6944cd8479bc075f7 |
| PhysicalClosureProjectionV2 | E | CONTROL | 1806 | 97879c1a887c71ee0783bb681742afcd20e57f0826da856107c7d23e0c324e02 |
| PlacementSubjectV2 | E | CONTROL | 943 | 9dbc6117f3ebfb970b3ed2eaea686a2e0b9e95a5f6fcef06200d7f888cbf364b |
| PlanCoreV2 | S | LARGE | 910873 | 33db17c51329590bac3d9b438a23d515f1b5bb043dbad1def4c356f5a3509335 |
| PlatformObservationEnvelopeV2 | X | SMALL | 1974 | 4dda754dc42734486b9555f6c6b693d983f6b0a703b26581d93fd83f1eaa9b6d |
| PlatformObservationV2 | X | SMALL | 1127 | 9185bed7832d2979712e70df2264766b23eb16bb6601fbecb7e59cfe077865ca |
| PreAttachSelectorCommitV2 | E | CONTROL | 1281 | 8e14e9deba4209a1b8336e5bbcb1739a37300750959ff6c255cede4404a877d9 |
| PreGateRetainedHandleRootBodyV2 | E | CONTROL | 804 | 81e41e8d6ed6ab4735b892153b15315be18414795e66596dc03a4a3572761477 |
| PrePlanAbortBodyV2 | N | LARGE | 2061 | 77fc7c72d3d6bd1b8feba7227246ee9fe986a6cbc4345e79eef2f97f6a2a0dbe |
| PrePlanAbortEnvelopeV2 | N | SMALL | 2698 | c28b1a040aff48f8113cd1ea8918ef34600965af9327fed194f81a32140b32e0 |
| PrePlanCleanupExpiryEnvelopeV2 | N | SMALL | 2845 | b6c08f9b92c4ebe9dc1fd5a3e51017b4c4cef6eeb731f90a0daa695108722ebe |
| PrePlanCleanupExpiryReceiptV2 | N | CONTROL | 2189 | 0de44fa8e839359bd0bc959340fbf4e59d05384e7666f7648e0140fb82e3f069 |
| PrivateAdbSubjectV2 | E | SMALL | 870 | a5d048f3010f837090ab925f8bdb838b838e96635fc0e868f1e42ed226c930bd |
| ProcessIdentityV2 | S | SMALL | 434 | 384c8ca3c4e6c26b508c373e633508e938427a199fa8a8ab0c5cea41f301db70 |
| ProcessImagePinV2 | S | CONTROL | 65536 | faf5ebd4a52aaeeef2ed897cd7a639e2252396d1b1c79bca4e75a1e196a3e8ca |
| ProcessResumeReceiptV2 | E | SMALL | 843 | 7b7f6143dda6954d03ce1b55539740f04f84f1cf1563cbf549bb1aff19b3fe8e |
| PublicationUncertainReceiptV2 | X | SMALL | 964 | 017589ff0ee6f7f035c42748de2d3cf9fc07fbd30dabaccce5012874c6922dd6 |
| RemainingEmitterStateV2 | E | CONTROL | 761 | 8ff1c87e628f6600a4a18a7113708cba0bd797f8deab249a3e4dbbc5fd7051ba |
| RequesterBridgeBodyV2 | E | CONTROL | 1490 | 33168d5e1dd6dcacc9f2fd43c3c93a203acd87c8a79aacf5e3fa25263a2cf26a |
| RequesterTerminalBodyV2 | E | LARGE | 2699 | 52ac85f01d3e6ac45ec14c02e5a943c9be24c6b920b94b734d26c04d9fe094e4 |
| RequesterTerminalRegistryV2 | E | CONTROL | 2942 | 43ce889088e126c07ac095928f786c5ce8d8c366f307ba670b97093826d6b984 |
| SameFdObservationV2 | S | SMALL | 458 | 3a9b20dc4ec232532197b4e3fbb3a18a3957b5c3b0e8ba7d09334f183dad3d99 |
| SameFdReceiptV2 | X | SMALL | 1077 | 1469b37d4d0bd7eda81b1fd1970d809e3b46e61f0ccf2b0fdb91a498bb73f9db |
| SelectorSubjectV2 | E | CONTROL | 1598 | bc808d477ca9914946851b746104d795cd120f4fca6798cdba2f7027371ea07f |
| ServiceBootstrapEffectReceiptV2 | P | SMALL | 772 | b390fc0c6f6424f9902e251240737754731978597148374ba62fa7b7c72fffda |
| ServiceBootstrapResumeReceiptV2 | P | SMALL | 782 | 20b5c6d82efc373f3e96231a737b820fab43d45ecd7c7aa50fd7e24d5d35126f |
| ServiceExecutionValidationReceiptV2 | E | SMALL | 872 | c87be8516f30fde622002f5584f248675d9e734f048320e1660f73ce90f540da |
| ServiceGlobalRecordV2 | E | CONTROL | 739 | 3f3a94c7525be77f85e1786056d81122d744159382e9bfcba0beb24ca4d022db |
| ServiceKeyBootstrapReceiptV2 | P | SMALL | 1044 | b8bbba5d7ad0f8258252635e2667c9dd603fb579a04e7d1839c4ec0cdea1a2e0 |
| ServiceObservationV2 | E | CONTROL | 589 | ec6979745151c43e66dd422ce5d41918309425ec7c42d2db7944e88ffe11b947 |
| ServiceTerminalBodyV2 | E | LARGE | 5187 | 2279376a0f7c5ad0485f2eb3b9fc2db8cf88534aa4fbbeef6aa675a3e4074edb |
| ServiceTerminalEnvelopeV2 | E | SMALL | 5926 | 33c9eff4b9161862e03a526732835744444914d4debda4f316558690692587e9 |
| SettlementAckEnvelopeV2 | E | SMALL | 2055 | 5ca9fd3952828b793dd7fb7efdfb3af816650640f6f4732c25e8f326f6be5b48 |
| SettlementAckV2 | E | SMALL | 1187 | 146216312bc8389947ccabdb9a07ada835f8dd28c3ba0bd913ab91b5c537d3a2 |
| SlotEvidenceBodyV2 | E | CONTROL | 27606 | 88a68bb7b9cd27fdff1943cf89f9dc1f0e77d0e97d45bb51e2ef7a1179c64c6c |
| SlotEvidenceEnvelopeV2 | E | SMALL | 28266 | 1e611201535288efe1d1d42e80be9978d29d6162d3194ac7892da3e0c9329c17 |
| SnapshotTransportAttestationEnvelopeV2 | X | SMALL | 2275 | b0fac196eb89400d6df5b87196eccc18f0d1edb9a4dbba06b1f2e4bcb0e5d839 |
| SnapshotTransportBindingV2 | X | CONTROL | 1414 | 71f7d88f3174f0098ca249c4baa6439e5ad5ae77cdc91cd99de2648533b8ae38 |
| SnapshotTransportChunkV2 | X | SMALL | 823 | 1433f49ab888cebda29dc24c099c4c0d5be1ee9490ff6e7b438fddf39e13a928 |
| SnapshotTransportControlEnvelopeV2 | X | SMALL | 2451 | de621657f7a5f01d70b3aaee8a7030f8e5f6868395131ea1b3e75ea4d8970d59 |
| SnapshotTransportSettlementV2 | X | CONTROL | 1110 | 9afda38e8d0e0aac8f307e8ee3f9926fca7b06ae34a4c1393af11d1f91d7543f |
| SnapshotTransportTerminalV2 | X | CONTROL | 1646 | 09ef0b182dbfaa4917ca0a83bd641abbaf5de807f4f0200831ed8569a07e3e7b |
| SpoolIdentityV2 | E | SMALL | 662 | fad239d29a740a71be77b5d30f36f8c657487bc50acf07de243bb015bf91edda |
| StabilityComparisonV2 | E | SMALL | 490 | 8075c191062de5f3b082c4afbd03a3f0fad7c2cacf8c089033362efedee9fac2 |
| StabilityPolicyV2 | S | CONTROL | 652 | 154aef7bd30f81ff0d3c1d0bc251b8dafbd32a39676d48bc6697f965ff06a366 |
| StabilityResultV2 | E | CONTROL | 14111 | f851bd79e4b76c9bd14c70d75f28c03bb4af0a5e1b4d7b9a5283d97aa1526782 |
| StageProjectionV2 | E | CONTROL | 20438 | f55e61160a7ea1720134c5b89fb945fa042d4b2651ff42fadbe443c17179fc3d |
| StreamEndObservationV2 | S | SMALL | 241 | 9ac9006fbe22071b77fd606c3f9a9ffa1d72bb770a0f436967cb5e7f70555d4c |
| SuccessSealV2 | E | SMALL | 1166 | b52ccee7134d9be6aaaba43a6df91a094d7b5e49d0b2941b970dd0cc555596e1 |
| SupervisorClosureBodyV2 | E | LARGE | 21750 | 8cc075cd295da1e1d3e2b3cb2c68f24d1b27eb6c55aa1f9db8685b4f69a2fb5d |
| SupervisorClosureEnvelopeV2 | E | SMALL | 22498 | c2aba8e22980a61ccf0cd01239810e43cec5624e5c469facdfdb75fb340ad01b |
| SupervisorDetachedAttestationBodyV2 | E | CONTROL | 994 | 73d7fd6d17d8fe1fdcedae024f75a44565a1403716c3338ca3cff4dc54cc3a0d |
| SupervisorDetachedAttestationEnvelopeV2 | E | SMALL | 1774 | a2579659d8e33b2bdb4535270f3416152ceeaeffd84979417e82ea44e7290034 |
| SupervisorKeyAttestationBodyV2 | P | CONTROL | 647 | 70c832da66e6624728e3296315ab070592ace0d0e80af8767928b1e0e197c5ea |
| SupervisorKeyAttestationEnvelopeV2 | P | SMALL | 1312 | aa6facdd13a895ed3ba51a6d376abb27b25a3d2bd68d97748572521ec6548bd7 |
| TargetPolicyV2 | S | CONTROL | 5463 | 6945e0c4ecf1dfa51c2c50c8e11961057822ac8176c7542e7a1607590e4a74cb |
| TargetProcessEvidenceV2 | E | CONTROL | 1576 | e564c4666b7513b0ab804bc9691d226e577170dc0e5121b29dd4ae9fe9c8f7a5 |
| ToolBundleSubjectV2 | E | CONTROL | 65536 | 398d3673996d4f4a09924a55417b835c77d70de34f5ee8f47d753701da199b6d |
| TranscriptAbandonmentV2 | E | CONTROL | 1870 | 2467552f9b6f19e4b52e1293fe0494493d0ef827c0cf2ccf905b13cc5033e49f |
| TranscriptAdmissionBodyV2 | E | CONTROL | 1074 | 4f982bc34ca202ec6fbad579ac4d67e95e255475644c4c3288fd6b6881d03864 |
| TranscriptForwardReceiptV2 | E | SMALL | 757 | 2d8c36b4e5f4a773ecc7502e087a60983a173f682be4f4559ec0842b5b33c2d6 |
| TranscriptHopClosureV2 | E | CONTROL | 16272 | b18d1bfa0140484adb3c6524c176121c0e375a1b2363201df2e4e4376ffb96ed |
| TranscriptRefSetV2 | E | CONTROL | 18908 | 2371cec48b15deeaa2a12c8fe2c30621773f693179b5a2faede5a6062cb6baa3 |
| TranscriptRefV2 | E | SMALL | 1164 | 8d7a27bfb391086838ad3ffd7c9d41df09779a771de5e5c4470b9449b7985faf |
| TranscriptReservationV2 | E | CONTROL | 542 | c7875cbe72d5d30e037de51d28708a632e8a181135ca342f4aee3ca8d8d781db |
| TrustAnchorPinV2 | S | SMALL | 284 | 45a06686a425940da63366a8305c63d05928f5c917e4a54032ee536389ab5b04 |
| VerifierCrashRequesterBodyV2 | E | LARGE | 6627 | cb9c6cdbdf3f2647b1617f066a7085cfd35d454c7bc7dc69060d83f61e535740 |
| WindowsObjectIdentityV2 | X | SMALL | 1029 | 087e4bc3ba73005cb6e5bcc0ff671e5acb3b27162732258fcd0c2c2237cdfc56 |
| WorkGateBodyV2 | E | CONTROL | 962 | 08e6a1f1fa2a67fe798a4dc5d8102b2959f7bde7c3a763a0b2fc5ab0e3c18b90 |
| WorkerImagePinV2 | S | LARGE | 178496 | ea69128f3998333b64380f1893954e2191ff109d4e7a1c1f4eeb3a869689fa49 |
| ZeroAuthorityHandleSetBodyV2 | X | SMALL | 816 | cd61734535a2b8e944e45ccbdb6b5e8665a583a423218ed2cd427995f57d2566 |
<!-- END ADAPTER V2 CORPUS -->
