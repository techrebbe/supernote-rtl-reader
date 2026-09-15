# Native-page visual task adapter

## Status and scope

`native_page_visual_task_adapter.py` is a host-only implementation of the
visual session harness's `TaskAuthority` protocol. It performs no I/O on
import and contains no ADB transport, shell executor, Android binder client,
filesystem reader, process launcher, or device discovery. All low-level work
must come from an injected `FixedTaskBackend` that has been retained and
reviewed separately.

This implementation does **not** make a hardware run ready. Its
`admission_status()` remains false because this repository still lacks a real
reviewed fixed-operation backend/bootstrap, measured hardware timing, and the
integrated exact-head review. The existing visual-harness blocker must remain
in place.

## Immutable authority

`ExactFixtureTaskPlan` pins:

- the harness session UUID;
- the one authorized serial;
- the restricted disposable fixture file URI and lowercase SHA-256;
- the exact retained monotonic-clock domain SHA-256 shared with the visual
  session plan, HostAuthority provider, and semantic observer;
- the harness absolute monotonic deadline and a smaller per-operation budget;
- either a pre-pinned positive display ID or the policy to bind exactly one
  positive ID on the one launch call.

The runtime display-binding mode is needed because `HostAuthority` allocates
the virtual display inside `VisualSessionHarness.run()`, after adapter digests
have already been pinned. The bound ID is carried by an internally minted
`ExactLaunchScope`, is checked against the strict post-launch
ActivityManager authority, and cannot change. Binding it does not change the
adapter's canonical bytes.

`TaskBackendBinding` retains the backend instance, device boot, private ADB
server, and isolated worker identities. It admits only a loopback private ADB
endpoint and requires all of these properties:

- explicit serial on every operation;
- retained private-server and worker handles;
- fixed operations and fresh sealed reply channels;
- mandatory pre-dispatch witnesses and post-operation quiescence;
- exact URI/SHA, display, non-exported-component, and compare-before-remove
  gates;
- complete ActivityManager and exact kernel process-liveness evidence;
- no general command or caller-argv input;
- no broad cleanup or process-kill capability.

The adapter retains the exact injected backend object as well as its canonical
binding. Every backend method is invoked through that retained object, with
object identity checked before and after the call (including exceptional
returns). A different object is rejected even if it reproduces the same
binding bytes. Any object substitution, PID/start-time, worker image, session,
boot, endpoint, or policy drift fails closed before a replacement can receive
a request.

Time is supplied by a retained authority, not a bare callback. Its canonical
bytes have a strict closed topology containing a retained clock instance and
monotonic-domain SHA-256. The adapter retains both the clock object and its
canonical bytes, binds their digest and domain into its own canonical bytes,
and calls `verify()` before and after each clock read. Object substitution,
canonical-byte drift, domain drift, failed verification, regression, a stalled
request clock, or a request-time jump larger than the bounded operation budget
fails before backend dispatch. The task plan and clock must name the same
domain; the harness independently requires that domain to equal the retained
HostAuthority provider and semantic-observer domains.

## Fixed backend surface

The low-level protocol has only these effect-specific calls:

1. `launch_exact_nonexported_document(request, scope, dispatch_witness)`
2. `remove_exact_retained_task(request, foreign, dispatch_witness)`
3. `prove_exact_task_absent(request, foreign)`

It also has binding verification and operation/all-operation quiescence
checks. There is intentionally no method that accepts command text, argv,
shell fragments, free-form package/process selectors, arbitrary paths, or an
unbounded payload. Caller values received through the harness are compared to
the immutable plan; the backend receives only adapter-created frozen typed
objects.

The future reviewed backend must invoke the mutation witness immediately
before the irreversible dispatch. For removal, it must first compare the
fresh task/token/PID/start-ticks/UID/display identity with the retained
`ForeignIdentity`; a mismatch must return before invoking the witness. The
Python layer validates the same pre-removal evidence again, but this later
validation is defense in depth and cannot replace the backend's pre-dispatch
gate.

## Launch transaction

The adapter consumes launch authority once and checks the exact serial,
fixture URI, fixture hash, display, and plan deadline. It then issues a
bounded request tied to the session, boot, backend digest, lifecycle
generation, entry generation, sequence, argument digest, and operation ID.

The accepted backend receipt must attest:

- explicit `ACTION_VIEW` of the stock full `DocumentActivity` component;
- `application/pdf`, exact fixture URI/SHA, and exact display;
- a non-exported component route with fixture bytes hashed before dispatch;
- no user document selection, caller command input, broad scope, or process
  kill;
- a fresh complete ActivityManager capture and shell-UID normalized kernel
  process evidence inside the trusted monotonic bracket.

`native_page_android_authority.parse_document_task_authority()` parses the
fresh ActivityManager bytes with `require_live=True`. The adapter requires the
stock package/process/UID/base APK, the exact display, canonical 1404 x 1872
at 300 dpi/rotation 0, and the matching PID. It combines the parser's task ID
and activity token with the process evidence's PID/start-ticks/UID/package and
the parser's stable semantic digest to create the retained
`host.ForeignIdentity`. The returned value is the harness's exact
`LaunchReceipt` type.

## Honest launch failure classification

The dispatch witness prevents a transport exception from being mislabeled:

| Observation | Raised result | Meaning |
| --- | --- | --- |
| Local validation fails, or backend fails before the witness and proves operation quiescence | `LaunchNotDispatched` | `side_effect_possible` is false; no task identity is invented. |
| Witness was attempted/seen, repeated, late, or operation quiescence/identity becomes uncertain | `LaunchOutcomeUncertain` | A task may exist; no broad or guessed cleanup is authorized. |
| Strict post-launch task/process identity is derivable but another launch attestation fails | `LaunchOutcomeUncertain` with `retained_foreign` | Exact cleanup may use only that retained identity. |

A successful return without exactly one witness is also uncertain. There is
no retry path. `LaunchOutcomeUncertain` subclasses the harness-owned
`TaskLaunchOutcomeUncertain`; its base class constructs immutable bounded
canonical evidence and optionally carries the exact parser-derived
`ForeignIdentity`. The harness catches only that type, re-verifies the throwing
adapter, validates the full stock task/process identity domain, and takes exact
cleanup ownership before publishing the uncertainty artifact or operation
result. An unknown, malformed, untyped-lookalike, or post-throw drifted result
keeps the task-creation obligation unknown and cannot authorize guessed cleanup.

## Exact teardown and final quiescence

`destroy_exact_task()` accepts only the retained `ForeignIdentity` and passes
that retained object—not a caller substitute—to the fixed backend. A valid
closure requires:

- fresh pre-removal strict ActivityManager authority equal to the retained
  task/token/PID/display stable identity;
- matching pre-removal kernel PID/start-ticks/UID/package evidence;
- one witnessed `removeTask`-equivalent dispatch for only the retained task
  ID;
- no package selector, wildcard, force-stop, caller command input, broad
  scope, or process kill;
- fresh post-removal ActivityManager evidence with the retained task/token and
  all stock `DocumentActivity` records absent;
- the exact retained stock process still alive with the same PID/start-ticks,
  UID, package, device boot, and shell-UID read-only evidence.

Those checks produce the harness's exact `TaskClosure` with
`task_absent=True`, `stock_process_alive=True`, `broad_scope_used=False`, and
`process_kill_used=False`.

`assert_quiescent()` performs another fixed read-only absence/liveness
observation, requires zero mutations, runs both per-operation and global
backend quiescence checks, and only then clears cleanup obligations. It can
resolve a removal whose reply was lost after dispatch when fresh evidence
subsequently proves absence and process liveness; it never retries the
mutation. Missing identity, live/recreated activity, process reuse/death,
late reply, deadline expiry, or quiescence failure remains sealed as
`TaskQuiescenceUncertain`.

## Concurrency and time bounds

All public entries use a nonblocking mutex and exact owner/entry generation.
Concurrent or recursive entry permanently invalidates the active authority.
Each request uses the smaller of the immutable session deadline and the
plan's bounded operation budget. The retained monotonic clock may not regress;
the request clock must advance without an excessive offset before dispatch; ACK,
dispatch, capture, and completion times must remain ordered and strictly
before the request deadline. Late or retained dispatch callbacks are sealed.

## Synthetic verification

`test_native_page_visual_task_adapter.py` uses only an in-memory clock and a
fixed fake backend. It covers the successful launch/removal/quiescence path,
harness-time display binding, canonical pin stability, strict parser-derived
identity, malformed and ambiguous ActivityManager evidence, process
PID/start/UID/boot/liveness changes, caller scope and command-like URI
mutations, backend policy drift, no/repeated/late witnesses, pre- versus
post-dispatch failures, deadline overruns, reentrancy/concurrency, exact
removal policy mutations, recreated tasks, process death, and operation/global
quiescence failures. It also covers retained-clock construction, substitution,
canonical/domain drift, verification failure, stall and offset cases, proving
that none can reach backend dispatch. Same-binding backend replacement before
verification or during a retained-backend callback is also rejected without
dispatching to either object.

No test contacts a device, opens a network connection, starts a child
process, or invokes a backend outside this synthetic fixed protocol.
