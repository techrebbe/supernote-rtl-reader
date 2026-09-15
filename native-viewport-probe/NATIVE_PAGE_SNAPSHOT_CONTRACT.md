# One-native-page read-only snapshot contract

Status: **superseded host-only v1 schema; closed-mock evidence only and no
hardware claim**.

Read-only static inspection of the pinned firmware has now established that the
real page state is a nested direct-reference graph rooted at
`DocumentActivity`, while task/display/session identity has no direct Activity
field. See `NATIVE_PAGE_FIRMWARE_FIELD_MAP.md`. Consequently this v1 flat-role
observer must not be given a fabricated runtime manifest or injected into the
device. A separately versioned graph observer and its matching runner schema
must replace it before hardware admission. The 77 closed-mock cases below
remain useful regression evidence for canonicalization, numeric validation,
bounded errors, and fail-closed framing; they are not evidence that the v1
field model matches Supernote.

`native_page_snapshot.js` is a bounded observation candidate for the first
one-genuine-native-page viewport gate. It does not create a viewport, change
page state, intercept input, call target methods, read pixels, or write target
memory. It enumerates exact Java classes and reads explicitly named fields from
an externally authenticated canonical UTF-8 manifest wire. The script
intentionally has no default manifest: an absent, incomplete, ambiguous, or
unsupported mapping fails.

The observer runs twice and emits a snapshot only if the complete encoded result
is identical. This detects ordinary lifecycle/page/identity mutation during the
observation, but the result remains `atomic:false`; it is not a transaction or
a save witness.

## Attachment authority

Before injection, the runner must independently authenticate all of the
following and retain the same evidence after the observer terminates:

- attached PID and `/proc/<pid>/stat` start-time ticks;
- exact process command/name `Document` and package
  `com.supernote.document`;
- owning APK path, byte length, and SHA-256;
- one exact mapped native module name/path/byte length/SHA-256;
- script bytes and canonical manifest bytes/SHA-256;
- one foreground Document Activity, Android task, and display.
- the original PDF path/size/hash/stat identity and either the same complete
  descriptor for its `.mark` or an explicit absent-mark descriptor.

The script directly checks arm64/8-byte pointers, PID, mapped module name/path/
size, exact Java classes, exact selected identities, and the expected task,
display, session generation, URI, zero-based current page, and page count. APK,
module-file, start-time, process-name, package-manager, script, and manifest
hashes and the two file descriptors are external before/after authorities
because the observer neither opens files nor reads module bytes. The
`externallyVerifiedSha256` names in its output must not be interpreted as hashes
calculated from target files by the script.

The manifest authority string is
`rtl-reader-native-page-snapshot-manifest-v1`. The manifest contains no digest
of itself. Instead the runner supplies its exact canonical UTF-8 bytes and a
detached lowercase SHA-256. The observer hashes those bytes in pure JavaScript,
strictly decodes UTF-8, parses JSON, reserializes it with recursively sorted
object keys and no insignificant whitespace, and requires byte-for-byte
equality. Duplicate keys, alternate ordering, whitespace, noncanonical numbers,
invalid UTF-8, and any byte mutation therefore fail. Unknown keys fail. Lowercase
64-hex SHA-256 values, positive bounded byte sizes, a positive decimal process
start time, nonempty bounded strings, and exact package/process names are
required.

File authority is `rtl-reader-native-page-file-authority-v1`. A present file
binds path, positive decimal size, SHA-256, device/inode/mode, uid/gid, and
nanosecond mtime/ctime. The original-PDF descriptor additionally binds the exact
`documentUri`, which must equal both `expected.uri` and the observed ViewModel
URI, plus an explicit authenticated URI-resolution record. No URI or canonical
path is inferred from the other. An absent mark binds
`present:false` and explicit nulls for every other member. The presenter mark
path must equal the present mark descriptor or be null when the descriptor says
absent. The external runner must re-hash and re-stat both descriptors after
detach and require exact equality; same-path replacement is a failure.

A `file://` document URI requires a manifest-authenticated record under
authority `rtl-reader-file-uri-resolution-v1`, binding the exact URI, externally
resolved canonical path, and resolution-evidence SHA-256. A `content://` URI
requires a separately reviewed record under authority
`rtl-reader-content-uri-resolution-v1`, additionally binding provider package
and APK SHA-256. In both cases the resolved canonical path must exactly equal the
PDF descriptor path. The observer deliberately implements no Android URI
decoder: percent escapes, Unicode, spaces, aliases, and provider semantics belong
to the external resolver evidence. Other schemes, missing resolution evidence,
or URI/path disagreement fail.

## Fixed record and bindings

The success record authority is `rtl-reader-native-page-snapshot-v1`. It binds
one stable double-sample of:

- Activity identity, task ID, display ID, and session generation;
- ViewModel identity, URI, zero-based current-page index, and page count;
- PageInfo identity/page index, page size, CropBox-like rectangle, forward CTM,
  inverse CTM, offset, and committed bitmap dimensions;
- presenter identity/current page/nullable mark path/raw rotation code, note
  identity, client identity, and Binder identity;
- layer-container identity plus background, committed-handwriting, and digest
  layer identities, **only if those readable fields have been established**.

Every bound role selects exactly one of at most 32 live instances. Its selector
must include an explicit stable identity field. Each configured field is one
direct Java field read; nested paths and getters are unsupported. A configured
field that is absent, wrapper-shaped rather than the declared primitive/string,
ambiguous, oversized, nonfinite, or changed between samples fails the entire
snapshot.

If layer identities have not been established, the manifest must say
`status: "unavailable"` with a bounded reason code and evidence ID. That explicit
state is included in the result. Silently omitting some layer fields or treating
an empty value as an identity is not allowed.

The observer treats a null presenter mark path as meaningful: a fresh PDF may
legitimately have no `.mark`. The field itself must still exist and be configured
as `nullableString`.

Page indices are zero-based. Integer fields reject negative zero. Finite
geometry is serialized as exact binary64 hexadecimal, including signed zero.
Both affine matrices use `[a,b,c,d,e,f]`, mapping
`(x,y)` to `(a*x+c*y+e,b*x+d*y+f)`. The supplied inverse must match the
analytically derived inverse within the observer's fixed numerical policy;
singular, nonfinite, or
excessively conditioned pairs fail. The observer derives the inverse directly.
It validates the four linear coefficients using only the linear condition and
validates translation separately against the derived translation. Large offsets
cannot inflate acceptance of a wrong linear or translation coefficient. This is
a consistency check, not permission to infer what an undocumented CTM means.

## Deadline and liveness coordinator

The manifest must bind authority
`rtl-reader-native-page-snapshot-coordinator-v1`, a session ID, a 250–10,000 ms
hard deadline, an exact ten-walk maximum, and mandatory detach-on-deadline,
abort-on-error, and post-detach target-liveness checks. The observer checks its
local deadline before and after each heap walk and rejects more than ten walks.
A bound-layer double sample uses ten; an explicitly unavailable layer uses
eight.

Java heap enumeration itself cannot be safely interrupted from inside a blocked
Frida callback. Therefore a separate host runner must own the hard timer, unload
or detach the observer on expiry, and then verify the same target PID/start time
is alive and the authenticated file/module identities are unchanged. **Hardware
admission is blocked until that runner and its timeout/detach/liveness tests
exist.** An observer success terminal alone is not the external liveness
postcondition.

Success framing is exactly:

1. one `native_page_snapshot` record;
2. one `native_page_snapshot_complete` record with `success:true`.

Failure framing is exactly one bounded `native_page_snapshot_error` with fixed
code `SNAPSHOT_REJECTED`, followed by one terminal record with `success:false`.
Only a primitive thrown string may become its bounded message. Objects are never
coerced or inspected; foreign or hostile errors produce the fixed message
`non-primitive observation failure`. No partial snapshot is emitted.

## Firmware observations required before enablement

No class or field offsets/names are invented in this preparatory change. A
read-only pinned-firmware pass must establish and review all of these before a
real manifest is created:

1. Exact concrete class and direct-field names/types for the foreground
   Document Activity, its page ViewModel, the current PageInfo, and the one
   presenter that owns the same note/page.
2. A stable direct identity field for each object and evidence that each
   selector is unique while one document is loaded. Raw Java-wrapper addresses
   are not accepted as stable session identities.
3. Direct-field provenance for task ID, display ID, and session generation.
   Calling `Activity.getTaskId()`, `View.getDisplay()`, or another getter is out
   of scope.
4. Direct-field provenance and index base for URI/current page/page count, plus
   PageInfo size, crop, CTM/inverse, offset, and committed bitmap dimensions.
   Rotation representation must remain a raw code until its enum meaning is
   independently established.
5. Direct-field provenance for presenter current page, nullable mark path, note,
   client, and Binder identities, with evidence that they refer to the same
   page/session as the ViewModel.
6. Direct readable identities for background, committed-handwriting, and digest
   layers. Until all are known, use the explicit unavailable binding.
7. Evidence that Frida exposes each approved String field as a primitive string
   through field access alone. If conversion would invoke target `toString()` or
   another method, that field is unsupported by this observer.
8. An exact mapped-module identity suitable for runtime replacement detection,
   plus before/after file hashing by the external runner.
9. A descriptor collector that obtains the PDF/nullable-mark stat and digest
   authorities before attachment, revalidates them after detach, and rejects
   inode, metadata, size, or content replacement at the same path.
   It must also capture the exact ViewModel document URI. Both `file://` and
   `content://` require reviewed resolution evidence; `content://` additionally
   binds provider identity. Neither may be reconstructed from the descriptor
   path by this observer.
10. A coordinator that enforces the authenticated hard deadline outside the
    script, detaches on expiry/error, and proves target PID/start-time liveness
    afterward.

The global DrawPath PID/start time and scalar screen/document-image geometry are
a separately authenticated prerequisite. This Document-process observer does
not attach to DrawPath or infer its fields. The terminal record lists the six
required scalar names under authority `rtl-reader-drawpath-scalar-snapshot-v1`;
their exact acquisition and firmware pins must be established independently.

Only after the manifest field map, external runner, and combined evidence have
their own adversarial tests and independent review may this observer be tried on
the disposable native-page fixture. That attempt remains observation-only and
cannot establish viewport, pen-engine, annotation, or persistence correctness.

## Closed-mock coverage

Run:

```text
node test_native_page_snapshot.js
```

The test executes the actual script with only class enumeration, field values,
runtime identity, and message output available. It rejects wrong task/display/
page/session, missing or ambiguous instances/fields, candidate overflow,
process/module replacement, nonfinite/singular/inconsistent matrices, invalid
crop/bitmap geometry, identity/data mutation between samples, unsafe/extra
manifest fields, mutated/noncanonical/duplicate-key manifest bytes, malformed
file descriptors, descriptor/observed-URI disagreement, same-URI/different-file
mutation, missing or mismatched `file://`/`content://` resolution authority,
percent-encoded Hebrew/space resolution, coordinator weakening/deadline overrun, tiny-scale/far-offset
inverse errors, hostile error coercion, unbounded strings/errors, and malformed
terminal behavior.
Static capability checks reject hook, target-call, target-memory, and write
interfaces. Passing these mocks is not a hardware claim.
