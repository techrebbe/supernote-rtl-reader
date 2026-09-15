# Native page graph snapshot v2 — frozen design before implementation

Status: **design only; hardware admission blocked**.

The v1 flat-role observer passed its closed mocks but does not match the pinned
firmware. This v2 design uses the exact nested graph recorded in
`NATIVE_PAGE_FIRMWARE_FIELD_MAP.md`. It preserves the useful v1 security
properties without silently redefining the v1 wire.

## Bounded question

During the visual-only FULL -> LEFT -> RIGHT -> FULL gate, does one externally
authenticated, resumed stock `DocumentActivity` retain the same native page
graph and raw page geometry while only the diagnostic host's outer surface
rectangle changes?

This snapshot does not establish writable input, annotation coordinates,
matrix semantics, save authority, or two live pages. It invokes no application
method and changes no target state.

## Ownership split

The external coordinator is authoritative for:

- authorized device serial and firmware pins;
- target PID/start-time/package/process, exact APK and native-module files;
- Android task, display, host session, and display generation;
- original PDF, nullable `.mark`, and URI-resolution evidence;
- hard deadline, Frida attach/detach, post-detach target liveness, and complete
  before/after revalidation.

The observer is authoritative only for one stable double-read of the retained
in-process object graph. It echoes external session values as externally bound
facts; it does not claim to have read task ID, display ID, or host generation
from `Activity`.

## Versioned wire

The manifest authority will be
`rtl-reader-native-page-graph-manifest-v2`; the success-record authority will
be `rtl-reader-native-page-graph-snapshot-v2`. The v1 authorities remain
unchanged and rejected by v2.

The manifest remains detached-SHA authenticated canonical UTF-8 JSON with
strict duplicate-key rejection, recursively sorted object keys, exact key/type
allowlists, finite numbers, bounded strings and no insignificant whitespace.
File and URI-resolution authorities retain their reviewed v1 structures. The
coordinator block is versioned for exactly one bounded Java heap walk and one
retained-root double sample.

Class names and field names are constants in the reviewed observer, not
manifest-selected strings. The manifest pins the exact firmware/APK/framework
evidence instead of granting a caller a reflective field-selection language.

## Root selection and graph traversal

The observer performs one `Java.choose` for exactly
`com.supernote.document.document.DocumentActivity`. A candidate is live only
when direct inherited fields say `mResumed=true`, `mFinished=false`, and
`mDestroyed=false`. Zero or more than one live candidate is failure.

It retains that exact root, then traverses only:

```text
DocumentActivity
  +-- documentViewModel
  |     +-- pageInfo
  |           +-- ctm / revertCtm
  |           +-- trimmingRect
  |           +-- originBitmap / displayBitmap / digestBitmap
  +-- handWritePresenter
        +-- bitmap
        +-- superNoteNote
        +-- handWriteClient
```

The concrete runtime class of every non-null reference must equal its pinned
class where the declaration is concrete. URI must be the pinned
`android.net.Uri$StringUri` before direct `uriString` is accepted. Nullable
fields remain nullable only where explicitly specified.

The first sample retains each reference. The second sample rereads every parent
field and uses JNI `IsSameObject` only to prove reference identity. That JNI
primitive does not invoke target Java code and is the sole permitted operation
beyond exact heap enumeration and direct field reads. Raw JNI handles are not
serialized or treated as stable identities. All retained references are
released on every terminal path.

## Raw snapshot fields

The record binds:

- Activity lifecycle booleans and graph-stability result;
- ViewModel URI, raw `currentPage`, `pageCount`, `scaleRect`,
  `portraitScaleRect`, `landscapeScaleRect`, `showRect`, `trimmingRect`,
  `landscapeTrimmingRect`, and raw `PageInfo.page`;
- PageInfo CTM/reverse-CTM, offset, scale, trimming rectangle, and exact
  dimensions of each non-null bitmap;
- presenter URI, raw current page, nullable mark path, raw rotation code,
  presenter bitmap dimensions, note-pointer presence/value, and both Binder
  reference-presence/stability results;
- inherited raw View bounds, scroll offsets, and attach counts for `mImage`,
  `handWriteView`, `digestImage`, `mContentView`, and `documentViewLayout`, with
  exact retained-reference stability for each;
- an explicit unavailable-layer record until committed/background/digest layer
  semantics are independently pinned.

Finite floats use exact binary64 hexadecimal after lossless promotion of the
observed Java float, including signed zero. Affines use `[a,b,c,d,e,f]` and
must be finite, nonsingular, and reasonably conditioned. The calibration
profile records `ctm` and `revertCtm` independently; their names do not prove
that they are mutual inverses or that offsets are already incorporated. Only a
hardware-established visual profile may enforce their measured relationship,
using the reviewed separate linear/translation tolerance policy. Rectangle
ordering, bitmap bounds, page count, and all integer ranges fail closed.

Native pointers may be recorded only as bounded fixed-width hexadecimal values
and only as run-scoped evidence. They are never persistent identity or external
authorization.

Until hardware establishes the index base and matrix meaning, output names use
`rawCurrentPage`, `rawPageInfoPage`, `rawPresenterPage`, and `rawRotationCode`.
The calibration profile requires each value to remain stable across the double
sample but deliberately makes no equality or offset assumption between them.
Two or more externally known source pages must establish each field's index
formula before the visual-gate profile may pin a cross-field relationship. A
later versioned contract may add established semantics; v2 will not silently
rename raw values or turn a calibration observation into index authority.

## Framing and deadline

The runner supplies the canonical absolute monotonic deadline and owns the sole
hard timer.  The observer validates and echoes the deadline wire only as an
externally bound fact; it does not read any clock.  In particular, it must not
use `Date.now`, `performance.now`, `System.nanoTime`, `NativeFunction`, or a
target method.  Requiring an in-process clock would contradict the rule that
the observer performs only one heap enumeration, direct field reads, and JNI
`IsSameObject`.

The runner starts its timer before attach, rejects every callback received at
or after the deadline, and forcibly unloads/detaches through its independently
timed cleanup path.  This external preemption is authoritative even if the
single synchronous heap walk never returns.  Success is exactly one snapshot
record followed by one success terminal. Failure is exactly one bounded
fixed-code error followed by one failure terminal. No partial snapshot is
emitted.

The runner rejects missing, duplicate, out-of-order, late, oversized, nested
unknown, or post-terminal messages. A script success is provisional until the
runner detaches and revalidates target liveness plus every external authority.
No automatic retry is allowed.

## Required deterministic tests

Before device use, closed mocks must cover at least:

- zero/one/multiple live Activities and stale destroyed/finished instances;
- every null, wrong-class, wrapper-shaped, missing, replaced, and mutated graph
  edge in both samples;
- JNI same-object false/error and retained-reference cleanup on every exit;
- URI subtype and URI/PDF authority disagreement;
- raw page mutation between samples, page/count bounds, nullable-mark parity,
  presenter URI disagreement, and visual-profile relationship mismatches only
  after an independently pinned calibration;
- matrix, rectangle, bitmap, pointer, integer and exact-float edge cases;
- canonical manifest mutations, duplicate keys, hostile thrown objects,
  oversized output, external deadline boundaries, late callbacks, terminal
  framing, and static rejection of every in-observer clock source;
- static rejection of hooks, writes, target method calls, target memory APIs,
  extra heap walks, and any manifest-selected field/class names; and
- external runner before/after replacement, PID reuse, task/display drift,
  timeout/detach/liveness, and exact output-schema mutations.

Only a clean subsystem review, one integrated exact-head review, and all host
tests permit a read-only firmware calibration. The physical pen remains blocked
for the later visual gate, and no observer result can authorize writing.
