# Virtual Spread mapping wire contract v1

Status: frozen for the v0.0.25 implementation. Any byte-level change requires
a new domain/version and new cross-project golden vectors.

## Scope and authority

The immutable original PDF is the document authority. A Virtual Spread PDF,
its sidecar, and Supernote's native `.mark` are device-local views. The mapping
authority described here is the only transform authority exported by RTL
Reader. InkBridge derives the inverse and rejects a singular transform or any
golden-vector/round-trip mismatch.

All serialized source, virtual, and manifest page indices are zero-based.
Human-facing page numbers are never mapping authority. Absolute paths are
diagnostic only and never participate in a digest, document ID, view ID, or
cache name.

## Primitive encodings

- Text is strict UTF-8. The canonical records below are restricted to ASCII.
- A digest is 64 lowercase hexadecimal SHA-256 characters.
- An integer is a base-10 ASCII integer with no sign, leading zeroes, decimal
  point, exponent, or surrounding whitespace. The only encoding of zero is
  `0`. JSON Booleans and floating-point values are not integers.
- A Boolean is `0` or `1` in canonical records and a JSON Boolean in the
  sidecar.
- A side is exactly `left` or `right` in lowercase ASCII.
- A rotation is one of the integer values `0`, `90`, `180`, or `270`.
- A finite number is encoded as the 16 lowercase hexadecimal digits of its
  IEEE-754 binary64 bit pattern in network (big-endian) byte order. NaN and
  infinities are rejected. Signed zero is retained; producers must not
  normalize its bit pattern after parsing.
- Every canonical line ends in one LF byte (`0a`), including the final line.
  CRLF is never canonical.

## Mapping authority

Domain:

```text
techrebbe.supernote.virtual-spread-mapping/v1
```

The digest input starts with the domain and LF. It is followed by exactly one
record per source page, ordered by `sourcePageIndex`, with no omitted or
duplicate index. The first index is zero and each following index increments by
one.

Each record has this exact positional form:

```text
page|
sourcePageIndex|
virtualPageIndex|
side|
sourceRotation|
sourceBox[0..3]|
normalizedSourceBox[0..3]|
slot[0..3]|
destination[0..3]|
scale|
transform[0..5]\n
```

The displayed form above is wrapped only for readability. The wire record is
one ASCII line whose fields are separated by one `|` byte.

`sourceBox` is the effective source CropBox in the original PDF coordinate
system. `sourceRotation` is the effective source `/Rotate`. The
`normalizedSourceBox` is that CropBox after rotation has been transferred to
content. `slot` is the complete target half. `destination` is the fitted source
page rectangle within that half. `scale` is the validated uniform scale. The
six `transform` values are the sole authoritative affine transform from
original PDF coordinates to virtual-spread coordinates, using:

```text
X = a*x + c*y + e
Y = b*x + d*y + f
```

The mapping authority is `SHA-256(canonical mapping bytes)`. The same lowercase
digest is required in the sidecar and in the descriptor-verified PDF authority
tail. The runtime recomputes it from strict sidecar values and accepts the
mapping only when all three values agree.

The sidecar mapping object may retain one-based display numbers, but they are
redundant and not consumed by InkBridge. The authoritative fields above are all
required, have exact JSON types and lengths, and must match the spread records.
Additional mapping fields require a new mapping domain if a consumer depends on
them.

## Deterministic document and view identity

The canonical document ID is:

```text
inkbridge-doc-v1-<lowercase SHA-256 of original PDF bytes>
```

View identity domain:

```text
techrebbe.supernote.virtual-spread-view/v1
```

The canonical view input is the following exact LF-terminated record sequence:

```text
techrebbe.supernote.virtual-spread-view/v1
source|<original PDF SHA-256>
schema|techrebbe.supernote.virtual-spread/v3
generator|techrebbe.supernote.virtual-spread-generator/v1
direction|rtl
cover|<0-or-1>
spread|<width-bits>|<height-bits>|<gutter-bits>
mapping|<mapping-authority-SHA-256>
```

The view ID is:

```text
inkbridge-view-v1-<SHA-256 of canonical view bytes>
```

The generator-format version changes only when generated representation
semantics change. It is deliberately distinct from the APK/plugin release
number so a runtime-only bug fix does not invalidate an otherwise identical
view.

## Deterministic output and cache naming

The versioned PDF basename is:

```text
<document-id>.<view-id>.virtual-spread.pdf
```

The sidecar is the exact `<PDF basename>.json` sibling. An existing file at a
different name is not the same cache view even if its bytes happen to match.
The generator CLI may materialize a pair under a caller-selected host staging
path, but that path is not cache authority. Before activation on Supernote, the
verified bytes and sidecar must be published under the exact basename above.
The Android runtime rejects an otherwise valid pair opened under any other
basename.

The initial Nomad cache candidate is:

```text
/storage/emulated/0/.inkbridge/virtual-spread/v1/
  <document-id>/<view-id>/<PDF basename>
```

This location is provisional until hardware proves that the native reader can
open it directly while the normal document library does not enumerate it.

## Canonical InkBridge coordinates

InkBridge points are normalized in the source page's displayed CropBox after
rotation. `(0,0)` is the displayed top-left; x increases rightward and y
increases downward. Both axes are bounded to `[0,1]`.

The adapter derives normalized-to-original-PDF coordinates from `sourceBox` and
`sourceRotation`, then applies the authoritative forward transform. It derives
the affine inverse for export. The inverse is never serialized as authority.
The adapter rejects a singular matrix, an out-of-bounds canonical point, a
non-finite result, or a forward/inverse round trip outside the contract's test
tolerance.

## Failure behavior

The generator and runtime fail closed for:

- malformed UTF-8, duplicate JSON keys, missing/additional authoritative
  mapping fields, wrong JSON types, non-finite numbers, or invalid arrays;
- unordered, missing, duplicate, negative, or non-integral page indices;
- a side/virtual-page relationship that disagrees with spread records;
- a singular/non-uniform transform or inconsistent source/destination geometry;
- a mapping digest mismatch between recomputed sidecar, declared sidecar, and
  embedded PDF authority;
- a view ID mismatch or an identity input that disagrees with authenticated
  manifest state; and
- stale asynchronous verification, pathname/descriptor replacement, or any
  publication state that cannot identify one stable PDF/sidecar pair.

The fixture at `fixtures/page-143-contract-v1.json` is normative. Python,
Android, and InkBridge must reproduce its canonical bytes, mapping digest, view
ID, and point/stroke round trips before integration is enabled.
