# InkBridge representation contract

Status: v0.0.24 hardware gate complete; v0.0.25 wire contract frozen.

The exact byte-level mapping and view-identity rules are normative in
[`MAPPING_WIRE_CONTRACT.md`](MAPPING_WIRE_CONTRACT.md). The page-143 fixture
referenced below is checked in at
[`fixtures/page-143-contract-v1.json`](fixtures/page-143-contract-v1.json).

## Ownership boundary

The immutable original PDF and InkBridge annotations in original-page
coordinates are canonical. BOOX continues to use the ordinary editable PDF.
Supernote uses a device-local, versioned Virtual Spread PDF, its authenticated
sidecar, and Supernote's native `.mark` data.

The generated PDF, sidecar, and `.mark` are views of canonical state. They are
never synchronized as annotation authority between unlike devices. RTL Reader
stays limited to generation-time representation rules plus native-reader
verification, RTL navigation, and viewport behavior. It does not import or
export InkBridge annotations and does not intercept native writing tools.

InkBridge owns automatic generation on a trusted host and canonical hydration.
The Nomad owns verification, cache safety, installation, and opening. The final
workflow must not require users to convert individual PDFs manually.

## Canonical identity and coordinates

- Document ID: `inkbridge-doc-v1-<lowercase SHA-256 of original PDF bytes>`.
- Every source, virtual, and manifest page index is zero-based. User-facing page
  numbers may be one-based but are never serialized as mapping indices.
- InkBridge annotations use normalized `[0,1]` coordinates in each original
  page's displayed orientation after effective CropBox and `/Rotate` handling.
  The cross-project golden fixture must pin the coordinate origin and axes.
- Virtual Spread publishes only the authoritative forward affine transform from
  the original source-page coordinate system into the virtual spread. InkBridge
  derives the inverse and rejects a singular or non-round-tripping transform.
- Absolute host paths are diagnostic only and must not participate in identity,
  mapping authority, or cache selection.

If Supernote element `userData` cannot retain an InkBridge source UUID reliably,
InkBridge must use a documented deterministic fallback ID. That decision belongs
to the adapter and must be proven by a device round trip before synchronization
is enabled.

## Authenticated mapping authority

Manifest schema v3 adds one canonical mapping digest covering every
field consumed by InkBridge for every source page:

- source page index and virtual page index;
- side;
- effective source/CropBox geometry and source rotation;
- destination rectangle and uniform scale; and
- the six-number forward affine transform.

Canonicalization uses the frozen field/record order, decimal integer encoding,
and IEEE-754 binary64 bit encoding in `MAPPING_WIRE_CONTRACT.md`. The generator
writes the same digest into the sidecar and the descriptor-verified PDF tail.
The Android runtime accepts mappings only when both values agree with a
recomputed strict sidecar digest.

The global layout digest remains necessary but is not a substitute for mapping
authority. Source SHA-256, source page count, effective CropBox/rotation,
source-to-virtual page/side mapping, and stable generated-output size/hash remain
available to the adapter.

## Deterministic view identity and cache

The versioned view ID will be the SHA-256 of a canonical record containing:

1. a fixed view-identity domain/version;
2. original PDF SHA-256;
3. manifest schema and generator version;
4. direction and cover parity;
5. spread width, height, and gutter; and
6. authenticated mapping digest.

The output basename must be derived only from the document ID and view ID, with
the sidecar named as the exact `<output>.json` sibling. A candidate device cache
is a dot-prefixed directory under shared storage, organized by document and view
ID. It is not approved until a Nomad test proves that Supernote's native reader
can open it directly while its normal library does not list it.

## Regeneration transaction

Regeneration must never overwrite an active view in place or copy an old `.mark`
onto differently generated PDF bytes. The orchestrated transaction is:

1. detect and export dirty native `.mark` state into canonical annotations;
2. generate a new versioned PDF/sidecar path;
3. fully hydrate both represented source pages from one canonical revision;
4. verify PDF, sidecar, mapping authority, and hydrated contents;
5. atomically switch the document-to-view mapping; and
6. retain enough prior-view evidence for rollback.

An export snapshots both source pages represented by a spread under one
Supernote revision. Hashes are dirty/checkpoint signals, not canonical IDs.

## Cross-project fixture and release sequence

A small generated fixture whose logical test case is called `page-143` will pin
source geometry, rotation, virtual page/side, forward transform, normalized
round trips, mapping digest, and view ID for both projects.

Sequence:

1. finish the exact v0.0.24 review and Nomad hardware gate;
2. introduce mapping authority, view identity/naming, the golden fixture, and a
   hardware-proven hidden cache location in a new schema/version;
3. implement and host-test InkBridge's forward/inverse transform adapter;
4. run page-143 ink create, sync, move, erase/tombstone, and idempotent-reimport
   end-to-end tests;
5. validate dirty export, full hydration, versioned regeneration, atomic switch,
   and rollback; and
6. expand beyond ink.

Native text-highlight enumeration/export and existing non-link source-PDF
annotations remain separate blockers. The earlier v0.0.18 preview and v0.0.23
planning baseline are superseded by the schema-v2 v0.0.24 release candidate.
