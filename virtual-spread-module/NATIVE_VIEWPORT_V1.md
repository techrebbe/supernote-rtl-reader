# Native viewport authority v1

Virtual Spread v0.0.26 exposes the live native page transform needed to map
Virtual Spread PDF coordinates into Supernote's persistent document-ink
canvas. This is runtime authority, not another inferred manifest field.

## Ownership

The LSPosed hook runs inside `com.supernote.document`, after the exact
schema-v3 PDF/sidecar pair and the already-open MuPDF `Document` have been
verified. For the current zero-based virtual page it reads the live
`PageInfo` render matrix, render offsets, and origin-bitmap dimensions. It
composes the PDF bottom-left to native top-left transform and publishes it to
the companion APK's memory-only provider.

The provider is intentionally not backed by shared storage. Its single record
is bound to a Binder owned by the document process and disappears when that
process dies. The hook also clears it when the activity closes or verified
manifest authority is invalidated. A stale page, document, representation,
filesystem generation, or canvas-size request returns `unavailable`.

Every native page activation begins a new monotonic, document-session-bound
load generation before Supernote exposes the replacement page. Beginning the
generation synchronously invalidates the prior record. Publication is accepted
only for that exact generation, so a late callback from the previous load
cannot restore stale CTM or inset authority. This fence applies even when the
same zero-based virtual page is reloaded with unchanged files and dimensions.
The completion must also carry the exact load identity: document view-model
identity, native MuPDF instance identity, zero-based page, and a monotonically
increasing per-page request serial captured by the initiating synchronous load
or the exact firmware's asynchronous page worker. The worker's resulting live
`PageInfo` object is bound to that identity before `onPageLoaded`. A delayed,
replaced, older same-page, or otherwise unbound completion is allowed to finish
Supernote's normal reader work but cannot publish viewport authority.

## Descriptor wire

`descriptorJson` is UTF-8 JSON with exactly these fields in this order:

```json
{
  "schemaVersion": 1,
  "authority": "rtl-reader-native-viewport-v1",
  "documentId": "inkbridge-doc-v1-<64 lowercase hex>",
  "viewId": "inkbridge-view-v1-<64 lowercase hex>",
  "virtualPageIndex": 1,
  "nativePageSize": [1872, 1404],
  "spreadToNative": [1.0, 0.0, 0.0, -1.0, 0.0, 1403.0]
}
```

Indices are zero-based. All six affine coefficients are finite binary64
values serialized with Java `Double.toString`; negative zero is normalized to
positive zero. The affine convention is:

```text
nativeX = a * spreadX + c * spreadY + e
nativeY = b * spreadX + d * spreadY + f
```

Virtual Spread input coordinates use the generated PDF's bottom-left
coordinate system. Native output coordinates use Supernote's top-left
persistent page canvas and pixel-center extent `[0,width-1] × [0,height-1]`.
The descriptor contains no inverse. Consumers derive and numerically validate
the inverse locally.

The normative page-143 golden descriptor is
[`../virtual_spread/fixtures/page-143-v1/page-143-native-viewport-v1.json`](../virtual_spread/fixtures/page-143-v1/page-143-native-viewport-v1.json).
The provider's canonical `descriptorJson` UTF-8 bytes (with no trailing line
feed) have SHA-256:

```text
a590afc7a95e92fbf7b9ac03fd949bcd6b474bcba70e06e4ec63936de937d033
```

The tracked fixture file appends one LF for repository portability and has
SHA-256:

```text
27145685a793ce2716a5da6c26db4a1fa64bac0e1ad6bc1329e0c502326a48e4
```

That fixture is expected evidence for cross-language tests, not a substitute
for the fresh provider record used in production.

## Provider API

Provider URI:

```text
content://com.techrebbe.supernote.virtualspread.viewport/v1/current
```

Read method:

```text
get_v1
```

Only `com.ratta.supernote.pluginhost` running as Android system UID 1000 may
read. Before treating a response as authority, InkBridge must also verify that
the provider resolves to package `com.techrebbe.supernote.virtualspread` with
the expected release signing certificate. The current protected release
certificate SHA-256 is:

```text
a5a8551131de84d41660a3cf22d224f320f7a2f05a380282f76f6fe731807c67
```

The request Bundle must contain all of the following expected values:

```text
documentId             String
viewId                 String
virtualPageIndex       int
nativeWidth            int
nativeHeight           int
documentPath           String
generatedPdfSha256     String (64 lowercase hex)
sidecarSha256          String (64 lowercase hex)
mappingAuthoritySha256 String (64 lowercase hex)
```

`nativeWidth` and `nativeHeight` are the exact values returned by
`PluginFileAPI.getPageSize` for the same active page. The other evidence comes
from InkBridge's independently verified schema-v3 manifest and current file.
Any omission or mismatch returns:

```text
protocolVersion = 1
status = unavailable
```

Reads also require the published record to remain current under the provider's
internal page-load generation fence. The generation is intentionally not a
consumer-supplied authority: InkBridge cannot revive an old record by guessing
or replaying it.

An accepted response contains:

```text
protocolVersion
status = ok
descriptorJson
descriptorSha256
documentPath
sidecarPath
generatedPdfSha256
sidecarSha256
mappingAuthoritySha256
snapshotId
pdfIdentity
sidecarIdentity
verificationGeneration
pageLoadGeneration
publishedAtElapsedRealtime
```

`descriptorSha256` is SHA-256 over the exact UTF-8 `descriptorJson` bytes.
The remaining fields are activation evidence, not fields in the descriptor
wire. Consumers must strictly parse `descriptorJson`, reject duplicate or
unknown fields, validate all identities and hashes against their expected
values, require the page size to equal `PluginFileAPI.getPageSize`, validate a
stable nonsingular affine, and prove all four Virtual Spread page corners stay
inside the native pixel-center canvas.

## Native derivation

The hook uses the same live `PageInfo.ctm`, `offsetX`, `offsetY`, and
`originBitmap` that Supernote uses to render the active PDF page and position
native annotations. It composes:

```text
Virtual Spread PDF bottom-left coordinates
  -> MuPDF page top-left coordinates
  -> live PageInfo CTM
  -> PageInfo render offsets
  -> native page pixel-center canvas
```

This carries native fitting, translation, insets, and any linear rotation or
skew. It does not infer presentation from aspect ratio and does not use the
portrait `showRect`, which is a screen crop rather than the persistent `.mark`
canvas.

## Failure behavior

Publication fails closed for missing or stale `PageInfo`, page mismatch,
non-finite coefficients, singular/unstable transforms, render bounds outside
the native canvas, a mismatched authenticated snapshot, or provider failure.
No descriptor is persisted or reconstructed after a restart. InkBridge's
Virtual Spread actions must remain unavailable until a fresh matching record
is published; ordinary PDFs remain unaffected.
