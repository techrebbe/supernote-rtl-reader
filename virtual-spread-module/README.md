# Supernote Virtual Spread Navigation

This is an isolated LSPosed companion for PDFs produced by the virtual-spread
generator. It deliberately leaves Supernote's renderer, handwriting, eraser,
lasso, text selection, highlighting, links, undo/redo, and `.mark` persistence
untouched.

It activates only when all of these are true:

- the open file has a sibling `<pdf>.json` manifest;
- the manifest schema is `techrebbe.supernote.virtual-spread/v1`;
- the manifest direction is `rtl`;
- the PDF byte length, page count, and full SHA-256 match the manifest;
- the persisted `coverSeparate`, spread occupancy, and source-page mappings
  describe the same complete RTL layout;
- the canonical direction, cover parity, page counts, spread geometry, and
  gutter digest matches the authority marker embedded in the hashed PDF; and
- the known Supernote document firmware fingerprint and APK size match.

Manifests generated before v0.0.15 lack that layout authority and fail closed.
Regenerate the PDF/sidecar pair before using it with this module.

The manifest cache is content-authoritative: the small sidecar is hashed on
every lookup, and the PDF cache identity includes its device, inode, size,
modification time, and change time. Generator and runtime share an 8 MiB
sidecar ceiling; the generator rejects an oversized manifest before publishing
it, while the runtime independently fails closed if that invariant is violated.
On a cache miss, the module fails closed while a single background worker
performs the full PDF SHA-256 check. It
publishes the result only if both the PDF identity and sidecar digest are still
unchanged, then refreshes the still-open native reader from its main thread.
Page-bar and page-turn callbacks never perform the full-file hash.

The `links` collection is required. Every entry must be a complete internal or
URI record whose source page, virtual page, and side agree with the
authoritative `sourcePages` mapping; internal targets must agree as well. Link
rectangles must use finite, canonical left/bottom/right/top ordering. Missing
collections, unknown record kinds, malformed URI records, reversed rectangles,
and contradictory mappings reject the whole manifest rather than losing half
focus. The generator hashes a canonical form of the complete ordered link
collection and embeds that authority digest immediately before the PDF's final
`startxref`. The runtime recomputes the digest from the sidecar and requires it
to match both the sidecar identity and the marker inside the already-verified
PDF, so omitted, reordered, or retargeted records fail closed.

Immediately before the link marker, the generator embeds a separate layout
authority. The runtime recomputes it from the validated sidecar and requires an
exact match. This prevents a stale or substituted sidecar from changing cover
parity or spread geometry even when the source and output page counts happen to
remain the same.

For a matching document it:

- reverses native page turns in landscape;
- reads the manifest's real left/right occupancy;
- orders portrait halves as right then left;
- skips the virtual blank beside a separate cover;
- uses Supernote's existing `showRect`/`offsetShowRect` split viewport;
- keeps the native previous/next controls synchronized with the virtual RTL
  reading order;
- preserves an internal link's intended left or right destination half when
  the linked spread opens in portrait;
- restores the correct source half for native Back and Original Back, while
  leaving Supernote's own link-history stack authoritative; and
- reruns Supernote's own orientation refresh after a configuration transition,
  so its native split mode, toolbar, handwriting state, and bitmap all move to
  the new orientation together.

It does not compose bitmaps, remap pen coordinates, modify annotation files,
or hook any annotation subsystem.

GitHub CI runs this module's complete host-side suite and then invokes the same
cross-platform build used locally, compiling the Android hook and producing,
signing, and verifying the companion APK.

## Build and test

```powershell
.\test.ps1
.\build.ps1
```

The signed APK is written to `build\artifact`.

Only `com.supernote.document` should be selected in LSPosed. Do not enable the
legacy Native Spread Probe at the same time.
