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
  gutter digest match the authority markers embedded in the hashed PDF;
- the source, layout, and link authorities read from Supernote's actually open
  native MuPDF `Document` match the authenticated manifest; and
- the known Supernote document firmware fingerprint and APK size match.

v0.0.18 retains link-authority v2 and the v0.0.17 native-open snapshot
binding. It additionally requires exact JSON integer tokens for every consumed
page count and page index; numeric strings and fractional values fail closed.
The generator rejects transformed URI `/IsMap true` actions and any link
rectangle or quadrilateral outside the source page's effective CropBox, and it
materializes the PDF default link border at the transformed width. Replacing a
PDF and sidecar at their existing paths can never apply replacement mappings to
an older native document that remains open in memory. Older generated pairs
fail closed; regenerate the PDF/sidecar pair before using it with this module.
If multiple tolerance-equivalent runtime link matches disagree on source half,
target half, or authenticated target-view policy, the match also fails closed
rather than selecting an order-dependent record.

The manifest cache is content-authoritative but uses an identity-based fast
path: every lookup captures both PDF and sidecar device, inode, size,
modification time, and change time, and reuses only a snapshot previously
verified with those exact identities. Generator and runtime share an 8 MiB
sidecar ceiling; the generator rejects an oversized manifest before publishing
it, while the runtime independently fails closed if that invariant is violated.
On a cache miss or identity change, the module fails closed while a single
background worker opens the PDF and sidecar, hashes the sidecar bytes, parses
them, and performs the full PDF SHA-256 check. It
publishes the result only if both the PDF identity and sidecar digest are still
unchanged. Before any navigation behavior activates, the main-thread callback
also compares the authenticated authorities with metadata read from the exact
native MuPDF `Document` instance. A mismatch fails closed until Supernote
reopens the replacement document. Page-bar and page-turn callbacks never
perform the full-file hash.

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
- restores the complete landscape spread after a source-page `/Fit` link, while
  leaving explicit `/XYZ` and `/FitR` destination views untouched;
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
