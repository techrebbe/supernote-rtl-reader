# Supernote Virtual Spread Navigation

This is an isolated LSPosed companion for PDFs produced by the virtual-spread
generator. It deliberately leaves Supernote's renderer, handwriting, eraser,
lasso, text selection, highlighting, links, undo/redo, and `.mark` persistence
untouched.

It activates only when all of these are true:

- the open file has a sibling `<pdf>.json` manifest;
- the manifest schema is `techrebbe.supernote.virtual-spread/v2`;
- the manifest direction is `rtl`;
- the PDF byte length, page count, and full SHA-256 match the manifest;
- the persisted `coverSeparate`, spread occupancy, and source-page mappings
  describe the same complete RTL layout;
- the canonical direction, cover parity, page counts, spread geometry, and
  gutter digest match the authority markers embedded in the hashed PDF;
- the source, layout, and link authorities read from Supernote's actually open
  native MuPDF `Document` match the authenticated manifest; and
- the known Supernote document firmware fingerprint and APK size match.

The activity, view-model, page-bar, link-target, and link-history hooks form one
required capability set. The module keeps virtual-spread behavior disabled
until every hook installs successfully; if any required hook is unavailable,
already installed callbacks remain native pass-through for that process rather
than leaving a partially active navigation layer.

v0.0.24 retains link-authority v2 and the v0.0.17 native-open snapshot
binding. Manifest schema v2 is intentionally incompatible with older companions:
it prevents a pre-snapshot-binding runtime from accepting a newly generated pair.
Regenerate existing v1 PDF/sidecar pairs before opening them with this build.
It first decodes the raw sidecar bytes with replacement disabled, so
malformed UTF-8 fails closed even inside an otherwise ignored field. It requires
exact JSON integer tokens for every consumed page count,
page index, and the persisted nonnegative output byte size. Every spread
dimension, gutter, and link rectangle coordinate must also be a raw finite JSON
number; numeric strings, fractional integer fields, and non-finite values fail
closed. Spread dimensions must also remain within PDF's 3-to-14,400-unit page
bounds. Spread coordinates may be scaled, but their width and height must retain
the Nomad's 4:3 landscape aspect; the generator and runtime independently reject
other ratios. Link `/QuadPoints` must form four distinct vertices in one strict
convex Z-order quadrilateral; duplicate, concave, and bow-tie regions fail
closed. Before Android's permissive `JSONObject` parser runs, a strict bounded
scanner rejects malformed JSON and duplicate object names at every nesting level,
including names that become equal after JSON escape decoding.
Canonical link-authority encoding also rejects unpaired UTF-16 surrogates in URI
or record strings before converting them to UTF-8, so Android cannot silently
hash Unicode replacement characters that the generator never authorized.
If a generated PDF is present but its required sidecar is missing or cannot be
inspected, navigation fails closed based on the authority embedded in the native
open document. A PDF whose native metadata explicitly contains no virtual-spread
authority remains an ordinary native document.
The generator rejects transformed URI `/IsMap true` actions, a source CropBox
that extends beyond its MediaBox, and any link rectangle or quadrilateral outside
the source page's effective CropBox. It materializes the PDF default link border
at the transformed width. Replacing a PDF and sidecar at their existing paths can
never apply replacement mappings to an older native document that remains open
in memory. Older generated pairs fail closed; regenerate the PDF/sidecar pair
before using it with this module.
If multiple tolerance-equivalent runtime link matches disagree on source half,
target half, or authenticated target-view policy, the match also fails closed
rather than selecting an order-dependent record.

The process-wide manifest cache is a synchronized four-entry access-order LRU,
so opening many distinct documents cannot retain every parsed manifest for the
lifetime of the document process. In portrait, authenticated explicit `/XYZ`
and `/FitR` internal-link destinations keep Supernote's native viewport rather
than being shifted to a page edge. That authenticated preservation state remains
attached to the current page across native reload and orientation callbacks until
real navigation supersedes it. Native screen changes and delayed portrait-focus
retries recheck that preservation state, so neither can overwrite a newer native
link destination. A cached manifest rejection remains fail-closed when the open
MuPDF document carries any virtual-spread authority marker (or its metadata is
not yet available); an ordinary PDF with no such marker remains fully native.
Activation also waits for a positive native page count that exactly matches the
authenticated output.
The generator accepts an explicit `/FitR` viewport only when its complete,
positive rectangle remains inside the target source page's effective CropBox
and its aspect-fitted portrait viewport remains inside the target half; an
out-of-page or neighboring-half viewport fails closed before publication. Explicit `/XYZ` left
and top coordinates obey the same CropBox boundary. An explicit `/XYZ` view is
accepted only when its horizontal anchor and positive zoom prove that the
complete portrait viewport stays inside the target half; retained/zero zoom,
an unknown anchor, or a neighboring-half spill fails closed. An underlined
`/BS /U` link also fails closed when page rotation would move its underline to
a different edge after composition.

The manifest cache is content-authoritative but uses an identity-based fast
path: every lookup captures both PDF and sidecar device, inode, size,
modification time, and change time, and reuses only a snapshot previously
verified with those exact identities. Generator and runtime share an 8 MiB
sidecar ceiling; the generator rejects an oversized manifest before publishing
it, while the runtime independently fails closed if that invariant is violated.
On a cache miss or identity change, the module fails closed while a single
background worker opens the PDF and sidecar, hashes the sidecar bytes, parses
them, and performs the full PDF SHA-256 check. Its queue retains only the latest
pending document; opening another document invalidates older work, and an
in-progress full-file hash checks for supersession between chunks. Observation
precedes cache and sidecar-existence fast paths, so an already cached spread or
an ordinary sidecar-free PDF also cancels stale work; delayed callbacks carrying
an older native view model fail closed. Native page turns are consumed while a
matching snapshot is pending, so the reader cannot leak one unverified native
LTR turn before RTL activation. Turns also remain blocked when a verified
replacement pair does not match Supernote's still-open native document; reopening
the document is required before the new authority can activate. A native link
tapped during verification is also consumed and queued once. After successful
activation, the module replays it only if the same document, exact PDF/sidecar
filesystem snapshot, unique verifier generation, native MuPDF document object,
embedded source/layout/link authorities, source page, and external/internal
routing classification are still current and the request is fresh; same-path
replacement, document/page changes, a newer manual turn, routing changes, and
failed or rejected verification discard it. External replay immediately
initializes the verified current spread,
while an internal replay waits for its native page-load callback. Reusing one
native view model for another document clears all page, half, link-history,
viewport, queued-link, and native-snapshot state. Delayed callback generations
remain monotonic across document and manifest changes, preventing an older task
from matching a newly reset counter. The verifier publishes the result only if both the PDF identity and
sidecar digest are still unchanged. Before any
navigation behavior activates, the main-thread callback
also compares the authenticated authorities with metadata read from the exact
native MuPDF `Document` instance. A mismatch fails closed until Supernote
reopens the replacement document. Page-bar and page-turn callbacks never
perform the full-file hash.

Supernote shares `showLinkJumpView` between link activation and native
annotation/digest menus. A callback without a `SuperNoteLink` therefore bypasses
the companion completely. Authenticated external URI links likewise remain in
Supernote's native handler. Only internal page links require the companion to
capture and restore an authenticated destination half; missing, malformed,
unmatched, or ambiguous internal targets are consumed.

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

The generator writes and fsyncs its recovery marker under a private staged name
before atomically exposing the marker on every supported platform. POSIX
recovery also recognizes the exact link-before-unlink crash state produced by
an older interrupted no-replace backup move, but only when the canonical and
backup names are the same inode and match the authenticated old digest. Current
guarded and unguarded POSIX no-replace publication uses
`renameat2(RENAME_NOREPLACE)`, so no incumbent destination is overwritten. A
source-name replacement detected after that move is restored to its original
name before publication fails closed.
Output, sidecar, and marker staging names are deterministic and reserved.
Each exclusively created staging inode remains open through all writes and is
identity-bound before Windows releases its handle for publication. The generator
captures each canonical target's exact pre-generation state, then rechecks it at
the transaction boundary. Final moves and rollback restores are no-replace, so a
late target is preserved rather than overwritten.
Forced-regeneration layout policy uses those same captured target snapshots, and
recovery removes a newly published canonical target only while both its verified
digest and filesystem identity still match.
Transaction cleanup authenticates the complete set of marker, stage, and backup
artifacts before deleting any of them, then carries each exact identity through
an unguessable retirement name. POSIX ctime participates in identity checks, so
an in-place same-size mutation cannot be hidden by restoring mtime.
Marker-free remnants are preserved and rejected for manual recovery; once a
valid marker exists, a staged remnant is removed only when its digest matches
the authenticated transaction. A pre-existing legacy or tokenized `.retired...`
path is never deleted merely because of its filename. The sidecar's published spelling is always the
exact output-derived `<PDF filename>.json`, including case.

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
  leaving Supernote's own link-history stack authoritative; direct Original
  Back after several link jumps validates the newest native destination before
  restoring the oldest recorded source half; unresolved history authority and
  unmatched or ambiguous internal link targets are consumed rather than being
  allowed to navigate without an authenticated half mapping; and
- reruns Supernote's own orientation refresh after a configuration transition,
  so its native split mode, toolbar, handwriting state, and bitmap all move to
  the new orientation together.

It does not compose bitmaps, remap pen coordinates, modify annotation files,
or hook any annotation subsystem.

GitHub CI runs this module's complete host-side suite and then invokes the same
cross-platform build used locally, compiling the Android hook and producing,
signing, and verifying the companion APK. The build fails before signing if
payload injection fails or if `classes.dex`, `assets/xposed_init`, or the LSPosed
scope entry is absent from the assembled archive.

## Build and test

```powershell
.\test.ps1
.\build.ps1
```

The signed APK is written to `build\artifact`.

Only `com.supernote.document` should be selected in LSPosed. Do not enable the
legacy Native Spread Probe at the same time.
