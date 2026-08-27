# Virtual Spread proof of concept

This experiment gives Supernote's unmodified native document reader one real
PDF page per physical spread. It does not compose a second live page inside
`DocumentActivity` and does not maintain two simultaneous handwriting owners.

For an RTL document with separate-cover parity, the generated PDF contains:

```text
virtual page 1:  blank  | source page 1
virtual page 2:  page 3 | source page 2
virtual page 3:  page 5 | source page 4
```

Every virtual page uses the same 4:3 page box, matching the Nomad's landscape
screen. Custom coordinate dimensions may scale that box but must retain the 4:3
ratio; both generator and companion reject other aspects. The generator's
programmatic boundary accepts only finite real numeric values for the spread
width, height, and gutter; Python Booleans are rejected rather than being
serialized as JSON values that Android would later reject. Source pages are fitted independently into fixed left and right slots,
so unusual source page sizes cannot change the reader's navigation surface.
Content streams remain vector/text PDF content rather than page screenshots.
The output retains the source document's declared PDF language version rather
than silently falling back to pypdf's `%PDF-1.3` default, and the staged output
is reread to verify that header before publication.
Supported internal and URI links, including indirect destination arrays, are
copied with transformed hit rectangles. Multiline `/QuadPoints` activation
regions are transformed point-for-point rather than widened to their bounding
rectangle. Standard annotation `/F` flags, visible `/Border` and `/BS` styling,
border color, and `/H` activation highlight mode are validated and preserved;
border dimensions and dash patterns follow the source-to-spread scale and page
rotation. A `/NoRotate` annotation flag on a rotated source page fails closed
because source rotation is baked into an unrotated virtual spread; copying that
flag would change its meaning. A `/NoZoom` flag likewise fails closed whenever
the source page is scaled into its half, because transformed annotation geometry
would otherwise have different viewer semantics. Underlined `/BS /U` links likewise fail closed
when page rotation would move the underline to a different physical edge. URI
actions retain a Boolean `/IsMap`, but the URI must be absolute. A relative URI
depends on document-catalog base state that this representation does not
preserve and therefore fails closed. Chained actions, custom
appearances, optional-content visibility, additional actions, and every other
unimplemented link semantic fail closed rather than being silently discarded.
Link `/Rect` arrays require four finite PDF number objects in increasing
coordinate order; numeric strings and non-finite values are never repaired.
URI operands likewise require real PDF text/Boolean objects. Internal `/Fit`
destinations become `/FitR` destinations around the original target source
page's placed rectangle, preserving Fit-page semantics instead of fitting the
entire two-page composite. Because source `/Fit` contains no explicit viewport,
the authenticated `targetView=fit-source-page` policy makes the companion restore
Supernote's native Fit-page view after the link loads. This path is distinct from
an explicit source `/FitR` viewport and has passed focused Nomad validation on
both target halves. `/XYZ` and `/FitR` retain their representable source
semantics while their coordinates are transformed into the target spread; a
source `/FitR` rectangle must be positive and remain wholly inside the target
source page's effective CropBox. Its aspect-fitted portrait viewport must also
remain wholly inside the target half, so it cannot expose a neighboring
composed page. Every explicit `/XYZ` left or top coordinate must likewise remain
inside that CropBox. Preserving `/XYZ` also requires an explicit horizontal anchor and
a positive explicit zoom whose resulting portrait viewport remains wholly
inside the target half; retained/zero zoom, an unknown horizontal anchor, or a
viewport that reaches the neighboring half fails closed. A positive `/XYZ`
zoom is divided by the target's validated uniform affine scale so the
source-page magnification remains unchanged. Viewport- and content-bound
`/FitB`, `/FitH`, `/FitBH`, `/FitV`, and `/FitBV` destinations cannot be
represented faithfully after composition and therefore fail closed. Duplicate
annotation `/NM` identifiers that would collide after two source pages are
paired likewise fail closed before publication. Unknown modes, invalid PDF
operand types, rotation-dependent partial coordinates, non-uniform zoom
transforms, and null coordinates whose source and target axis transforms differ
fail closed instead of silently degrading; every transformed destination
operand is also rechecked for finite output before serialization. A JSON manifest records every
source-page affine transform and target half. The companion runtime supports RTL
virtual spreads only, so the generator rejects LTR at its public boundary before
acquiring a publication lock or touching an output.

## Reproducible Python environment

Python 3.12 is used in CI (Python 3.10 or newer is required). Install the
generator's exact tested dependencies in an isolated environment:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r .\virtual_spread\requirements.txt
```

## Generate

```powershell
python .\virtual_spread\generate_virtual_spread.py `
  source.pdf `
  output\pdf\source.virtual-spread.pdf `
  --direction rtl `
  --cover-separate
```

The caller-selected output above is a host staging name, not the on-device
cache identity. Read `output.cacheBasename` from the generated JSON, then
publish the unchanged PDF to that exact basename and its JSON sibling to
`<cacheBasename>.json` before opening it on Supernote. v0.0.25 rejects a valid
pair opened under `source.virtual-spread.pdf` or any other renamed basename.
See `MAPPING_WIRE_CONTRACT.md` for the versioned cache layout.

The command refuses encrypted PDFs, unsupported annotation subtypes, unresolved
links, and every document-catalog semantic it cannot preserve safely. It
regenerates the structural `/Type` and `/Pages` entries and preserves validated
`/PageMode` names plus compatible `/SinglePage` and `/OneColumn` page layouts.
Source `/TwoPage*` and `/TwoColumn*` layouts fail closed because applying them
after composition would display two virtual spreads—up to four source pages—at
once. Outlines, opening actions, optional-content layer configuration, viewer
preferences, and every other unsupported or unknown catalog entry fail closed
before staging or publication rather than being
silently discarded. Source page dictionaries use the same complete contract:
content, resources, geometry, rotation, and supported link annotations are
consumed explicitly; ReportLab's empty transition placeholder is inert; page
durations, meaningful transitions, additional actions, user-unit scaling, and
every other unsupported or unknown page entry fail closed. Persisted rotation
must be a true PDF integer divisible by 90. Quarter-turns are transferred with
exact `0/1/-1` matrices, so the mapping and PDF content do not contain
trigonometric near-zero coefficients. CropBoxes with absolute offsets large
enough to lose the mapping contract's placement or round-trip precision fail
before staging or publication. The document information dictionary
is copied with primitive PDF types intact; standardized text and `/Trapped`
entries are validated, while arrays, dictionaries, streams, or other unsupported
values fail closed rather than being stringified. Existing outputs also require
`--force`. A forced replacement must also state every persisted layout choice
explicitly: `--cover-separate` or `--no-cover-separate`, `--spread-width`,
`--spread-height`, and `--gutter`. This prevents an unattended regeneration from
silently resetting a document's cover parity or spread geometry to defaults.
The command rejects a source path that collides with its output's
deterministic marker, backup, retirement, or lock artifacts before recovery or
lock acquisition. It copies and hashes the source through one file snapshot,
re-reads the opened
source to prove that
the copied bytes are stable, generates only from that verified snapshot, and
rehashes the current source before publication. The PDF and manifest are each
protected by a deterministic OS-owned lock keyed only by the output PDF for the
entire recovery, generation, and publication operation. A concurrent generator
targeting the same output fails without touching the live transaction; a crashed
process releases the lock so the next invocation can recover it. A new lock
file is initialized only when its inode was created with exclusive-create and
is still an unaliased regular file. An existing empty lock or any lock with
multiple hard links fails closed and is never initialized or otherwise mutated,
so a hostile lock pathname cannot be used to alter another file. The Android
runtime discovers only the sibling `<output>.json` sidecar. The generator uses
that path by default and rejects any other `--manifest` path before acquiring a
lock or changing an output, preventing alternate sidecars from bypassing either
runtime discovery or publication ownership. For the same reason, an output path
that contains a symlink, junction, or other filesystem alias is rejected both
before and after acquiring publication ownership; the lexical path is retained
through every recovery and publication boundary. The runtime-visible PDF and
sidecar must share one unambiguous path. Existing PDF, manifest, marker, and
backup entries must be regular files; directories and other special entries are
rejected rather than renamed, even with `--force`. Backup destinations are
created without replacement and are revalidated immediately before each move.
The persistent OS lock is opened without following links where the platform
supports it; its path and descriptor must identify the same regular file before
initialization and again after lock acquisition. On POSIX, every publisher first
locks the already-open output-directory inode and holds it until the per-output
lock and complete transaction are released. All cooperating publishers acquire
those locks in that order, so unlinking and recreating the per-output lock cannot
admit a second recovery or publication owner. This intentionally serializes
virtual-spread publications that share one directory on POSIX; Windows already
prevents replacement of the open per-output lock. Both identities are rechecked
before every shared transaction operation. On POSIX, staged-file creation,
writing, reopening, hashing, size/type inspection, marker and backup handling,
publication, rollback, and cleanup are all relative to the retained output-
directory descriptor rather than its replaceable pathname. The source snapshot
is kept in one already-open temporary stream outside that namespace. If the
parent pathname is exchanged before an operation, validation fails closed; if
it is exchanged between validation and the syscall, the descriptor-relative
operation remains confined to the originally locked directory and cannot touch
the replacement tree. Staged artifacts are type- and hash-checked before backup
moves and immediately before publication, and both canonical hashes are verified
before recovery evidence is retired. Every exclusively created staging inode is
kept open through all writes, so replacing its pathname cannot redirect output
into a source hard link. Windows releases that handle only after recording the
same identity required by the subsequent move. The exact output and sidecar state
authorized before generation is rechecked at the transaction boundary; a target
that appears, disappears, or changes meanwhile is preserved and rejected. Final
publication also reopens and hashes the canonical source immediately before
transaction preparation and again after the new PDF/sidecar pair has moved but
before rollback evidence is retired. A matching PDF/sidecar pair remains
rollback-only until that second check publishes a separate, fsynced
source-commit record. The record is bound to the transaction-marker hash, both
new canonical hashes, and the source path, identity, size, timestamps, and
SHA-256. Crash recovery revalidates that persisted source snapshot before it
may classify the pair as committed. A crash before the record, a changed source,
or a record that does not exactly match its marker therefore restores the old
pair (or removes a first-published pair). Cleanup retires the marker before the
source-commit record only for a committed transaction; an orphaned final record
can finish cleanup solely after it authenticates both canonical files. This
closes the process-death interval between the final source check and ordinary
cleanup without making an incomplete matching pair authoritative. Publication
and backup restoration use atomic
`renameat2(RENAME_NOREPLACE)` moves on POSIX, so an incumbent destination is
never overwritten and no link-then-path-unlink cleanup can delete a recreated
source. The moved entry is checked against the authenticated source identity.
If that post-move identity is wrong, the race is inherently ambiguous: a
non-cooperating writer may have replaced either the source before the move or
the destination afterward. The generator preserves the destination exactly
where it is and fails closed. Any existing transaction evidence remains intact,
and it never moves a potentially writer-owned destination back to the source. A host lacking
the no-replace primitive fails closed rather than falling back to a lossy
emulation.
Forced-regeneration layout policy is derived from those same captured target
snapshots, so a target that appears after an earlier existence observation still
requires explicit cover and geometry choices. Recovery also binds every cleanup
to both its authenticated digest and exact filesystem identity. The marker,
stages, and backups are authenticated before cleanup begins, then each exact
identity is carried first through an unguessable `.retired...` name and then,
without replacement, into an unguessable `.retained...` namespace. Cleanup
never truncates or unlinks those authenticated bytes: POSIX cannot prove that
an inode has not gained a new hard-link alias between a link-count check and a
mutation. A late alias therefore remains byte-for-byte intact, while a source
or destination substitution is preserved and fails closed. Successfully
retained files are inert and ignored by transaction recovery; they are kept
until the containing versioned cache directory can be safely garbage-collected.
A same-content pathname replacement is preserved. POSIX
identity checks include
ctime so an in-place, same-size mutation cannot hide behind a restored mtime;
the generator permits only the ctime transition caused by its own
atomic namespace move. The returned post-move identity becomes authoritative
for every subsequent publication check.
The PDF and manifest are staged before publication as one recoverable pair.
Their output-derived temporary names are deterministic, so a process death
cannot leave an unbounded collection of randomly named files. Before a marker
exists, any occupied staged name is preserved and generation fails closed for
manual recovery. After a valid marker exists, recovery removes a remaining
stage only after its SHA-256 matches that marker's authenticated transaction;
a mismatched stage is preserved. Likewise, a nonempty or non-regular legacy or
tokenized `.retired...` name is never treated as disposable scratch data:
publication and recovery stop without changing it. Authenticated zero-length
`.retired...` tombstones left by an older completed cleanup remain inert and
ignored; current cleanup publishes nonempty bytes only under `.retained...`. A
transaction marker is durably published before
either previous file is moved. POSIX builds
sync every affected parent directory; Windows builds use
`MoveFileExW(MOVEFILE_WRITE_THROUGH)` for the marker, backup, publication,
rollback, and retirement renames. If the process or machine is interrupted, the
next run recognizes the fully published pair only when both staged hashes and
the bound source-commit record authenticate it; otherwise it restores the
previous PDF and manifest from the recorded backups. Publication marker v2
records the prior pair's SHA-256 values; recovery
reads, hashes, and parses that marker through one descriptor-bound snapshot,
authenticates each backup before restoring it, and preserves the marker plus
evidence if any backup was altered. Before every retirement for a committed,
rolled-back, or discarded transaction, it revalidates both canonical path
existence states, identities, and hashes captured for the settled pair.
A canonical target found in front of a valid
backup is overwritten only when it still matches the transaction's staged hash;
an unrelated or concurrently replaced target is preserved and recovery fails
closed. An interrupted v1 transaction containing
backups therefore fails closed rather than restoring unauthenticated bytes.
Recovery compares recorded paths with the host filesystem's case and separator
semantics, so a Windows drive/path casing change does not strand an otherwise
authentic transaction; dot-segment and other lexical aliases remain rejected.
The published sidecar nevertheless always uses the exact output-derived
`<PDF filename>.json` spelling, including case, so copying the pair onto
Supernote's case-sensitive storage cannot make the runtime sidecar invisible.
Ordinary publication errors use that same recovery path immediately.
Manifest schema `techrebbe.supernote.virtual-spread/v3` deliberately requires a
mapping-authority-capable companion. Older companions reject newly generated v3
pairs, and v0.0.25 rejects legacy v1/v2 pairs; regenerate the PDF and sidecar
together when upgrading. The manifest records the staged PDF's exact size and SHA-256, which the runtime
module verifies before trusting its mappings. A canonical digest of every link
record is also embedded in the generated PDF and verified against the sidecar,
preventing a separately edited sidecar from omitting or retargeting links.
A second canonical authority binds RTL direction, cover parity, source/output
page counts, spread dimensions, and gutter to that same hashed PDF. This keeps
an otherwise internally consistent sidecar from swapping cover pairing or
geometry. A third frozen digest authenticates every InkBridge-consumed mapping
field for every source page, including CropBox/rotation, virtual page/side,
destination, scale, and the authoritative forward affine transform. The same
mapping digest is bound into the PDF tail and into a deterministic view ID and
cache basename. Page indices are capped at Java's signed 32-bit maximum, and
both producer and runtime reject reflected or wrong-rotation matrices,
non-generator scale/fit, and off-center placement. Source filenames and paths
remain sidecar diagnostics only: byte-identical source PDFs under different
names produce byte-identical generated PDFs, output hashes, and cache identity.
Native module v0.0.25 recomputes and validates these records,
then authenticates each internal link's target-view
policy and the exact source snapshot. It rejects malformed UTF-8 bytes before
decoding, non-integral manifest page indices or output sizes, numeric strings or
non-finite values in spread/link geometry, and malformed or duplicate-key
manifest JSON at any nesting level, spread dimensions outside PDF's
3-to-14,400-unit page bounds, duplicate, concave, or self-intersecting link
quadrilaterals,
transformed URI `/IsMap true` actions, a source CropBox outside its MediaBox, and
link geometry outside the effective source CropBox. It preserves an omitted PDF
link border at its correct transformed default width. Link-authority v2 records
and the source marker fail closed on older generated pairs; regenerate the PDF
and sidecar together before opening them with v0.0.25. Native reader callbacks
perform only strong PDF and sidecar
identity checks. Sidecar reading/hashing, parsing, full-PDF hashing, and stable-
snapshot verification run on the single background verifier. Its bounded queue
keeps only the newest pending document, and an active full-file hash cooperatively
cancels when a newer document supersedes it. Document observation happens
before cache and sidecar-existence fast paths, so switching to an already cached
spread or to an ordinary sidecar-free PDF also cancels stale verification work.
While a matching PDF/sidecar snapshot is still being verified, native page turns
are consumed rather than leaking one wrong-direction LTR turn; navigation becomes
available as soon as the verified manifest is activated. A verified replacement
pair whose authority does not match Supernote's still-open native document also
keeps turns blocked until that document is reopened.
Native links tapped during that cold verification window are likewise consumed,
queued once, and replayed only after the same document and source page acquire
verified authority. It is bound to a unique verifier generation, the exact native
MuPDF document object, and all three embedded authorities rather than merely a
reusable path snapshot. Every native page-load callback advances a monotonic
generation even before manifest activation, and replay requires the exact
generation captured with the tap. The queued invocation is discarded after a document/page
change, verification rejection, native-document replacement, a newer manual
turn (including one blocked during verification), a newer already-verified
link, or its bounded freshness window. If a generated PDF is missing its
sidecar—or the native authority metadata cannot be inspected—
navigation remains blocked; an ordinary PDF whose native document explicitly has
no virtual-spread authority remains fully native.
Delayed callbacks from an older native view model cannot reclaim ownership. That verifier
opens each PDF and sidecar exactly once, binds the callback identities to those
descriptors, performs every content and authority read through the same open
handles, and finally proves the handles still match the visible pathnames. The
module then reads the source, layout, and link metadata from Supernote's retained
native MuPDF `Document` and requires all three to match before activating. A
pathname replacement consequently fails closed while the old native object is
still open and can activate only after Supernote reopens the replacement. The
module fails closed until both checks have passed.

The generator also enforces the companion runtime's exact 8 MiB sidecar limit
before publication. The limit, staged-file identity, and SHA-256 are captured
from one open descriptor and revalidated before transaction-marker creation,
immediately before the sidecar move, and after canonical publication. Recovery
will not accept an oversized sidecar as a committed pair. Oversized or exchanged
manifests therefore fail with an explicit error while any previous PDF/sidecar
pair remains intact.

The staged PDF receives the same descriptor-bound treatment. Its identity, size,
and SHA-256 are captured before strict PDF verification, revalidated afterward,
and then carried unchanged into the manifest and publication transaction. The
same evidence is checked before the sidecar move, before the PDF move, and after
canonical publication, so exchanging the staged PDF cannot make its sidecar
describe different bytes.

Recovery recognizes the prior v1 transaction schema only while no backup exists.
It validates the canonical paths, prior-existence flags, and staged hashes before
discarding a marker only when every previously existing artifact remains present
and does not match the staged digest, while every previously absent artifact is
still absent. A complete or partial new publication, any backup, and every other
ambiguous legacy state remain fail-closed with all evidence preserved. Unknown or
malformed markers always fail closed for manual recovery, even when no canonical
artifact or backup is present. Only a marker with the exact field set for its
declared schema can reach
legacy recovery classification; duplicate JSON keys or additional fields are
structurally ambiguous and always fail closed with the marker and canonical
evidence preserved.

Pull-request CI builds and verifies the companion APK with a short-lived
ephemeral certificate and never reads the long-lived upgrade signer. The
upgrade-compatible APK is rebuilt only by the successful trusted `main` push
job, which runs in the `virtual-spread-release` GitHub environment. That
environment accepts deployments only from `main` and is the sole location of
`VIRTUAL_SPREAD_APK_KEYSTORE_BASE64`; no repository-wide duplicate is retained.

## Nomad hardware result: GO

The generated documents were validated on a Supernote Nomad on 2026-08-21
with the previous Native Spread LSPosed module disabled and absent from the
document process. The unmodified native reader successfully handled:

- `blank | cover`, `3 | 2`, `5 | 4`, and `7 | 6` RTL spread pairing;
- native next/end-boundary navigation across normalized spreads;
- internal PDF links in both directions after destination remapping;
- native Back and Original Back with restoration of the exact portrait source
  half, including a fail-closed manifest fallback after a process restart;
- extreme and mixed source page boxes without the old page-turn failure;
- native pen input on both halves of one spread page;
- native erasing with persistence after a document round trip;
- native lasso selection, movement, dismissal, undo, and redo;
- native text selection and highlighting with correct alignment;
- persistence of all tested ink, erasure, lasso, and highlight changes; and
- native portrait writing followed by a clean document round trip.

A focused v0.0.15 revalidation on 2026-08-25 used a freshly generated
mixed-shape/link pair. It passed landscape cold-open, all RTL turns and
boundaries, portrait-half focus and rotation, both internal-link target halves
with native Back, native pen persistence, and sidecar-free ordinary-PDF
pass-through. This closes the v0.0.15 hardware release gate.

The portrait persistence check is especially important: `123` written in Box D
remained visible after switching documents and reopening the calibration PDF.
The native `.mark` grew from 82,566 bytes to 134,698 bytes and changed SHA-256
from `4e689512f5f5890fbb2b4b942eaa6927973cbc45ca0ebb15e235471f242babf7`
to `224865d95794788b15f420e893603e18ecef512ae641d911c53f2470534d62da`.

These results validate the central architectural claim: when a spread is one
real PDF page, Supernote retains one native page, one handwriting owner, one
coordinate system, one undo history, and one `.mark` record. Native annotation
features therefore work without intercepting or reconstructing their internal
state.

## Remaining boundary

The generator and its narrow companion module now provide RTL page progression,
portrait half focus, native page-bar boundaries, and link destination/history
half restoration. The project does not yet:

- show source-document page numbers instead of virtual spread numbers;
- regenerate or migrate annotations when the source PDF changes; or
- export virtual-page annotations back to source-page coordinates.

Annotation code remains deliberately untouched. The manifest supplies the
source-page, half, and affine-transform data needed for a later InkBridge
conversion layer. The versioned ownership, mapping-authority, cache, and
regeneration boundary for that work is recorded in
[`INKBRIDGE_REPRESENTATION_CONTRACT.md`](INKBRIDGE_REPRESENTATION_CONTRACT.md).
The v0.0.25 exact-head review and Nomad hardware gate are complete. It freezes
and enforces the representation boundary without adding annotation interception
to this companion. Hardware confirmed authenticated schema-v3 activation and
RTL navigation from the deterministic dot-cache path, fail-closed missing and
altered sidecars, ordinary-PDF pass-through, and absence of the cache from the
normal Supernote Documents library.
