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
screen. Source pages are fitted independently into fixed left and right slots,
so unusual source page sizes cannot change the reader's navigation surface.
Content streams remain vector/text PDF content rather than page screenshots.
Supported internal and URI links, including indirect destination arrays, are
copied with transformed hit rectangles; internal destinations are remapped to
their virtual spread page. A JSON manifest records every source-page affine
transform and target half.

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
  --manifest output\pdf\source.virtual-spread.pdf.json `
  --direction rtl `
  --cover-separate
```

The command refuses encrypted PDFs, unsupported annotation subtypes, unresolved
links, and existing outputs unless `--force` is supplied. It copies and hashes
the source through one file snapshot, re-reads the opened source to prove that
the copied bytes are stable, generates only from that verified snapshot, and
rehashes the current source before publication. The PDF and manifest are each
staged and validated before publication as one recoverable pair. A durable
transaction marker is synced before either previous file is moved. If the
process is interrupted, the next run either recognizes the fully published pair
by both staged hashes and finishes cleanup, or restores the previous PDF and
manifest from the recorded backups. Ordinary publication errors use that same
recovery path immediately.
The manifest records the staged PDF's exact size and SHA-256, which the runtime
module verifies before trusting its mappings. A canonical digest of every link
record is also embedded in the generated PDF and verified against the sidecar,
preventing a separately edited sidecar from omitting or retargeting links.

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
conversion layer.
