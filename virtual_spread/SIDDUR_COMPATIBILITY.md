# Siddur compatibility assessment

The inspected source PDF is immutable and remains SHA-256
`235140b21b941548ab817cbc2d6a5e4a733fc7028d2911668806021e40046f98`.
It contains 663 source pages and 25 outline items (15 top-level and 10 nested).
Nineteen items are actionable and six are structural. Six actionable entries
use `/Fit`; thirteen use `/XYZ`.

The focused compatibility path preserves the outline hierarchy, titles,
ordering, style, and target source page. Supernote exposes outline navigation
at page granularity, so the 13 validated `/XYZ` entries are converted to
authenticated fit-source-page destinations only when
`--normalize-outline-viewports` is supplied. One structural `Sheet1` entry has
a literal null target; `--discard-broken-outline-destinations` retains its
title and hierarchy while removing only that unusable destination.

The source contains 1,442 `/Named /NextPage` or `/PrevPage` link actions.
`--remove-adjacent-page-links` removes those validated previous/next actions
and any direct or named internal link targeting exactly one neighboring
original source page. This is opt-in because it also removes a genuine
adjacent-page reference. Same-page, distant, external URI, and outline links
remain. For this source, 1,448 adjacent-page links are removed in total and
901 links are retained. Four additional internal links contain a literal
PDF-null target; `--discard-broken-internal-links` removes only those already
nonfunctional links. Four oversized `/FitR` destinations wholly enclose the
target source page; `--normalize-oversized-fitr-links` converts only that exact
case to fit-source-page. Partially out-of-bounds viewports still fail. Eighteen link
rectangles exceed a CropBox by no more than 0.442 point; the generator clips
only up-to-0.5-point rectangle bleed and continues to reject larger overflow or
any out-of-bounds `/QuadPoints`.

Five intentional `/Square` annotations are used as visible highlights or
whiteouts and each has a closed empty `/Popup`. With
`--flatten-square-annotations`, the generator validates the annotation flags,
rectangle, normal appearance Form XObject, exact appearance matrix, and paired
popup, then paints that appearance into the derived page content. The derived
spread contains no editable `/Square` or `/Popup`; the immutable source keeps
the original editable objects. Unknown, hidden, open, orphaned, or differently
structured annotations continue to fail closed.

The source's empty AcroForm shell is safely omitted. XMP XML metadata and RTL
`/ViewerPreferences /Direction /R2L` are preserved. Page thumbnails are cache
artifacts and are omitted; the exact supported RGB transparency group is
preserved. The source also contains accessibility structure that cannot be
correctly remapped after two pages are composed. The user explicitly approved
`--discard-structure-tags` for this derived device cache: the generated spread
omits `/StructTreeRoot`, `/StructParents`, and structure-order `/Tabs`, while
leaving visible text and graphics unchanged. This removes tagged-PDF reading
order/accessibility semantics only from the derived copy, never from the
original PDF.

These switches do not silently change the frozen mapping contract. Each one
authorizes one deterministic repair for an input that otherwise fails; if its
target condition is absent, enabling it produces no alternate representation.
The original SHA-256 continues to bind the source, and the generated PDF,
mapping, links, navigation records, output hash, view ID, and cache basename
remain authenticated through the existing schema-v4 authorities.

The validated invocation is:

```powershell
python .\virtual_spread\generate_virtual_spread.py `
  C:\SupernoteVirtual\siddur.pdf `
  output\pdf\siddur.virtual-spread.pdf `
  --direction rtl `
  --cover-separate `
  --spread-width 864 `
  --spread-height 648 `
  --gutter 0 `
  --remove-adjacent-page-links `
  --discard-structure-tags `
  --flatten-square-annotations `
  --discard-broken-internal-links `
  --normalize-oversized-fitr-links `
  --normalize-outline-viewports `
  --discard-broken-outline-destinations
```

Generation always publishes a separate derived PDF/sidecar pair. It never
edits `siddur.pdf`.
