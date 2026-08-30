# Siddur compatibility assessment

The inspected source PDF is immutable and remained SHA-256
`235140b21b941548ab817cbc2d6a5e4a733fc7028d2911668806021e40046f98`.
It contains 663 source pages and 25 outline items (15 top-level and 10 nested).
Nineteen items are actionable and six are structural. Six actionable entries
use `/Fit`; thirteen use `/XYZ`.

The schema-v4 bookmark implementation preserves the hierarchy, titles,
ordering, style, and representable target half. It does not yet make this exact
file convertible. The current strict preflight stops first at `/AcroForm`,
`/Metadata`, `/StructTreeRoot`, and `/ViewerPreferences`. Later independent
blockers include page thumbnails/tagging/groups, five `/Square` annotations and
their popups, four unresolved link destinations, several out-of-CropBox link or
viewport records, and 13 source `/XYZ` outline viewports that Supernote's
page-only outline UI cannot retain.

The file also contains 1,442 `/Named /NextPage` or `/PrevPage` link actions.
The opt-in adjacent-page filter now recognizes and removes those exact actions
when they resolve to an existing neighbor. It does not weaken validation of the
remaining links or bookmarks.

No source bytes were changed and no partial output was published during the
compatibility run. Supporting the remaining catalog, page, annotation, and
unrepresentable-viewport cases requires separately reviewed policies; they are
not silently stripped by this focused bookmark change.
