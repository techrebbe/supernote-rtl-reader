# Native Spread annotation trace schema

`events.jsonl` contains one JSON object per line. Schema version 1 uses a
monotonic `seq` within one session plus wall-clock and uptime timestamps. Pen
transactions receive a `transaction` number at first contact and retain it
through `receive_trials_finished`.

Every stateful event may include:

- `readerPage`: zero-based PDF page held by `DocumentViewModel`;
- `visibleReaderPage`: the corresponding one-based page number;
- `markPage`: Supernote's one-based handwriting page;
- `pendingActivationPage`: zero-based inactive spread page being committed;
- `orientation`: Android configuration orientation;
- `editable` and `coverSeparate`: the active Native Spread configuration.

Important event families:

- `pen_contact_started` / `pen_contact_ended`: physical pen transaction and
  resolved spread page;
- `trail_container_returned`: operation trails emitted by libsupernote;
- `save_trails_started` / `save_trails_finished`: native save lifecycle;
- `receive_trials_started` / `receive_trials_finished`: completed pen/eraser
  lifecycle;
- `modify_page_trails_started` / `modify_page_trails_finished`: explicit
  page-local replacement transaction;
- `annotation_boundary`: ordered file-backed and in-memory trail summaries;
- `mark_file_event`: filesystem notification for the active `.mark` file;
- `mark_snapshot`: a stable, SHA-256-verified snapshot whose contents differ
  from the preceding snapshot;
- `handwrite_bitmap_submitted`: transient/canonical display-composition input;
- `module_log`: the existing detailed Native Spread diagnostic stream.

Each trail summary contains an ordered-list fingerprint and per-trail
fingerprints derived from identity, tool attributes, eraser references,
recognition/refresh/shift rectangles, contour geometry, and all point
coordinates. This permits exact state comparison without relying on a
screenshot. Screenshots remain useful for distinguishing correct persistence
from incorrect visible composition.

The bundle can contain document paths, handwriting geometry, screenshots, and
raw `.mark` data. Treat it as private document data.
