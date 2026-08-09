# Native Spread annotation trace schema

`events.jsonl` contains one JSON object per line. Schema version 1 uses a
monotonic `seq` within one session plus wall-clock and uptime timestamps. Pen
transactions receive a `transaction` number at first contact and retain it
through `receive_trials_finished`.

The trace root's `active.txt` identifies the session currently recording.
`last.txt` identifies only a fully finalized session: it is updated after the
final snapshot and stop event are written, immediately before `active.txt` is
removed. A failed startup therefore leaves the previous completed-session
pointer unchanged.
If the document process terminates before finalization, the next trace-helper
action removes the abandoned `active.txt` pointer after validating its recorded
PID. The partial session directory is retained for diagnosis and `last.txt`
continues to identify the preceding completed session. A `Stop` action reports
the recovered incomplete session and refuses to pull that preceding session in
its place.
At normal shutdown, final snapshot capture is retried up to five times if the
source changes during hashing or copying. `last.txt` is published only after a
stable attempt. If all attempts fail, `incomplete.txt` names the partial
session, `active.txt` is removed, and the helper reports the incomplete result
without treating it as finalized.
The source identity is checked again after the copied snapshot is hashed; a
rewrite during that verification makes the attempt unstable and retryable.
Missing-file and unchanged-hash fast paths also recheck the live source before
they can complete finalization.
Snapshot diagnostics precede the last re-stat; successful paths do no logging
between final source verification and acceptance.

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
