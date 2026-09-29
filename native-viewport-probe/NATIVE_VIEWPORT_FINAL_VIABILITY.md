# Final bounded viability decision: stock writer in a custom viewport

Status: **NO-GO for the current architecture on the pinned Nomad firmware**.
This source-based decision uses existing read-only Nomad evidence; it is not a
claim that every possible firmware rewrite is impossible. No **new** Nomad
access, package installation, PDF/`.mark` change, or hardware test was part
of this decision. Preserve the experimental branches and
their evidence; do not promote the visual lease to a writable build.

## 1. Native writer witness — NO-GO

The pinned DrawPath service has no established non-mutating endpoint that
atomically returns exact page/layer, effective writable regions, service
incarnation, and a non-reusable **pre-write** generation. The Java presenter and
Binder setters are commands, not read-back authority. The observed service
paths do not share a lock: page/layer (`setAppInfo`) is written without the
region setter's lock; the derived write-area update has another lock; and
pen-up copies page/layer and area without a lock shared by both setters.
The worker's own pen-up mutex does not fence those setters. A timestamp or a
two-sample memory read cannot prevent ABA or in-flight-contact ambiguity.
See [NATIVE_WRITER_AUTHORITY.md](NATIVE_WRITER_AUTHORITY.md).

A process-local observer could record these calls, but observing does not make
their state atomic. A credible target-owned witness would require a reviewed
service-owned synchronization/generation change spanning both setters and the
pen worker, plus verified safe installation, quiescence, removal, and crash
recovery. No such narrowly isolated implementation or verification model has
been established. It would change the native service's concurrency behavior,
not merely expose an existing read-only value. Under the requested hard-stop
rule, **do not open another speculative Nomad capture to search for it**.

## 2. Target-owned rollback — not established

The tested `TargetOwnedVisualLeaseCore` models a main-Looper deadline, exact
owned-child removal, and structural/paint verification. Its Android Port is
disconnected from the stock Document activity; it has no actual owner that
certifies every stock scene mutation or independently reports a terminal
restored state after PC/Frida failure. The emulator result is synthetic and
does not prove restoration of the live stock reader. A durable process-local
helper is plausible while the stock process and main Looper remain responsive,
but it has not been implemented or validated. Frida unload, task restart, or
process death cannot be counted as exact live rollback. See
[TARGET_OWNED_VIEW_ROLLBACK_V1.md](TARGET_OWNED_VIEW_ROLLBACK_V1.md) and
[disposable-lease-host/README.md](disposable-lease-host/README.md).

## 3. Canonical coordinate/layer ownership — not established

Stock landscape split mode crops the `1404x1872` source page before display:
the observed `showRect` is `1404x1053` and the displayed bitmap is
`1872x1404` (the later live capture is recorded in
[REGRESSION.md](../REGRESSION.md), “Stock split/crop v2 micro-experiment”).
PDF, digest/persisted highlighting, and dry `.mark` ink are
separate native layers. The three `TrimmingUtil.adaptiveTrimming` callers can
identify their raster output paths, but changing those outputs alone leaves
live text-selection rectangles, hit testing, tool state, and saved geometry in
the stock split coordinate system. Forcing `isSplit`/`showRect` also changes
native pen rotation, recognition offsets, trimming, and repository geometry.
See [NATIVE_PAGE_VIEWPORT_GATE.md](NATIVE_PAGE_VIEWPORT_GATE.md) and the pinned
`DocumentViewModel`, `HandWritePresenter`, and `DocumentActivity` source audit.

The physical pen is not an Android View child: DrawPath reads the Wacom input
device and writes wet ink/erase pixels directly to `/dev/ebc` planes whose
addresses are retained by native painter objects. Moving or scaling an
Android page View does not remap that input/output. No verified bridge binds
background, committed ink, wet output, selection/eraser, navigation and `.mark`
coordinates to one unchanged canonical page while presenting it in a half
screen. See [NATIVE_PEN_BOUNDARY.md](NATIVE_PEN_BOUNDARY.md) and
[NATIVE_ENGINE_STARTUP.md](NATIVE_ENGINE_STARTUP.md).

The source-only audit therefore does **not** admit a writable native spread,
even if a future visual-only screenshot looks correct. There is no overnight
hardware action to take. Reopening this architecture would require a new,
concrete service-side witness and coordinated pen-output design, not another
smaller UI observation.

## Product pivots

| | A. Custom RTL spread plus our annotation layer | B. RTL spread reading plus stock single-page editing |
| --- | --- | --- |
| Complexity | High: own pen capture, stroke/eraser/lasso/highlight model, persistence, export, and conflict handling. | Moderate: make the existing page handoff and return path reliable; stock reader continues to own all editing. |
| Existing Supernote annotations | Originals stay untouched, but displaying/importing existing `.mark` faithfully and reconciling later edits need separate validation. Do not promise native round-trip fidelity. | Preserved and edited by the untouched native reader on the original PDF/`.mark`; the separate RTL spread may not yet display those marks or native highlights. Verify that explicitly before relying on this workflow. |
| Pen/tool fidelity | Must be rebuilt and hardware-tested; native latency and complete tool parity are not inherited. | Native pen, erasers, lasso, text selection, highlighting, Undo/Redo and save behavior remain stock while editing. |
| Reading/editing workflow | Two-page RTL reading and writing could eventually share one view. | Tap a spread page to edit it in stock single-page view, then return to the same RTL spread. The mode change is visible, but avoids dual-page writer state. |
| Likely Nomad performance | Existing direct PDF rendering/prefetch is fast for reading; annotation latency and e-ink refresh are unproven. | Existing cached RTL page turns are fast; native single-page ink performance is retained. Mode-switch latency needs a bounded hardware test. |
| Main risks | Annotation compatibility, tool completeness, palm rejection, wet-ink latency, canonical export/import and conflict resolution. | Robust bidirectional page/position handoff, mode-switch UX, and keeping native edit actions isolated from RTL navigation. |
| Reuse | Existing RTL renderer, cover/direction/navigation/cache; InkBridge canonical annotation work may help later. | Existing RTL renderer, navigation, cover rules, per-file settings, and already demonstrated close-to-native page handoff. |

**Recommendation:** productize **B** first as the shortest safe route to the two
reading goals plus full native editing on demand. The current reader already
hands a selected PDF/page to the native app on Close; a per-page Edit action
and automatic return to the same spread still need implementation and hardware
validation. The experimental Native Spread LSPosed module must be disabled for
the untouched-native-editor baseline, then ordinary PDF/`.mark` behavior must
be regression-tested. A separate visible-annotation check is needed in both
modes so writing that survives in stock editing is not silently invisible in
the RTL spread. Keep **A** as a separate longer-term project if seamless
writing directly across a two-page spread is essential. Neither option
requires changing original PDFs merely to read them. No pivot implementation
or merge begins until the user chooses the product behavior.
