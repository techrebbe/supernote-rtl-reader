# Native Spread guidance

This file supplements the repository-root guidance for changes under
`native-spread-module/`.

## Code Review Rules

### Preserve canonical, page-local annotation semantics

- Flag annotation changes that can replace unrelated trails, mutate the wrong
  page, persist display-transformed coordinates as canonical data, or treat an
  incomplete transient bitmap/container as the saved page. Ordinary pen commits
  are additive; eraser, lasso, Undo, and Redo may replace state only for the
  intended operation and page. Safe path: begin from the verified canonical
  `.mark` page, apply the operation to its explicit document/page identity,
  preserve unrelated trails and pages, and verify the result through reload and
  portrait/landscape round trips.

### Tracing must neither perturb annotations nor publish uncertain state

- Flag filesystem access, JSON serialization, hashing, or other blocking work on
  pen, UI, hook, or native-writer callbacks. Those paths may capture immutable
  state and enqueue it to a serialized worker; completion must drain the worker
  before publishing session state.
- Flag every trace/snapshot success path that does not revalidate the live
  document, session, source identity, and copied content after its final
  fallible or delayed operation. Events and `last.txt` may be published only
  after acceptance. Startup, finalization, cleanup, or pointer-write ambiguity
  must fail closed while retaining the exact incomplete/publication-failed
  session; it must never fall back to an older successful trace.
