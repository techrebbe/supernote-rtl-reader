# Native Reader v2 review gates

No diagnostic or release APK may reach the Nomad unless every applicable gate
below passes on the exact source head used to build it.

## Architectural gates

- One `SpreadSession` is the sole authority for document identity, page pair,
  active page, layout generation, gesture route, and activation transaction.
- There is one authoritative page-to-screen affine per visible source page.
  PDF, ink, digest, links, text, lasso, menus, and input may not independently
  reconstruct geometry.
- The inactive page is immutable. No production path may merge, replace,
  synthesize, or directly edit its `.mark` state.
- A native edit can run only after the reader, presenter, note object, draw-path
  client, page index, layout generation, and gesture token agree.
- Gesture routing is selected once at `ACTION_DOWN` and cannot change through
  `ACTION_UP` or `ACTION_CANCEL`.
- Native chrome pass-through is gesture scoped. Document gestures cannot become
  toolbar gestures after crossing a boundary, or vice versa.
- Portrait mode restores Supernote's original page stack and identity affine;
  only explicitly enabled RTL navigation may remain altered.

## Concurrency and lifecycle gates

- Every delayed callback carries immutable activity, document, page, layout,
  and transaction generations and rejects any mismatch.
- Only one activation transaction may own the writer. Timeout, cancellation,
  process recreation, rotation, page turn, Back, and document replacement must
  have deterministic transitions.
- No filesystem operation, hashing, JSON parsing, reflection discovery, bitmap
  composition, or blocking lock is allowed on the low-latency pen callback.
- Buffered pen data is bounded by sample count, byte count, and time. Overflow
  fails visibly without native mutation.
- Activity destruction and document replacement retire every callback,
  buffered gesture, bitmap, writer claim, and native component identity.
- Save acknowledgement must precede source-owner release. Target load and
  component verification must precede writer publication.

## Data-integrity gates

- Original PDF and `.mark` files are the only document/annotation authority.
- Production code never edits serialized `.mark` bytes directly.
- A failed activation cannot write to either source or target page after its
  ownership token becomes stale.
- Undo/Redo remains native and page local. The module may not fabricate history
  entries to conceal an activation or persistence failure.
- Recovery evidence binds exact PDF and `.mark` bytes before editable testing
  on a non-disposable document.
- Every failure path is tested for preservation of unrelated strokes.

## Containment gates

- Every behavior-changing hook proves the exact active activity, original PDF,
  enabled document setting, supported firmware, component identity, and
  current generation before changing arguments, results, or native state.
- Without that proof the original method is invoked exactly once with unchanged
  arguments and its result/exception is preserved.
- Module installation alone cannot affect an ordinary PDF.
- Disable/Off retires ownership before restoring native geometry and callbacks.
- Unsupported firmware or native symbol drift disables the complete feature;
  partial activation is forbidden.

## Adversarial automated gates

- Exhaustive state-machine transition tests, including every invalid edge.
- Property tests for RTL/LTR, cover parity, both rotations, odd page counts,
  mixed page geometry, fit/fill, gutter, and clipped margins.
- Mutation tests that remove or reorder every authority check and require a
  deterministic failure.
- Race tests for stale load completion, save completion, hover/contact overlap,
  rapid side changes, rapid turns, rotation, activity replacement, and close.
- Gesture corpus replay for finger, hover, pen, eraser, lasso, text selection,
  recognized line, toolbar contacts, cross-divider motion, cancellation, and
  malformed/missing terminal events.
- Bitmap/cache tests for stale page, recycled bitmap, partial annotation layer,
  document replacement, and generation mismatch.
- Package tests for exact version, signer, LSPosed scope, native-library ABI,
  deterministic source inputs, and artifact hash.

## Review gates

1. Review the state machine, geometry, gesture router, native writer boundary,
   rendering/cache, settings provider, and containment as separate subsystems.
2. Batch accepted findings; do not start a review-fix-review loop per finding.
3. Run the complete deterministic matrix after the batch.
4. Perform one integrated review of the exact candidate head.
5. Require a clean confirmation review of that unchanged head.
6. Resolve every correctness or safety finding before device installation.
7. Keep the PR unmerged until the user completes the hardware gate and decides
   to merge.

## Hardware gates

- Begin with ordinary-document inertness and a disposable calibration PDF.
- Capture exact version, signer, firmware, logs, screenshots, `.mark` identity,
  and before/after page-element evidence.
- Test every native tool on each physical side and both landscape rotations.
- Exercise initial inactive-page input with finger, hover, and direct pen down.
- Test rapid navigation/activation and rotation during every transaction phase.
- Reopen in ordinary portrait and verify native position, size, editability,
  Undo/Redo, and InkBridge export.
- Repeat the final matrix on one backed-up real document before release.

## Release evidence

- The source commit, APK SHA-256, package version, signer certificate, test
  matrix, review result, and hardware evidence must identify one exact build.
- Rebuilding that source head with the pinned toolchain must reproduce the same
  unsigned payload; signing inputs and any expected signature variance are
  recorded separately.
- A release candidate is rejected if any evidence was gathered from an older
  installation, an uncommitted source tree, or a differently signed package.
