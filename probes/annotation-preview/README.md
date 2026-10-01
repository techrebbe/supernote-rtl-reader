# Disposable native handwriting PNG probe

This diagnostic is separate from the installed RTL Reader. It cannot edit,
close/reload/kill the Document process, or write a PDF/`.mark`. Its only SDK
operation is the pinned `PluginFileAPI.generateMarkThumbnails` read/render call.
JNI output/side effects remain a hardware question, not a source-only guarantee.

The bridge accepts only original zero-based PAGE 3 of
`/storage/emulated/0/Document/RTL_RAPID_TOOLS_T004_20261001.pdf`, whose exact source
SHA-256 is `ffb6c3b889ed455841d3c4f50a0813d844109c3c97255b4bbb5e4b949c9592c9`.
It requests 1404×1872 and retains one unique private PNG until explicit cleanup.
Original PDF/annotation byte and inode snapshots must match before and after.
These checks are change detection, not save durability or an atomic native revision.

The JS orchestrator defaults disabled. This dedicated diagnostic UI explicitly
enables a manual Generate-once action; normal reader startup never invokes it.
The plug-in ID, component key, and Android namespace differ from RTL Reader.
No existing source pins or installed package identity are changed.

## Earliest hardware gate

After basic host checks, package verification and independent review, obtain
fresh user approval and issue #23 reservation. Use the existing disposable
PAGE 3's retained ink/erasure/lasso/highlight, without new pen actions. One
thumbnail call only; do not turn pages, rotate, switch documents or draw while
it runs. Inspect dimensions, transparency/background, and alignment against the
stock reference; determine highlight coverage separately, without promising it.

PASS: bounded valid PNG, observed correct ink geometry, unchanged disposable
PDF/`.mark`, and verified owned-cache cleanup. A rejected output can be useful
evidence but is not a display PASS. STOP on context/hash mismatch, crash, an
unsettled SDK call, unexpected mutation or cleanup ambiguity. Do not start
another call to diagnose a failure. UNKNOWN is an acceptable outcome.

The SDK call has no cancellable timeout. JS cancellation suppresses delivery
but does not delete an output while JNI may still write. A stuck call remains
blocked and requires a separate recovery decision; no kill/reset fallback.

## Offline build

Run `scripts/build_annotation_preview_probe.py <pinned-template-tgz> <repo> <new-project>`.
It materializes the normal pinned template, installs only diagnostic sources,
and scopes the same packager hardening to the diagnostic namespace. Do not use
the normal packager patch directly: its production namespace must stay frozen.
Install the exact
locked dependencies without lifecycle scripts; then run the template's
`buildPlugin.sh`. Verify with
`scripts/verify_annotation_preview_probe.py <snplg> <repo> <bundle> <apk>`.
Never apply these transforms to Claude's checkout or the retained T004 build.

Focused host gate: `node scripts/test_annotation_preview.js`.
This probe is not a production annotation overlay, a native-save endpoint,
or a release candidate for personal documents.
