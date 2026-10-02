# Disposable native handwriting PNG probe

This diagnostic is separate from the installed RTL Reader. It cannot edit,
close/reload/kill the Document process, or write a PDF/`.mark`. Its only SDK
render operation is the pinned `PluginFileAPI.generateMarkThumbnails` call;
v0.0.2 additionally observes `PluginFileAPI.getPageSize` before/after that call.
JNI output/side effects remain a hardware question, not a source-only guarantee.

The native bridge retains the original zero-based PAGE 3 allowlist of
`/storage/emulated/0/Document/RTL_RAPID_TOOLS_T004_20261001.pdf`, whose exact source
SHA-256 is `ffb6c3b889ed455841d3c4f50a0813d844109c3c97255b4bbb5e4b949c9592c9`.
It also accepts only PAGE1 of exact
`/storage/emulated/0/Document/RTL_INK_GEOMETRY_T008_20261002.pdf`, SHA-256
`bd0fd00b4879cedb1b768a19deb2901a6d50dc7373decc8ef60e445613d83e64`.
It requests 1404×1872 and retains one unique private PNG until explicit cleanup.
Original PDF/annotation byte and inode snapshots must match before and after.
These checks are change detection, not save durability or an atomic native revision.

The JS orchestrator defaults disabled. This dedicated diagnostic UI explicitly
enables one manual attempt for T008 PAGE1 in landscape; normal reader startup
never invokes it. Default T004 pure-controller behavior remains tested unchanged.
Wrong context/orientation fails before output generation. A window change
cancels publication (including away/back ABA); actual SDK settlement is awaited.
The output is always requested at1404x1872. Actual native nominal page size is
recorded as immutable evidence, never used to resize/crop/rotate the thumbnail
or claimed as canonical annotation-coordinate authority. Pre/post nominal sizes
must agree; other than the two known Nomad size pairs, sizes are rejected.
The plug-in ID, component key, and Android namespace differ from RTL Reader.
No existing source pins or installed package identity are changed.

## Earliest hardware gate

After basic host checks, package verification and independent review, obtain
fresh user approval and issue #23 reservation. Use the existing disposable
T008 PAGE1's existing finalized BoxA line, without new pen actions. One
thumbnail call only in settled landscape; do not turn pages, rotate, switch documents or draw while
it runs. Inspect dimensions, transparency/background, and alignment against the
retained portrait native/SDK reference. Determine highlight coverage separately,
without promising it. This T011 gate does not enable production landscape ink.

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

Focused host gates: `node --test scripts/test_annotation_preview.js
scripts/test_annotation_preview_landscape.js scripts/test_annotation_preview_app.js`.
The actual-App suite resolves the pinned Babel modules normally or through
`BABEL_MODULE_ROOT` pointing at the prepared template's existing node_modules.
This probe is not a production annotation overlay, a native-save endpoint,
or a release candidate for personal documents.
