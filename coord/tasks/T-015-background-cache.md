# T015 — return dropped PDF backgrounds to the existing cache

Status2026-10-06: source correction independently reviewed CLEAN, focused tests
PASS. Full native mutation run is in progress; no build/install/hardware pass yet.
Parent cbb63b7; isolated from the parked T014 injected-key delivery question.
Candidate0.4.24-cache-exp1/code54, unchanged key routing and native annotations.

## Concrete defect and ownership correction

T013C needs fresh generation-keyed native page views for exact draw completion.
Permanent RN drop calls PdfPageView.dispose, which previously recycled its pure
PDF background. Consequently reverse navigation can rasterize the page again
instead of using the existing four-entry LRU. The actual generated detach patch
already preserves transient detach; do not change that lifecycle boundary.

Change only permanent dispose's replaceBitmap(null,null,cachePrevious=false) to
the existing default cache-return path. Keep generation increment, pending-event
retirement and ink-lease release. replaceBitmap clears view ownership BEFORE
returnVisibleBitmap publishes the previous bitmap under its ORIGINAL RenderKey.
Do not reconstruct keys from current file props, cache ink/composited pages, add
another save/writer authority, change invalid-prop recycling, or enlarge the LRU.

Cache take removes the entry. A returned distinct bitmap with an identical key
can recycle only the cache-owned predecessor, not an image taken/displayed by
another view. Late old-document returns remain under old source/path/page/width/
profile keys and cannot satisfy a different key. Existing descriptor/path profile
verification and source identity are unchanged. End-of-reader drop may retain
up to four pure backgrounds; this is NOT full PDF memory cleanup/leak proof.

## Focused software gate

New test_pdf_bitmap_ownership.py extracts actual Kotlin key/metadata/cache/
dispose/replacement methods verbatim, compiles them with cached Kotlin2.0.21 and
JDK17 and strict Bitmap/ink-lease doubles. Original production compiles but fails
"Drop must return the pure background, not recycle it"; correction passes43
checks. Five compiled mutants reject old-drop recycling, take retaining cache
ownership, wrong-width return, omitted ink release and omitted view retirement.
Tests cover repeated drop, overlapping same-key views, identity differences,
metadata copying, orphan/invalid/recycled images and four-entry eviction. These
are method/ownership doubles, NOT Android/RN/renderer/writer/hardware tests.

The real patch_transient_detach.py executes on a temporary generated template;
transient detach does not dispose, permanent-drop methods remain exact. Existing
CI test_saved_ink_renderer.py gains two focused structural regression tests;
no new compiler-download prerequisite is added to CI. The cached-Kotlin runtime
test is a mandatory local gate for this change, not silently skipped if absent.

Root-executed current results:43 actual Kotlin checks/five compiled mutants,
10 renderer structural tests,172 JS tests plus62 lifecycle checks, native/v2/
Edit/cross-layer invariants, wiring/fit/provenance/package-fail-closed checks and
native85407 core assertions PASS. Independent narrow read-only review CLEAN
against cbb63b7, including untracked source/test/plan. Reviewer independently
confirmed actual same-key ownership and exact version-only frozen pins; reviewer
did not execute tests/build/device. Report retained tmp/t015-cache-review1.md.
Initial harness-framing syntax error and host runner's ordinary unittest stderr
handling were corrected without production/test weakening; compiled original
then failed the specific drop assertion, corrected source passes. No hardware,
memory-leak or physical-turner conclusion follows from these checks.

Run existing native/Edit/v2/mutation/cross-layer/wiring/provenance/package gates,
independently review the source/ownership/test diff, and build an exact clean
signed candidate. Frozen index/workflow pins change ONLY version/artifact strings;
verify that scope independently, not a blind repin. Preserve code53/52/51 rollback.

## Earliest safe hardware gate — one reverse round trip

After the software/review/package/signature gate: fresh exclusive issue23
reservation, Nomad SN078C10015092 only, disposable T008 PDF only. Before touching
settings/pages/install establish source/mark/installed-payload hashes, native
PAGE1, saved line, prefs/plugins/cache, rotation1-2, battery>=20% or charging.
Stop if another workflow owns the device, it is disconnected, identity changes,
ink/cleanup is uncertain or preflight is not exact. No originals, BOOX or pen.

1. Normal install verified code54, retain code53 rollback and config backup.
2. Open RTL on exact T008PAGE1; normal Settings Single/keysOff, Done. Wait for
   exact PAGE1/nativeREADY1; record original-key background and saved-ink geometry.
3. ONE ordinary logical Next to PAGE2, wait for exact READY2; then ONE ordinary
   Previous to PAGE1, wait for READY1. No swipes/injected keys/cover/rotation loop.
4. PASS requires the dropped PAGE1 background logged VISIBLE_CACHED and matching
   reverse RENDER cacheHit=true/renderMs=0 under original source/geometry/width,
   fresh display-generation readiness, unchanged saved line and source/mark.
   If reverse misses, FAIL (not retry); if evidence cannot establish it, UNKNOWN.
   Screenshots/time values are not a visible-flash/feel or general performance pass.
5. Restore keysOff/Auto, normal Close, verify stockPAGE1/saved line, exact source/
   mark/payload, other plugins/prefs/rotation, owned SDK cache drained. Remove
   only exact hash-backed owned scratch/staging files, retain local evidence,
   post result and release reservation. No extra follow-on mutations on failure.

Original PDF/.mark must not change. This is a no-pen background-reuse test, not
save/annotation generalization or a Bluetooth-delivery rescue. Human flash/feel,
physical paired turner and new pen gates wait awake. No merge/PR finalization.
