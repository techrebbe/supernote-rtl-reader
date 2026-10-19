# T020 — chosen-book favourites/direct-open fallback

## Current approved hardware checkpoint

Reviewed25 authored files106ec80+fc64026 are published and public branch HEAD
fc640261e9f69dfefbf9c4a3dd81aa5379080bb8 verified. Exact72 installation and one
two-disposable favourites check are approved. First NEW6269131197 preflight
stopped at focused DayWeave before capture/input/stage/install or file/payload
integrity checks; RELEASE6269173663. Code72 remains UNINSTALLED. Wait for user's
Document-library readiness, then NEW reservation; no repeated unchanged tests.

Prepared bookA is the existing four-page synthetic interactive fixture. BookB
will be a fresh named copy of the existing clean two-page display fixture,
SHA25628b126627dd5966e8975ae1bf48385d65e1f8189e8aa32ddc0eab778904859c9.
Host page count/text/no-annotations and rendered PAGE1 checked; no PDF or device
write yet. Do not reuse older ink-bearing test copies or personal originals.
SaveA -> normal Close -> normal openB -> launch chooser -> selectA ONCE ->
require actual exact-book visible READY, not show acknowledgement. On success,
normal Close and chooser-only Close must preserve the native page; then restore
starting library/settings, integrity, owned scratch/stage cleanup and release.
No separate pen/Edit/zoom experiment is implied by this favourites-only scope.

## Decision and boundary (2026-10-19)

User requested that chosen documents keep using RTL Reader. The pinned supported
SDK0.1.65 has `PluginFileAPI.openFile(path,page)` and `showPluginView`, but no
established document-open subscription for Supernote's file list. Its Java
`setFullAuto` implementation is an empty TODO. Do not install a guessed hook,
background poller, root dependency, or bounce stock Edit back to RTL.

User explicitly selected **favourites/direct-open fallback**. Implemented source
is based on2d815e7e7a2531b427e702c5d3056730260fa6c7. Initial independent source
review and exact identity/pin follow-up are CLEAN; see the review note in
coord/reviews. Candidate0.4.25-library-exp1/code72 is UNBUILT/UNINSTALLED at this
initial checkpoint, not published. Last-verified installed71 and rollback70 retained.

### Completed local candidate build

Exact source106ec80e566adce8555ab69fd94e6745c7708116, normal clean archive attempt2
exit0/75tasks/SDK0.1.65 and JS58. Full package/source/DEX/ELF/engine/notices/bundle
verification PASS, including new library class/store/UI. Actual-APK provider11
PASS/no skips. Package com.supernotertlreader, pluginID snrtl20260726001; outer72,
Android native manifest1.0/code1 is deliberate/unchanged. v2/v3 signer SHA256:
fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c, matching retained71.

- SNPLG:3327f873c7436a7e183a9648395fa4352aebcae236b2cf6115b07498e119d29d
- APK:656f4c1653b3b0c771671cf2227403aff72168b4ba33250c5436f8af5ab51693
- Bundle:9d8913bf3bc8937f3862cc370aced9fca3b34b2c315f2810e276624a103614c4
- Source archive:5064a12b2b27f417d3a303c5fd48ae8ec1c090a5ad992734bd9d41e1e9892011

First attempt failed in stock SDK CMake/Ninja (long object paths, dirty manifest
after100 regenerations). Retained evidence; same source succeeded using a shorter
temporary root. No production fix, dependency update or weakened gate was used.
Candidate/identity receipt local under tmp/t020-library-106ec80-build2. Not uploaded
or installed; no device accessed. Local build failure is not a device failure.

## User flow

1. Open a PDF normally and launch RTL Reader using its existing button.
2. `Save to favourites` stores the current authenticated PDF identity, not a page
   or Edit-return record. Explicit removal deletes only this private metadata.
3. On a later RTL Reader launch, a nonempty favourites list offers saved books,
   `Read current PDF`, and `Close to native reader`. With no favourites, the
   existing immediate current-document launch is preserved.
4. Selecting a favourite makes ONE supported SDK `openFile(path,-1)` request;
   native last-viewed position and the existing source-bound preference/Edit
   loader remain the page authority. After bounded document/count confirmation,
   source recheck and supported showPluginView, the ordinary App is mounted.
5. Edit and normal Close keep using the existing shared handoff. Closing only
   the chooser explicitly skips page handoff, so it cannot reposition a book.

This is NOT a new home-screen shortcut or a modification of Supernote's file
list. The existing toolbar entry still needs a native DOC context. No favourite
automatically intercepts native reading or native editing.

## Ownership and rejection contract

- `ReaderLibraryModule` has a separate app-private preferences namespace. Never
  use ReaderPreferencesModule.save for the index: it would overwrite that
  module's lastSavedFilePath/prepared handoff authority.
- Schema1, at most50 unique absolute PDF paths, bounded path/JSON/page count and
  SHA256 identities. Corrupt/unsupported storage is not reset or overwritten.
- Hash through the existing bounded/stable O_RDONLY source reader on the common
  FIFO, before and after SDK open. No PDFium/writer session is created by this
  fingerprint operation. A missing, unreadable, removed or replaced favourite
  fails closed; user can explicitly remove/re-save it from a current PDF.
- Wait for actual previous PDF queue, serialized preference save and ink-cleanup
  receipts before direct-open. Retained cleanup failure blocks; no fake success.
- A process-local synchronous open lease excludes overlapping opens, toolbar
  activation and plugin Close until settlement. Cancellation/unmount suppresses
  all later actions. No repeated SDK open or guessed rollback on failure.
- Context path/count and the actual staged PDFium owner path/count/SHA must
  match the selected record before preferences/render readiness. Owner mismatch
  drains that exact owner without source writes and exposes an error.
- No change to rendering/portrait/spread geometry, logical navigation/Bluetooth,
  annotation storage, existing Edit/Return precedence, or native writer behavior.

## Offline evidence and remaining gates

Focused new JS/controller/actual-JSX26 pass; combined reader/permission/handoff/
Bluetooth/Edit JS198 pass (no skips). Native library109 actual-method assertions pass with controlled
JSON/preferences/React peers. Focused real Android35/RN0.79.2 compilation passes
(one missing Kotlin annotation metadata warning). Integration9 including the
actual generated-index exclusion guards and assembly/source inventory pass.
Actual streamed source tests2 pass (73 Session and87 JNI assertions; three
compiled input mutants rejected), including non-mutating library fingerprint.
Pinned SDK0.1.65 actual JS forwarding/validators for openFile(-1/3) and show pass.
Native/render, v2 and Edit/Return invariants pass. Core85407, all271 mutations,
package fail-closed and saved-ink wiring6 pass. git diff --check is clean.

Cross-layer source gate initially stopped at the changed frozen workflow. After
independent review, the exact scoped workflow/build/runtime-marker digests and
matching72 identity expectations were verified by reverse reconstruction, then
all native/v2/cross-layer/Edit/wiring checks passed. No frozen preference/native
writer source or signing/SDK/permission pin changed.27-input source aggregate is
9840778312d78d31bcf212fde9f33804cc00561b7a7de0b807b5abd8841e63e9.

Normal exact clean-source compatible-signed package is now verified above.
Publication/install require their own scope approval; no upload or hardware action
has happened for T020. No additional speculative emulator prerequisite is needed.

## Earliest safe hardware gate

After focused gates, independent review, exact new package/signature and explicit
approval: one fresh exclusive issue23 reservation using two clean disposable
synthetic PDFs with different counts. Save favourite A, normal Close, normally
open B, launch RTL, choose A. PASS only if exact A/page/source and original
layout/settings are verified, one SDK open is observed, normal Edit/Close still
works, then restore starting scene, integrity, owned scratch cleanup and release.
Check chooser Close does not move native pages. No physical pen needed.

The host SDK may hide the plugin while opening another PDF; retention/re-show,
supported last-viewed-page timing, Android storage permission and process-death
behavior remain device-dependent. A failed/ambiguous open stops the trial; no
ad-hoc native restart, second open or original-document test. No need for broad
emulator modeling before this decisive gate. Saved ink stays PARKED; pinch budget
failure remains OPEN, independent of this feature. Timer PAUSED; no merge.
