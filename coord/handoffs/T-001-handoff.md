# T-001 handoff — claude -> codex (independent review requested)

Base `69e2aa2` · branch `claude/edit-return-groundwork` · code commits `0e616c9` (characterization tests only, no prod change) then `abd9ada` (feature). Spec + evidence: `coord/tasks/T-001.md`.

## Done
- Pinned existing Close/reopen page selection with 11 host tests before changing anything; refactor is differential-tested (320-case grid vs frozen legacy rule).
- New pure module `overlay/editReturn.js`; `App.js` uses it; per-page "Edit p.N" header buttons; Edit = save `lastPageIndex=N` + `editReturn` record, then ordinary Close (existing handoff). No Kotlin change.
- `scripts/check_edit_return_invariants.py`; CI runs it + `node scripts/test_edit_return.js`; `build.sh` copies `editReturn.js`.

## Verified (host only, this machine, Node 22.23, Python 3.10)
27/27 `node scripts/test_edit_return.js`; 6/6 deliberate mutations of the logic caught; PASS: `check_native_invariants`, `check_native_reader_v2_invariants`, `check_native_spread_invariants`, `test_plugin_packaging_fail_closed`, `test_build_provenance`, `check_edit_return_invariants`. `patch_direct_view.py` and `patch_initial_layout.py` apply cleanly to the modified `App.js` (scratch copy). `@babel/parser` parses `App.js`, `index.js`, `editReturn.js`.

## NOT verified
- `test_native_reader_v2_core.py`, `test_native_reader_v2_mutations.py`: need a JDK (`javac`); this machine has only a JRE and the JDK download was blocked. Mutation suite mutates `overlay/App.js` text once (`restored.direction` block, untouched by me).
- No Metro/RN bundle, no `.snplg` build, no CI run, no device run. JSX parses but is not rendered: header layout with two Edit buttons is unseen.
- Kotlin unchanged (nothing to compile).

## Please review closely
1. **Frozen-digest pins** updated for `overlay/App.js`, `.github/workflows/build.yml`, `build.sh` in `check_native_spread_invariants.py`. Each old pin matched base, so only my edits moved them. This is the "explicit review" the gate asks for — I did not self-approve it.
2. `editPage` ordering/failure handling (`App.js`): gate -> payload -> `savePreferences('edit')` -> `closePluginView`; ref/state consistency so the unmount save cannot overwrite `lastPageIndex`/`editReturn`.
3. "Native page always wins after a valid Edit record" (incl. E4 handoff-did-not-happen). Disagree? Say what evidence.
4. Whether shipping Edit before E3 (SIGKILL/unsaved ink) is acceptable; my position: not for real documents.
5. `build.sh` now copies a third overlay file; packaging verifier accepted it in its own tests but the real bundle was not built.

## Uncertain / risks
- Prediction (not evidence): RTL renderer never draws `.mark` ink, so stock annotations will not appear in the spread (E1). If confirmed, Option B needs an ink display path — a much larger task.
- Same-path/same-page-count document replacement undetectable in JS.
- Kill safety unknown (U1–U4 in T-001.md).

## Blind-review option
For an unanchored review give Codex only: base+commit `abd9ada`, the T-001 brief up to "Done when", and this file's "Verified"/"NOT verified" sections; withhold the analysis sections until it reports.

## Next permitted
Codex review -> `reviews/T-001-codex.md`; Claude responds first to findings; unresolved disagreements go to the user. No merge, no Nomad access.
