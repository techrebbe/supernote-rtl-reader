# Repository guidance

## Pull request quality gates

- Keep behavior-changing pull requests in draft until the complete branch diff is
  implemented and the relevant automated and hardware evidence is recorded.
- Before requesting GitHub review, run both invariant suites, the build affected
  by the change, and a local Codex `/review` of the full branch against `main`.
  Treat that independent review as additive to CI and hardware testing, not as
  a substitute for either.
- Address a review's findings as one batch when practical. Then rerun the
  relevant checks and review the full updated branch, including the fixes. Ask
  for one final `@codex review` while the pull request is still draft; mark it
  ready only when the final head has passing checks and no unresolved findings.
- Marking a draft ready triggers this repository's automatic Codex review. Do
  not merge until that ready-state review has also completed on the unchanged
  final head.
- Add a deterministic invariant or regression test for every accepted defect
  when practical. Keep mechanical checks in scripts or CI rather than encoding
  them only as prose review rules.
- Do not claim a Supernote hardware pass from source inspection or CI alone.
  Record the device build/version and the observed result in `REGRESSION.md`.

## Validation

Run the repository checks with an available Python 3 runtime:

```text
python scripts/check_native_invariants.py .
python scripts/check_native_spread_invariants.py .
```

For Native Spread changes, also build and verify the companion APK with
`native-spread-module/build.ps1`. For plug-in changes, run the normal plug-in
package build or rely on the equivalent GitHub Actions job when the local
Supernote toolchain is unavailable.

## Code Review Rules

### Persisted configuration is authoritative across layers

- Flag changes that let defaults, stale runtime state, or inferred orientation
  override an explicitly persisted per-document setting, including explicit
  `false`, `off`, Fit-page, cover-parity, divider, or header values. The plug-in,
  Native Spread module, marker/config files, compatibility handshake, and
  documented/package versions must agree on the same state and capability.
  Safe path: read and validate the persisted document-bound state first, preserve
  explicit negative values, and make every consuming layer use that validated
  value or fail closed.
