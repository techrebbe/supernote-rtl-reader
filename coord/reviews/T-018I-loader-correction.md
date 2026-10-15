# T018I loader correction — independent source-only review

2026-10-15, user explicitly authorized a separate narrow reviewer. Reviewed the
12-file uncommitted correction against94534ef13329d47e607232ac780ff0a90d06d27a.
Reviewer read/ran offline checks only: no source/Git metadata/device/publication
or installation changes. Outcome: no P0/P1/P2 findings within this scope.

The exact prior code60 device failure is preserved in REGRESSION.md. This review
does not prove the precise PluginHost symbol-scope cause or a corrected hardware
load. Native engine/provider authentication remains unchanged; no renderer,
navigation/Edit/writer/ink behavioral source changes are part of this fix.

Independent findings/checks:

- Production builder links the pinned static C++/ABI/unwind/compiler archives
  before PDFium and hides their exports; independent fresh ARM64 compile PASS.
  __emutls_get_address, __cxa_throw and _Unwind_Resume are LOCAL, not runtime
  imports/exports; exactly nine JNI entry points exported.
- Packaged-byte verifier enforces the same ELF boundary. Actual receipt-consistent
  substitutions of code60 AND the incomplete runtime-only correction rejected.
  Corrected payload accepted. These additional two negatives were not skipped.
-8 ELF tests PASS, real failed/corrected binaries/no skips;5 real payload PASS;
  3 generated integration PASS including Java14 and actual generated callbacks;
  13 lifecycle JavaScript PASS. Native renderer/v2 invariants PASS.
- Consistent proposed identity0.4.25-pdfium-exp2/code61.
- Cross-layer current failure was the intentionally unchanged pin. Substituting
  ONLY the two below independently reviewed values in memory made it PASS.

Scoped pins approved by reviewer and independently matched by owner:

- overlay/index.js changes ONLY runtime marker exp1 to exp2. Normalized SHA256
  76f1365dcc7bf2331c1653c5ef3efe9e62f01542a03d3fba787147dcc1030940.
- .github/workflows/build.yml changes ONLY adding test_pdfium_elf.py and exp2
  artifact name. Normalized SHA256
  2c6df6c2b6ed6555d8d6ed8d0370fbf4eb62ce7d6ed2aed5ed9355b54e93854e.
- No other frozen source pin changes approved or made.

Owner additionally ran19 focused JS PASS, Java Core85407 assertions PASS on
explicit JDK17, Edit/Return and package fail-closed gates PASS. An initial host
test invocation accidentally resolved Oracle javapath and hung; it was cancelled,
not reported as PASS. Explicit pinned-JDK rerun passed; not a production defect.

Conclusion: eligible for the reviewed two pin updates and one exact clean signed
full package build. Full APK/SNPLG verification and later fresh exact-package
hardware approval/reservation remain gates. No Nomad connection needed for this
offline phase, no hardware/release PASS, public push, PR finalization or merge.
