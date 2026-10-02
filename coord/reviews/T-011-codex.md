# T011 diagnostic — independent local review

Scope: local bounded diagnostic diff against be24db0, not the architecture or
the production reader. Authored native AnnotationPreviewModule, pure probe
orchestration, diagnostic App/config/marker/docs and focused landscape tests.

Independent reviewer t011_independent_review: CLEAN after one medium correction.
Completed previews previously survived unmount/remount while their window
listener was removed. App now invalidates image publication on unmount/window
change, retaining the exact cleanup handle. A separate presentationEpoch fences
the completed-controller-result / later-UI-delivery interval. One-attempt latch
survives remount; native ownership remains retained until actual settled cleanup.

Reviewer executed actual App lifecycle code for completed-preview invalidation,
late-delivery rotation/unmount, single attempt and explicit cleanup retry. Four
targeted lifecycle cases PASS; actual controller suites44/44 PASS; scoped
whitespace checks PASS. No remaining critical/high/medium findings reported.
Root existing diagnostic build tests11/11 and production native/v2/cross-layer/
Edit invariants, Java core85407assertions,271mutations and package failure-injection
gates PASS. Separate checked-in actual-App Babel/VM regression suite8/8 also
PASS (52combined JS tests); covers both late-delivery windows, unmount/rotation,
pending SDK no-early-discard, one attempt and matching cleanup ACK before Return.
No production source pin, writer/save/handoff or installed package
change. Actual saved-ink geometry remains a separately approved hardware gate.

Review involved no device access, branch edit, external source upload or merge.

Independent build-input consistency follow-up CLEAN: authored App/controller/
config/index/app.json match raw bytes; native files match template package
substitution and CRLF generation. Template SHA/SRI and decompressed lock match;
production pins/build defaults remain unchanged. Strict verifier subsequently
rejected the initial Windows-path-converted archive. Root corrected generated
config only and repackaged identical compiled APK/bundle; final strict archive/
DEX/signature verification PASS. T-011 task records the exact corrected package
hash, build-replay limitation and retained failure evidence. No claim that this
diagnostic build was from a clean Git archive or that geometry passed hardware.
