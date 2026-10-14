# T018 isolated proof review — 2026-10-14

Owner codex, agent/page-turner-bridge. Reviewed uncommitted authored slice based
on4078893919c324f31b36ebaa0dedc8cefb24a0a6, not a production package/PR review.
Two separate local read-only Codex sessions; raw reports remain local at root
tmp/t018-source-review1.md and review2.md. No PDF/vendor/annotation/browser-
capture/credential upload or device access. First review mistakenly read beyond
the leading STATE checkpoint; extra history excluded from its conclusions.
Confirmation's first test indirectly read the canonical App/key source; noted.

First verdict FINDINGS: two P2 issues. Actual failed-surface handlers enabled
zoom without a settled active viewport, then threw. Fixture generator could
overwrite an existing JSON/symlink despite a fresh PDF. Corrected as one source
batch with active-surface/callback guards+Fit recovery and fresh-both-leaves+
exclusive manifest creation. Owner also corrected the actual PDF.js6 API cleanup
failure with idempotent loadingTask-owned worker/transport destruction.

Confirmation CLEAN/no new critical-high issue in the requested slice:
failed-surface zoom CLOSED; loading-task shutdown CLOSED; fixture source fixed,
but independent filesystem execution PARTIAL/NOTRUN due read-only temp setup.
Reviewer11Node and six no-write metadata/AST authority checks PASS. Owner88Node
(11prototype+existing navigation/transport/Edit-return), five Python tests (three
actual temporary-file refusal/race, two mocked symlink metadata), syntax and four
unchanged native/Edit/v2/cross-layer invariants PASS. The two mocked Python tests
and evidence notes were added after runtime-source confirmation; no runtime edit
followed it. Initial environment/CLI failures retained, no production bypass.

Working-byte SHA256 of the confirmed runtime sources, before commit:

| Source under probes/interactive-pdf | SHA256 |
|---|---|
| viewer.mjs | f0c37aef43a5c8e00811baced10faa9e56788867785beb625aeb861f6e7fc6e0 |
| destinations.mjs | 19b8aaeab8f716630f6c9a6f0a61ae32bc8f65162d155189bdd7af7b272d8472 |
| canonical-core.mjs | 517d9564312ff32d5f99eff073d28763900115287c84bc48d1ebaa398842840f |
| server.mjs | cb5614dc689644392c7d5b76c4bb8f8f2f7276bea2201c4d9af05144af709892 |
| make_fixture.py | 98fc0aedf87158fabb3dea274aa3ca31ba2331e5592b52270723acaadc5261e3 |

Owner browser evidence, not independently replayed: Chrome155/PDF.js6.4.299
direct/named/same-page destinations, nested Unicode outlines, English pointer
selection, zoomed hit, shared crop/rotation, canonical RTL halves/active-page
portrait return, external denial/script disable, local key simulation and
loading-task cleanup. Four-page Poppler fixture inspected; hash unchanged/no
.mark. Logical Hebrew copy order UNKNOWN. All own browser/server sessions closed.

Preserve this unshipped proof. No production App/native/installer/SDK/pins changed,
no build/install/hardware/Bluetooth/ink/release claim. The next decisive gate is
separately approved/reserved read-only Nomad WebView metadata; version-level
support alone will not establish functional compatibility. See T-018C and the
prototype README. Saved ink remains parked; timers paused; no merge/finalization.
