# STATE — RTL Reader (updated 2026-09-30 by codex)

## Goal
RTL two-page spread reading of PDFs (Hebrew books) on Supernote Nomad with Supernote's native annotation kept intact. Original PDFs/.mark are never rewritten by RTL Reader.

## Decisions (user, 2026-09-29)
- Native-writer viewport line (stock writer inside a custom split viewport) = bounded **NO-GO**; reopen only on genuinely new evidence.
- Direction = **Option B**: RTL spread for reading; explicit "Edit this page" hands off to the stock reader; user later returns to RTL.
- Repo is the shared channel. Share broadly, write narrowly; occasional blinded reviews are intentional.
- Hardware-first: after basic host safety validation and independent review, use the earliest decisive bounded Nomad gate; do not add speculative offline prerequisites. See `SAFETY.md`.

## Canonical refs
- `main` = `69e2aa2` (PR #22, Native Reader v2; remote-confirmed 2026-09-29). v2 README says "not shippable yet"; `README.md` top sections are stale/contradictory — trust this file first.
- NO-GO record: `agent/native-writer-witness` @ `d8f6120` -> `native-viewport-probe/NATIVE_VIEWPORT_FINAL_VIABILITY.md`.

## Branches (owner)
- Codex, read-only for Claude: `agent/native-writer-witness` d8f6120 (NO-GO tip), `agent/native-paint-order-readonly` ea392b0 (hierarchy v2 read-only Nomad evidence, not in tip), `agent/saved-ink-probe-gate-fix` 7c3331c, `agent/target-owned-helper-app` 845434f, `agent/native-viewport-alpha`/`paint-order-observer` e3162ad.
- Claude: `claude/edit-return-groundwork` (base 69e2aa2) — task T-001.
- Codex: `agent/edit-return-correction` — reviewed/built software candidate `66ac1d56546db1102d3a50ae0c021d57653d6c35`; subsequent documentation commits do not replace that binary identity.

## Tasks
| id | owner | branch | status |
|----|-------|--------|--------|
| T-001 Edit/Return groundwork | claude | claude/edit-return-groundwork | Historical input at `904ee54`; branch untouched. Its exp1 candidate/build claims, E5-E7 fallback table and hardware execution order are superseded by T-002; preserve its E3 stock-ink safety questions. |
| T-002 Edit/Return correction and first gate | codex | agent/edit-return-correction | Findings 1-6 CLOSED; independent exact-head review and offline/build gates PASS. Candidate `0.4.24-edit-exp2`, code 44. `tasks/T-002.md` is the current hardware plan; not approved or run. |

## Known unknowns (do not claim otherwise)
- Whether annotations made in the stock reader show in the RTL spread. Source inspection says the RTL renderer (Android PdfRenderer path) never reads `.mark`; expected NOT shown. Hardware test E1 in `tasks/T-001.md`.
- Whether SIGKILL of `com.supernote.document` (existing Close handoff, reused by Edit) can lose unsaved stock ink. Hardware test E3.
- Immediate handoff success acknowledges config/restart scheduling, not the target activity's completed load. T-002 tests that gap on disposable data.

## Device
Nomad access: user approval per task + reservation via GitHub issue #23. No device work is authorized right now.

## Next permitted
Approve/reserve the T-002 disposable gate, then install the already-built exp2 `.snplg` and test on the Nomad. No new build/emulator cycle is required for this documentation-only policy update. Exact hashes, signer and review/test evidence: `handoffs/T-002-handoff.md`. Nothing merges to `main` without user approval.

## Needs user approval
T-002 installation/document/configuration/input/restart actions plus issue #23 reservation; merging and releases. Reviewed source pins are recorded at candidate `66ac1d5`; no new pin change is proposed here.
