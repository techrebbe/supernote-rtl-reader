# STATE — RTL Reader (updated 2026-09-30 by claude)

## Goal
RTL two-page spread reading of PDFs (Hebrew books) on Supernote Nomad with Supernote's native annotation kept intact. Original PDFs/.mark are never rewritten by RTL Reader.

## Decisions (user, 2026-09-29)
- Native-writer viewport line (stock writer inside a custom split viewport) = bounded **NO-GO**; reopen only on genuinely new evidence.
- Direction = **Option B**: RTL spread for reading; explicit "Edit this page" hands off to the stock reader; user later returns to RTL.
- Repo is the shared channel. Share broadly, write narrowly; occasional blinded reviews are intentional.

## Canonical refs
- `main` = `69e2aa2` (PR #22, Native Reader v2; remote-confirmed 2026-09-29). v2 README says "not shippable yet"; `README.md` top sections are stale/contradictory — trust this file first.
- NO-GO record: `agent/native-writer-witness` @ `d8f6120` -> `native-viewport-probe/NATIVE_VIEWPORT_FINAL_VIABILITY.md`.

## Branches (owner)
- Codex, read-only for Claude: `agent/native-writer-witness` d8f6120 (NO-GO tip), `agent/native-paint-order-readonly` ea392b0 (hierarchy v2 read-only Nomad evidence, not in tip), `agent/saved-ink-probe-gate-fix` 7c3331c, `agent/target-owned-helper-app` 845434f, `agent/native-viewport-alpha`/`paint-order-observer` e3162ad.
- Claude: `claude/edit-return-groundwork` (base 69e2aa2) — task T-001.

## Tasks
| id | owner | branch | status |
|----|-------|--------|--------|
| T-001 Edit/Return groundwork | claude | claude/edit-return-groundwork | Codex findings 1-6 + identity addressed (`reviews/T-001-codex.md`); host-verified; candidate `0.4.24-edit-exp1`; awaiting build of exact APK + user approval of `tasks/T-001-hardware-plan.md` |

## Known unknowns (do not claim otherwise)
- Whether annotations made in the stock reader show in the RTL spread. Source inspection says the RTL renderer (Android PdfRenderer path) never reads `.mark`; expected NOT shown. Hardware test E1 in `tasks/T-001.md`.
- Whether SIGKILL of `com.supernote.document` (existing Close handoff, reused by Edit) can lose unsaved stock ink. Hardware test E3.

## Device
Nomad access: user approval per task + reservation via GitHub issue #23. No device work is authorized right now.

## Next permitted
Build the exact-head APK (CI or Codex; this host cannot run gradle) and record commit + SHA-256; Codex re-check of the correction commit. Nomad steps only after user approval of `tasks/T-001-hardware-plan.md`. Nothing merges to `main` without user approval.

## Needs user approval
Any Nomad action; merging; the frozen-digest updates in `check_native_spread_invariants.py` (App.js, build.yml, build.sh pins; new editReturn.js pin); releases.
