# coord/ — shared state for Claude and Codex

Read order for a bounded task: `STATE.md` (canonical, <80 lines) -> the task file in `tasks/` -> only the evidence it links. Do not reread history.
Write rules: one owner per task and per branch; update `STATE.md` in the same commit as the work; never edit another agent's branch or worktree.
Files: `SAFETY.md` hardware rules · `tasks/T-NNN.md` brief + spec (owner, branch, allowed paths, forbidden, done criteria) · `handoffs/T-NNN-handoff.md` (<60 lines: done, evidence, failed, uncertain, next) · `reviews/T-NNN-<agent>.md` (verdict CLEAN/FINDINGS, file:line, commit reviewed).
Link to evidence (commit, file, test name); never paste logs. Commits carry an `Agent: claude|codex` trailer.
