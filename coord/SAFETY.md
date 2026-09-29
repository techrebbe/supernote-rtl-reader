# SAFETY — hardware and workspace rules (all agents)

## Device (Supernote Nomad, ADB)
- No device-mutating operation without explicit user approval for that task: no install/uninstall, file writes, settings changes, pen/touch/key injection, page turns, `.mark`/document changes, reboot.
- Read-only observations are allowed only if this file or the task names them AND the user approved them.
- Reserve the device through GitHub issue #23 before any authorized session; release it in the same issue when done. Do not invent another reservation mechanism.
- Hardware tests use disposable PDFs only, never the user's real documents. A hardware pass needs device build/version and observed result recorded; never claim one from source or CI.
- Hard stop: if a probe line is recorded NO-GO, do not open another speculative device capture without new evidence and user approval.

## Workspace
- Another agent's worktree/branch is read-only: no edits, commits, checkout, reset, rebase, merge, stash, clean, formatters, or Git-metadata changes there.
- Read others' worktrees with `--no-optional-locks`. Never run `git worktree prune`/`gc` from a shell that sees different paths than Windows Git.
- Never delete or modify user documents found in a workspace (e.g. stray PDFs); report them.
- Kill/restart of the stock reader exists only in `ReaderPreferencesModule` (3 sites, enforced by `scripts/check_edit_return_invariants.py`). Do not add another.
