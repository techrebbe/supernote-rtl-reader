# SAFETY — hardware and workspace rules (all agents)

## Hardware-first validation

Once a change has passed basic host validation and at least one independent
review sufficient to remove obvious software hazards, prefer the smallest
decisive test on the actual Supernote Nomad over additional speculative
emulation, synthetic testing, or theoretical analysis.

Additional offline testing should be required only when it is likely to reveal
a concrete safety or correctness problem before device use, not merely because
more testing is possible. Required release/merge checks still apply; an early
hardware gate is not a release approval or a substitute for those checks.

Hardware experiments must be:

- **bounded** — test one defined question at a time;
- **observable** — define the expected result and explicit PASS / FAIL criteria
  before execution; record UNKNOWN when evidence cannot establish either;
- **reversible or safely disposable** — use disposable documents/data whenever
  mutation is involved, and preserve a known-good rollback package/configuration;
- **hard-stop controlled** — define conditions that immediately terminate the
  experiment rather than allowing ad-hoc follow-on mutations;
- **non-destructive** — do not alter firmware, bootloader state, system partitions,
  or other difficult-to-recover device state without a separately approved task;
- **protective of user data** — never put irreplaceable PDFs, annotations, `.mark`
  files, or other user material at risk when equivalent testing can be performed
  on disposable copies.

Experimental failure such as an app crash, failed handoff, incorrect page
selection, restart failure, or loss of disposable test data is an acceptable
research result. Risk to the device itself or to irreplaceable user data is not.
Expected `.mark` changes, compaction, or file-size/hash changes alone do not prove
annotation loss or persistence: assess the saved annotation meaning and geometry.

The device-control requirements below remain in force: explicit task approval,
reservation through issue #23, exclusive device use, exact build/commit evidence,
and a recorded result before the next trial/experiment. Actions within a trial
must follow its predefined sequence. Stop when state or cleanup
is uncertain; do not reinterpret an uncertain result as permission to continue.

Do not allow emulator or host-test work to become an indefinite prerequisite for
hardware evidence. When the remaining uncertainty is fundamentally
device-dependent, move to a bounded real-device experiment once its safety gate
is satisfied. If that gate is blocked by approval, reservation, or physical
availability, report the exact blocker rather than inventing another offline
prerequisite.

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
