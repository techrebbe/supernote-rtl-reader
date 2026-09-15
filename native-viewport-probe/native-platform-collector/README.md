# Native page platform collector

This directory contains the fail-closed Android 11 platform-evidence collector
for the native single-page viewport experiment. It is a candidate component,
not a deployment authorization.

## Frozen execution boundary

The production process accepts only `--wire-v1` and UID 2000. Internally it can
execute exactly six compile-time command tuples: the two pinned `getprop`
lookups, the native-page-host package-path lookup, and the three pinned
`dumpsys` dialects. No caller string, environment value, path, or stdin byte can
select or alter a subprocess command.

Subprocess pipes are created with `O_CLOEXEC` only. The child therefore inherits
blocking stdout/stderr pipe writers. After `fork`, the parent closes its write
endpoints and applies `O_NONBLOCK` only to its distinct read endpoints, which it
drains concurrently in bounded chunks. Output cardinality, stderr, exit status,
and capture deadline all fail closed.

## Hard time bound

The ordinary capture state machine has a 20-second monotonic deadline. Before
capture begins, the process also arms a 22-second `CLOCK_MONOTONIC` POSIX timer
whose signal handler calls async-signal-safe `_exit(70)`. This outer watchdog
bounds operations that cannot otherwise be made reliably nonblocking on the
pinned platform: local APK/proc reads, regex normalization, child reap after
`SIGKILL`, and a blocked final wire consumer. `SIGALRM` is explicitly unblocked
before the timer is armed. A command that reaches the 20-second capture
deadline receives a distinct one-second cleanup grace. Cleanup polls
`waitpid(..., WNOHANG)` only within that grace. The collector returns from the
runner only after the exact child is proven reaped; otherwise it terminates
fail closed while the 22-second watchdog still bounds the whole process. No
unbounded blocking wait is used.

## Parsing and reconciliation

Activity and window records are scoped by scanning their entire candidate
blocks. If either protected package appears anywhere in a block, the header and
all identity, process, geometry, lifecycle, and cross-manager reconciliation
fields must parse exactly. Moving a protected package mention below an
unrelated/malformed header therefore rejects instead of hiding the record.

## Reproducible build and admission

`build-and-test.ps1` resolves one Python executable, records and rechecks its
SHA-256, and uses it for both Python gates. The two downstream parser sources
must each be ordinary, non-reparse files. Their exact bytes are hashed before
the test, copied to a controlled staging directory, imported only from those
staged bytes, and re-stated and re-hashed after the test. A domain-separated
canonical digest binds both named hashes in fixed order. The manifest and
admission evidence record the individual hashes and the combined digest. The
build also records the exact NDK revision, `source.properties`, clang
wrapper/executable hashes and version, and a path-independent digest of the
canonical compile command. It builds the API-30 AArch64 PIE twice and requires
byte equality.

The same build runs `command_runner_posix_test.cpp` under the named local WSL
distribution against the production runner translation unit. Link-time
`execve` wrapping verifies that the child actually receives blocking stdout and
stderr, drains a one-megabyte output without truncation or deadlock, records the
exact identity of a hung child and proves both that it was reaped and no longer
exists before the runner returns, and rejects a mutated command ID before fork.
Absence or failure of this POSIX test environment is fatal.

`collector-admission.txt` is a strict line grammar containing the expected
collector, proposed PrivateADB service, compile-command, both downstream parser
sources, and canonical downstream-contract hashes. Its current state is
`pending-independent-review`. Matching those values proves only that a
candidate was reproduced; it does **not** claim independent review or authorize
device installation. A reviewed change must explicitly advance the state after
the candidate, service wrapper, and downstream identities have passed
independent exact-head review.

## Hardware-only gates still open

- Confirm the Nomad firmware's exact ActivityManager, WindowManager, and
  DisplayManager dialects, including `mSurfaceFrame`, `mBufferSize`, and display
  inventory spellings.
- Confirm shell UID 2000 visibility of the two relevant `/proc` records and the
  installed package path.
- Confirm toybox `stat` output, SELinux execution of the fixed root-owned binary,
  and the before/after service-wrapper identity checks.
- Decide whether downstream evidence requires a versioned NPPCAP02 envelope
  carrying device monotonic timestamps. NPPCAP01 remains unchanged.

No device or package mutation is part of the host build.
