# Child-only isolation substrate — host tested, NOT device admitted

This prepares a bounded mechanism experiment for the offscreen native-engine
investigation. It contains no firmware loader, pen input/replay, Binder proxy,
Document launcher, production module change or two-page reader. A pass never
sets `native_start_allowed` to true. It is not yet a usable native worker.

## What the Android diagnostic would test after review

`native/isolation_probe.c --prove-isolation` would create one fresh, empty
`/data/local/tmp/native-viewport-isolation-XXXXXX` directory per case and fork
a disposable child. The parent never changes its mounts or credentials.

The child must perform these steps in order; any failure terminates it:

1. Require supervisor CAP_KILL and normalize its SIGCHLD disposition before
   forking. Verify the parent and fresh directory, then arm parent-death SIGKILL
   and an independent five-second child watchdog before privileged setup.
2. Unshare the mount namespace and prove its identity differs from the parent.
3. Make the child's mount tree recursively private BEFORE mounting anything.
4. Mount a one-megabyte private tmpfs, verify its identity, and create ordinary
   canary files at the private `/dev/ebc` and `/dev/input/event7` paths.
5. Close inherited descriptors except the owned report pipe; chroot AND change
   current directory. No procfs, actual devices, Binder or property sockets,
   system libraries, personal files or annotations exist in that root.
6. Drop supplementary groups, real/effective/saved IDs and capabilities. Re-arm
   parent-death SIGKILL after the credential change and recheck the parent.
7. Enable no-new-privileges and a minimal syscall filter; verify all boundaries.
8. Read/write only the ordinary private canaries. Device ioctls, sockets,
   namespace changes, process creation and other non-allowlisted calls fail.

The parent supervises timeouts, reaps its exact child, compares its original
namespace/device/directory metadata, and removes only that exact empty directory.
Every reap is bounded and checks waitable-child ownership before signaling.
If cleanup cannot be proved, the supervisor exits unsuccessfully and preserves
the exact directory for inspection; it never continues or signals a stale PID.
The child's independent SIGALRM deadline survives credential changes and cannot
be canceled by the installed filter. It is separate from parent-death SIGKILL.
No real input or EBC node is opened. Cases include normal completion, deliberate
child exit after mount/chroot/filter, and timeout after a positively reported
filter admission. Child namespace destruction removes private mounts. If the
parent itself dies, an empty owned outer directory may need later inspection;
the child must not survive it. There is no recursive deletion or global cleanup.

This deliberately restrictive filter cannot run the native engine: mmap,
threads and firmware loading are denied. Expanding it for a worker is a separate
design/review gate, not an implied permission from this diagnostic.

## Current host evidence

`build-isolation-probe.ps1` uses the existing Windows GCC for portable tests and
NDK 27.0.12077973 for AArch64/API30 compilation. On 2026-09-07:

- Shared sequencing core: **16 cases PASS**, including every step failure.
- The actual BPF instruction array under a closed host interpreter:
  **56,376 vectors / 50 decision mutations PASS**. Unknown architecture kills;
  unlisted syscalls are denied; prctl admits only three read-only queries.
- The Android wrapper compile-time checks ABI offsets, syscall numbers and
  filter encoding against installed Linux/Android headers. Compilation with
  warnings as errors and Clang static analysis both pass.
- Existing unprivileged WSL Linux/x86-64 host: **102 kernel-filter runs / 1,428
  checks PASS, no descriptor leaks**, including an intentionally stalled child
  after a complete report. The parent retains a bounded exit deadline; reporting
  success cannot leave it waiting indefinitely. The shared supervisor also passes
  an injected kill-EPERM case (child watchdog actually terminates it), inherited
  SIGCHLD-ignore normalization, and a reaped-child no-signal regression.
  This translates only architecture/syscall
  numbers in the same BPF program; no root, namespace/mount test, firmware,
  networking or tablet operation. Positive I/O uses `/dev/null` and owned pipes.
  It is specifically NOT a Nomad seccomp or namespace hardware pass.

Latest Android diagnostic build:
`build/isolation-1b9348304e074db298129cb2807e8185/isolation_probe`
SHA-256 `4775fe42b615970ece06ef49131d440a7fefc0043e432ef9411473438f67099c`.
It has not been transferred to or run on the Nomad.

## Review history / safe next action

The user explicitly approved sending the diagnostic sources and authored notes
to OpenAI's Codex review service, excluding PDFs, annotation data, firmware
binaries and credentials. This supersedes the disclosure blocker described below.
The fresh 35-file exact-source review of head `25aa958` completed NOT CLEAN:
failed child termination could lead to an unbounded wait, and inherited SIGCHLD
auto-reaping could leave stale numeric-PID signal authority.

Both findings are addressed by `isolation_supervisor.h`, shared with the Linux
kernel test. Android now requires CAP_KILL, normalizes SIGCHLD, arms a child
watchdog, uses bounded reaping and stops without signaling on ECHILD. Updated
tests and the Android build pass. A full updated source confirmation review
is required before staging or executing the diagnostic.

The review also keeps these limits explicit: this cooperative diagnostic assumes
trusted staging ancestors (verify on-device); the host test does not reproduce
Android UID/SELinux transitions or parent-death delivery; a private engine still
needs pre-initializer isolation, private IPC and canonical background/output
coupling. No hardware or native-start claim follows from the source review.

### Earlier rejected attempts (preserved history, not an active blocker)

The earlier independent Codex CLI review attempt for the architecture notes was rejected
before execution because sending those notes to an external review service needs
more specific user approval. The CLI provider was subsequently verified as OpenAI
from the existing configuration/review log. A smaller fresh review containing
ONLY seven generic authored diagnostic source/build files, excluding all internal
architecture notes, was also rejected before execution for lack of specific
payload-disclosure approval. Neither review ran. Do NOT retry or route around
these rejections without explicit approval. That approval has now been received.

The unreviewed local snapshots are
`inspection/native-reader/reviews/native-viewport-engine-boundary-20260907-r3`
and `inspection/native-reader/reviews/isolated-process-source-only-20260907`.
The latter is flattened (C files beside the build script) and includes the
seven diagnostic source/build files at that attempted review. The subsequent
host child-exit deadline fix has not been copied into that preserved snapshot.
A new complete exact-source review
is required after approval; the existing r2 clean review covers ONLY the older
buffer observer and instantaneous EVIOCGRAB mechanism.

Local tests and static investigation can continue. Do not stage/run the new root
diagnostic, load a private native engine, modify live native mappings, or enable
Document in the viewport host before the new exact-source review and device
ownership/identity/cleanup gates are satisfied.

Primary mechanism references: [mount namespace propagation](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html),
[chroot limitations](https://man7.org/linux/man-pages/man2/chroot.2.html), and
[kernel seccomp filter semantics](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html).
Neither chroot nor a syscall filter alone is treated as a complete sandbox.
