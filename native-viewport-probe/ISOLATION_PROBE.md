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

1. Verify the parent and fresh directory, then arm parent-death SIGKILL.
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
- Existing unprivileged WSL Linux/x86-64 host: **101 kernel-filter runs / 1,414
  checks PASS, no descriptor leaks**, including an intentionally stalled child
  after a complete report. The parent retains a bounded exit deadline; reporting
  success cannot leave it waiting indefinitely. This translates only architecture/syscall
  numbers in the same BPF program; no root, namespace/mount test, firmware,
  networking or tablet operation. Positive I/O uses `/dev/null` and owned pipes.
  It is specifically NOT a Nomad seccomp or namespace hardware pass.

Latest Android diagnostic build:
`build/isolation-15a4b0ff6c874a8c8d9c99b945f699f5/isolation_probe`
SHA-256 `01aa3493218f3ab8be23e1d5c7c923b64b59635b46b5ddaf23845f649031a28a`.
It has not been transferred to or run on the Nomad.

## Review blocker / safe next action

The independent Codex CLI review attempt for the architecture notes was rejected
before execution because sending those notes to an external review service needs
more specific user approval. The CLI provider was subsequently verified as OpenAI
from the existing configuration/review log. A smaller fresh review containing
ONLY seven generic authored diagnostic source/build files, excluding all internal
architecture notes, was also rejected before execution for lack of specific
payload-disclosure approval. Neither review ran. Do NOT retry or route around
these rejections; request explicit approval when the user returns.

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
