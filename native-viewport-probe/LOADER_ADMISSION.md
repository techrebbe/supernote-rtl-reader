# Native loader preparation — no engine admitted

2026-09-07, resumed from source `68b57c108d1dd67a0cb4dbe0380c374c1f18fee4`.
This is a read-only device / host-parser result. It is NOT a native viewport,
initializer or handwriting pass. No library was executed by these tools.

## Observed runtime, not APK guesses

Nomad `SN078C10015092`, firmware build 20260616, DrawPath PID 1425/starttime
2642 remained unchanged before/after both captures. Root system-library bytes
matched their remote hashes, and selected mapped device/inode/ranges matched
before/after. No debugger attachment, native invocation, process stop, raw input,
document launch, file mutation, package install or module enablement occurred.

Local-only evidence is `../../loader-inventory-20260907c/`. Do not commit or
upload its ELFs, memory-pointer data, or raw process maps to a review service.
The earlier partial `build/loader-inventory-20260907a` and `...b` captures are
preserved: parser access and Windows path-length failures, not completed gates.

- `inventory.json`: 202 candidate libraries / 76,823,616 bytes, 1,841 dependency
  edges. 595 edges have multiple mapped namespace candidates. Candidate closure
  is deliberately **not** loaded-binding or safe-initializer authority.
- `bindings.json`: 5,057 GLOB_DAT/JUMP_SLOT slots in five modules. Each bounded
  run was read twice and required identical bytes (43,312 bytes per capture).
  Before/after process and mapped-file checks passed. 4,825 target pointers are
  inside exactly one recognized file-backed library; 232 are unresolved by that
  classifier, mostly objects in anonymous BSS. No BSS contents were read.
- 4,339 slots have function symbol type. All except one resolve into recognized
  library mappings. OpenMP's `sigaction` points to the mapped executable
  `/system/bin/app_process64`, not the libc implementation. Raw map inspection
  confirms the address range; this is an executable-interposition observation,
  not permission to invoke it from another process.
- `runtime-images.json`: separately pinned mapped linker and app executable.
  The linker's real SONAME is `ld-android.so`; that explains the three edges
  called "missing" by the basename-only candidate tool. Do not edit the original
  inventory to pretend its heuristic established this runtime alias.

The root pen library's `defaultServiceManager` pointer resolves into
`/system/lib64/libbinder.so`, SHA-256
`758f29a75b164e4669b89d120a4a5ecedeee783c29a6b22ca3847b99360d6895`.
The APK's bundled Binder (SHA-256 beginning `92255144`) is not that runtime
authority. Binder in turn has nine inspected C++ function/vtable imports
interposed by `/system/lib64/libandroid_runtime.so`. OpenCV, libc++_shared and
the root engine also interpose some symbols across each other's mappings.

Pinned runtime linker SHA-256:
`b2c0fe187aa60162665f5b30768b78e4aa5e09e1d5c6d22ee549c97ffbe7800d`.
Pinned app_process64 SHA-256:
`c60a4f4a4eb176c7bdf0bbee18bbe6fd010025fdbbd320aebd4ab9396ab84c87`.
Neither executable was run by the capture.

## Parser checks

`inspect_loader_dependencies.py` is a bounded, read-only candidate collector.
`inspect_loader_bindings.py` reads only ELF-derived pointer intervals; it never
dereferences their target pointers. Unsupported formats fail explicitly.
Android APS2 RELA is decoded with bounds/overflow/group checks; RELATIVE data
and RELR blocks are not live-read as import pointers.

Host tests: 15 inventory cases and 17 binding/parser cases pass. The dedicated
inventory command requires `--python-path` and fails if the ELF parser is absent.
Generic unittest discovery explicitly skips three parser-dependent cases when
the optional dependency is absent; that is not the dedicated loader test gate.

An independent `llvm-readobj` comparison matched **48,764 relocation records**
across all five pinned libraries, including offsets, symbol/type info and
addends. This validates the host decoder against another implementation, not
the safety of loading those libraries. Result: `llvm-comparison.json`.

## Consequence for the initializer-only experiment

Do not fork the running app/DrawPath or reproduce its entire Java process to
inherit its interposition. That would carry live engine state and ownership
into the proposed test. Do not select APK duplicates as substitutes either.

The next executable must be a separate, bounded supervisor/child loader probe:

1. Use a versioned immutable local manifest of exact file hashes and load paths.
   Preserve namespaces/paths rather than flattening duplicate SONAMEs. The
   inventory above is input to that manifest, not an automatic load permit.
2. Establish child-only private mounts/root, no inherited outside descriptors,
   dropped credentials/capabilities, no-new-privileges, parent-death protection
   and bounded supervisor recovery **before** any selected library initializer.
   Only reviewed copied library files may exist in that root. No actual Binder,
   input/EBC nodes, property sockets, annotations, personal directories or procfs.
3. Add a separately tested loader-specific syscall policy, not an expansion of
   the already hardware-tested mechanism filter. Read-only file opening,
   private mappings/protection and runtime queries need precise rules. No shared
   output mapping, global IPC, ioctl, thread/process creation, new executable,
   signal/watchdog reconfiguration or privilege/mount changes. Unsupported
   initialization must produce an explicit failure, not a fabricated I/O result.
4. Test the policy/loader first with our own tiny constructor fixtures that
   deliberately try forbidden operations and timeouts. Review exact integrated
   source and host/kernel evidence before running any new executable on Nomad.
5. Only then attempt the pinned engine's initializers under the same boundary.
   Do NOT invoke JNI_OnLoad, startDraw, initBinderServer, worker/painter startup,
   onTransact or a Document page during this gate. Missing dependency, unexpected
   symbol binding, disallowed syscall, crash or uncertain cleanup is a failure.
6. A successful isolated load would prove only constructor/loader feasibility
   in the new environment. Its bindings must be recorded independently; they
   cannot be assumed to match app_process64. Private dispatch, owned background
   and output planes, pen admission and saved-native geometry remain later gates.

Keep the existing stock reader untouched and the companion disabled. Reuse the
tested isolation supervisor and display/geometry substrate; no second page,
tool-specific remapping, annotation conversion or production release is added.

## Constructor-policy preparation (host only)

`native/loader_filter.h` is a NEW policy candidate, separate from the previously
hardware-tested isolation filter. No Android wrapper installs it. Its host
interpreter tests argument/architecture/unknown-syscall behavior and decision
mutations. It admits read-only opens, private non-W+X mapping requests, exact
report-FD writes and a minimal runtime-query set; disallowed requests TRAP.

`run-loader-linux-tests.sh` runs our own `loader_fixture.c`, not Supernote code,
in disposable unprivileged x86-64 children with the translated policy installed
in the actual Linux kernel. Three rounds of 17 cases PASS (51 total): positive
load/memory/random constructors, trapped write/create/socket/ioctl/clone/exec/
signal/prctl/futex/remap/W+X/shared-mapping requests, and bounded stall recovery.
This host harness does NOT use a private filesystem/mount namespace, nor claim
that arbitrary firmware is safe to load there. It may load ONLY authored fixtures.

The first positive load correctly exposed the Linux loader's legacy
`MAP_DENYWRITE` flag. Its documented ignored bit is now admitted; private mapping
and protection restrictions remain. See [Linux mmap flags](https://man7.org/linux/man-pages/man2/mmap.2.html).

Before any real Android constructor loading, the wrapper must prove all earlier
root/FD/credential/namespace requirements, plus runtime mapping and personality
preconditions (no inherited external shared writable mapping or implicit-exec
personality). A filter checks syscall requests; it cannot establish filesystem
authority, arbitrary code integrity, actual effective W^X by itself, constructor
semantics, or faithful app-runtime behavior. The standalone Android worker,
library-publication manifest, SIGSYS report handler and immutable loader root
are still unimplemented. Do not combine this policy and firmware on the Nomad
without that implementation, adversarial evidence and exact-source review.
