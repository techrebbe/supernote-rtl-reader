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
hardware-tested isolation filter. The new Android wrapper is fixture-only and
has not run on the Nomad. Its host
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
semantics, or faithful app-runtime behavior. Firmware library publication and
the real engine worker are still unimplemented. Do not combine this policy and
firmware on the Nomad without that implementation, evidence and exact review.

## Review-fix batch and authored Android loader — 2026-09-07

The approved 52-file review of `9e2441f`/code `8480054` returned NOT CLEAN with
four actionable host-evidence findings. All were accepted in this batch:

- Inventory v2 opens `/proc/<pid>/map_files/<range>` and compares the **open
  descriptor's** device/inode with the process mappings. Both bounded captures
  and before/after descriptor stat records must match. No pathname in adb's
  different mount namespace is treated as equivalent. Lack of map_files access
  fails explicitly. The existing inventory-v1 evidence remains preserved, not
  retroactively upgraded; the live binding collector now rejects it.
- Import slots must agree with both PT_LOAD file offsets and the readable
  process mapping's file offsets. BSS-only/ambiguous storage is rejected.
- Dynamic-table addresses/sizes, allocated section coverage and symbol-table
  identity replace name-based `.rela.*` selection. A renamed packed-table
  synthetic ELF proves imports cannot silently disappear. RELR relative entries
  are covered separately and never read as symbolic import pointers.
- Local reads validate the opened descriptor and read at most its prechecked
  size plus one. Remote stdout is capped while reading; the mapped transfer has
  an explicit dd block count. LLVM consumes an exclusive bounded-byte copy,
  not a potentially replaced source pathname.

The revised independent LLVM comparison matches **49,594** records: the earlier
48,764 RELA/APS2 records plus 830 RELR entries. This does not change the earlier
observed pointer values or grant new live-memory authority. Local evidence:
`../../loader-inventory-20260907c/llvm-comparison-v2.json` (no ADB run).

The first Android compilation caught an architecture-specific open-flag error:
the AArch64 allowed mask is `0xac800`, not x86-64's `0xb8800`. The target ABI is
now compiler-asserted; host tests translate those flag semantics explicitly.
174,795 policy vectors / 124 decision mutations pass. New constructor markers
distinguish loader-ready, constructor-entered, operation-returned and completed
dlclose. 5,704 report checks reject missing/reordered/wrong/truncated evidence;
the 51 Linux kernel/own-constructor cases pass again with these markers.

`build-loader-probe.ps1` builds `loader_android_probe.c` with the compiled bytes
of our own small `loader_fixture.c` embedded. There is no arbitrary DSO argument
or firmware payload. It reuses the tested isolation sequence/supervisor, creates
a child-only private tmpfs, seeds only that fixture and makes the root read-only,
rejects inherited shared/W+X mappings and implicit-exec personality, closes all
outside descriptors, chroots, drops credentials/capabilities and installs the
constructor filter before dlopen. SIGSYS reports use the exact report pipe.
Seventeen constructor cases plus five isolated crash boundaries are prepared.
The parent checks bounded exact-child cleanup and unchanged namespace/root/device
node identity; it never opens pen/EBC nodes. Unknown cleanup preserves evidence.

The Android build and Clang analysis pass. This is **BUILD ONLY**, not 22 device
passes. No new helper was staged, installed or executed; the companion remains
disabled. Exact integrated source review and owned-device preflight are required
before this test. A fixture pass would still not authorize JNI_OnLoad/startDraw,
Binder service creation, engine threads, Document admission or real pen input.

Prepared artifact: `build/loader-probe-8e207c0811ac402fb154a0bd281ef8ca/`
`loader-android-probe` SHA-256
`5c0059935ea71788e9f8a740b03918df8b1e4fb81de994a3841e7afcc2b6e889`;
embedded authored DSO SHA-256
`6a1418ef3517ca03124e5082c8c274603b39b4464a063962cd615b80c5703663`.
All 54 Python cases pass with the ELF parser enabled (zero skips), alongside
280 viewport, 45,459 display assertions and 34 closed observer cases. The generic
check script's five optional-parser skips are covered by that explicit run.

The integrated Ultra r2 review of `56de162` reviewed all 56 files and found one
additional P2: section-selected symbol/string bytes were not tied completely
to DT_SYMTAB/DT_STRTAB. This is fixed by checking their PT_LOAD file offsets,
dynamic string address/size, symbol extents and each name's in-table terminator.
Tests displace both `.dynsym` and `.dynstr`, change string geometry, exceed the
name offset and remove the terminator. All 56 parser-enabled Python tests pass;
all 49,594 offline LLVM records still agree (`llvm-comparison-v3.json`). The C
loader, binary hash and previously run kernel/policy tests are unchanged. The
review established no further loader/cleanup/geometry finding, but the combined
subset still requires the final updated-head confirmation before a device run.
