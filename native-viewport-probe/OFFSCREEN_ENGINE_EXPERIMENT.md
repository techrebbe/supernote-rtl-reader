# Next bounded proof: one offscreen native pen engine

Status: candidate design awaiting independent review, not implemented or authorized
as a live handwriting session by passing the earlier display-only tests.

## Invariant, not a second page-state controller

One native Document context keeps its original page, canonical native dimensions,
tools, undo/redo and `.mark` authority. The Android canvas and pen output must be
presented through one frame transform. Physical contacts are classified once,
transformed into that canonical canvas before entering the native pipeline, and
retain pressure/tool/sequence metadata. Rotation changes presentation only.

The missing boundary is global DrawPath's physical input and three EBC planes.
Changing page geometry or patching individual lasso/erase positions is rejected.

## Alternatives to evaluate before code

### A. Isolated native pen worker (preferred to investigate, not yet selected)

Run the exact pinned native engine in a private process. Before its first native
initializer/startup, establish a kernel-enforced hardware isolation boundary.
Supply owned input and output endpoints and a private Binder endpoint. No native
library file is patched or distributed. One reviewed session binding must cover
both Java and native Document Binder clients before a page context exists.

Required initial proof, without launching Document or touching the real service:

- The worker cannot open/read/grab real input, map/write/refresh real EBC, register
  a global service, change global properties, or access annotations.
- Hardware-shaped test endpoints are process-private and parent device identity,
  live DrawPath process, device nodes, input grab state and fixture hashes are
  unchanged after normal exit, injected failure, timeout and worker death.
- Native startup is first blocked, then admitted only against verified private
  endpoints. Unknown I/O or unsupported startup fails the probe; do not pretend
  arbitrary ioctl success is faithful hardware emulation.
- Only after that proof: native synthetic rendering to owned planes with a
  deterministic recorded input sequence. This is algorithm/output evidence,
  never a physical pen or saved-native-tool pass.

Possible mechanism: a child-only private mount namespace with no physical `/dev`
or global Binder/property sockets, followed by capability/UID restrictions;
explicit native I/O adapters for the owned endpoints. Namespace operations must
be proved not to propagate to the parent. A Java hook alone is NOT the isolation
boundary. The generic child-only mount/filter mechanism has since passed as
described below; no firmware worker or library startup has been attempted.

The isolated-process substrate is described in `ISOLATION_PROBE.md`. The user
approved source-only review; two supervisor findings were fixed and the full
confirmation review was clean. The exact diagnostic then passed its five
bounded Nomad cases and was removed. It has no firmware loader and does NOT
admit native startup. Parent-death delivery and hostile deployment remain
separate from the completed cooperative mechanism test.

Concerns: native dependencies/SELinux, startup global-service assumptions,
initializers, Java callback delivery, native Binder caches, added IPC latency.
If isolation cannot be established cleanly, reject this route rather than mask
errors or relax the safety boundary.

### B. Lease the existing native engine and replace its output backing

Keep one original service and establish an exclusive session. A complete output
virtualization boundary must cover all cached pointers/aliases and physical
refresh calls before contacts are enabled. Redirecting one getter is inadequate.
Replacing the mapping at the same virtual address could preserve aliases but
requires a real quiescence protocol, atomic admission, and guaranteed restoration
on interruption. This is substantially riskier in the live shared service.

Do not call mmap/MAP_FIXED, mprotect or write any live native pointer as part of
the current investigation. First model/test alias lifetime and failure recovery
against a disposable process/file, not `/dev/ebc`. A successful disposable test
would still not prove the live service is safe to swap.

### C. Existing firmware offscreen mode

Prefer an existing coherent offscreen mode if the pinned native code exposes it.
The inspected buffer getters return physical EBC-backed planes; the short overlay
methods are no-ops on this firmware. `SFCommunicate` and casting code remain leads,
not an established offscreen engine. Do not treat an evocative symbol name as a
supported mode or substitute a bitmap renderer for genuine native tool behavior.

## Stop criteria and release boundaries

### Next bounded proof, before a page/tool test

The 05:20 local static findings in `NATIVE_ENGINE_STARTUP.md` narrow the next
step; they do not approve starting the stock service:

1. Establish the exact loaded dependency closure from pinned local evidence
   (or a separately owned read-only device observation), not APK filenames
   alone. Record library hashes, needed libraries and constructor boundaries.
2. Specify an initializer-only loading experiment in the disposable child.
   It must have no Document, global Binder, property sockets, physical devices,
   personal paths or annotation access. The current mechanism filter cannot
   load libraries or create threads; any expanded policy must be separately
   implemented, adversarially tested and reviewed before device execution.
   Unknown dependencies or initialization side effects must fail explicitly.
3. After that gate, evaluate private Parcel/onTransact dispatch without
   initBinderServer/global registration. Named BnMyService tool methods are
   RET stubs and cannot serve as the adapter. Preserve protocol semantics,
   application identity, queue deadlines and native replies; do not fake success.
4. Admit painter/worker initialization only with all retained output aliases
   bound to owned planes from construction, plus a verified canonical page
   background input. SFCommunicate::sync_pw_buffer is not an established frame
   export endpoint. The Nomad's Java e-ink-manager refresh route must also be
   accounted for; the old SurfaceFlinger Java branch is not active on this model.
5. Prove deterministic synthetic input/output and teardown before exposing
   Document to one canonical page in full, left and right rectangles. This
   still cannot replace the later real-pen, saved-geometry and untouched-native
   reopen gate. Only a passed single-page gate admits second-viewport work.

This sequence retains the stock evidence, display geometry, observer and
isolation supervisor. It adds no competing page/save owner and does not grant
permission to mutate the existing service's mappings while a loader is missing.

This is a single native engine/viewport investigation, not two independently
writing readers. Keep original PDF and `.mark` authoritative; no conversion,
InkBridge changes, personal-file mutation, module enablement or production install.
Unknown I/O, lost ownership or incomplete cleanup is a failed experiment.
Automated failure injection plus independent exact-source review precede any new
device executable. Actual stylus checks remain required when a genuine native
page is finally admitted in full, left and right frames.
