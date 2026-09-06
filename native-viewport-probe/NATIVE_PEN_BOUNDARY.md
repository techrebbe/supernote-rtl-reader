# Native pen boundary investigation — Gate B, not a pen-ready build

The Android display substrate is proved separately in `DISPLAY_HARDWARE.md`.
It does not redirect the native pen service. The overnight investigation starts
from that result, keeping all production modules disabled/unchanged and using
no physical or synthetic pen input.

## Pinned static and device evidence

Nomad SN078C10015092, Document 1.02.446 / PID 2027 and DrawPath PID 1425 on
2026-09-06. File Manager is foreground; the native Document is gracefully closed.
These PIDs are observations, not reusable authorization for a later run.

DrawPath `/system_ext/app/drawPath/lib/arm64/librecgnition.so` SHA-256:
`3ce8bcf151e92899cb06c64e529723c560718aea36f070761c4ee9fe99bd57e2`.
The on-device hash matches the locally disassembled binary.

- DrawPath owns `/dev/input/event7` (fd 46) and `/dev/ebc` (fd 48).
- `/proc/1425/maps` shows a shared writable `/dev/ebc` mapping of 0x786000
  bytes. This is not an Android VirtualDisplay buffer.
- `ThreadUpdateEpdc` constructor at 0xc0a88 opens `/dev/ebc`, queries its
  geometry with ioctl 0x48545201, and maps three planes with `MAP_SHARED`.
  Object offsets 0x98, 0xa0 and 0xb0 receive base, base + planeBytes, and
  base + 2 * planeBytes. Width/height are read from offsets 0x78/0x7a;
  plane/mapping byte lengths are stored at 0xbc/0xc0.
- `getDrawBufferMat` at 0xbd29c reads the member at 0xa0 directly.
  `getFbBufferMat` at 0xbb1f0 uses 0x98 or 0xb0 depending on native mode.
  `set_path_buffer` at 0xc17b4 is exactly `str x1,[x0,#0x98]; ret`.
- `ThreadSampleEmr::pushPointMess` at 0x653fc calls `adjustEMRDirection`
  and then pushes the resulting PointMess into the native queue.
  `adjustEMRDirection` at 0x65b80 clamps native axes, adjusts pressure for
  native pen state, conditionally flips both axes, and copies a 112-byte
  PointMess result. It is not merely a view-coordinate rotation. Do not
  replace this whole function with a two-coordinate transform.
- The previously documented `g_docFactor` special-case near 4/3 is not a
  general viewport scale. It remains unsuitable for arbitrary half-view scale.

Document's `MOVEOBJECT::cacheUpdate2framebuff` at 0xa5b70 uses `cv::Mat`
members inside MOVEOBJECT (for example pixel data at member 0xf8). The name
alone does not establish a physical framebuffer target. Its actual producer
binding remains to be traced; do not conflate it with the confirmed DrawPath
`/dev/ebc` mapping. No `/dev/ebc` mapping was found in the currently closed
Document process. That negative observation does not prove all live tools are
captured by the Android surface.

## Prepared bounded observation

`pen_boundary_snapshot.js` observes only exported scalar/member metadata on
the exact pinned DrawPath ABI. It never calls a native method, reads pixels,
hooks execution, changes pointer targets, writes memory or replays input.
It verifies the architecture, module path, export offsets, the setter's two
machine instructions, singleton initialization, readable member ranges, and
two matching metadata samples. It reports `atomic:false`: two equal samples
are not a synchronization primitive or permission to mutate the service.

Required invocation boundary: confirm the exact Nomad serial, process identity,
and library SHA-256, use `inspection/native-reader/tools/frida_readonly_snapshot.py`
with a bounded timeout and fresh local evidence path, then recheck process/hash
and stock fixture hashes. That runner unloads the script and detaches in `finally`.
Use the existing loopback-only, user-authorized Frida server; do not expose a
network listener. The required hash in the JSON is a declared prerequisite,
not a claim that the JS script itself computed the file digest.

`test_pen_boundary_snapshot.js` executes the actual script against a closed
mock API. New writes, native calls, hooks, unapproved metadata reads or pixel
reads have no implementation and fail. Tests include missing/shifted exports,
wrong architecture/module, unexpected instructions, uninitialized singleton,
null/unreadable buffers, incomplete ranges and changing metadata. This is
in addition to, not a substitute for, exact-source review and device evidence.

## Decision boundary for the native adapter

A genuine native viewport must coordinate:

1. Canonical native page/task and fixed-size Android surface.
2. Physical contact routing to that canonical canvas, preserving native pressure,
   pen type, contact boundaries, event ordering and native sample metadata.
3. DrawPath's canonical wet-ink/erase planes and refresh path, composed into the
   same physical frame as Android content, rather than written full-screen.
4. Android tool/chrome input on that same canvas, including selection popovers.

An input-only remap or a SurfaceView-only resize would split these authorities.
The next lower-level experiment must establish a reversible, process-scoped
offscreen pen-output boundary before a live half-page is writable. It must
also account for already-cached native buffer pointers and refresh calls,
not just override one getter after its result has escaped.

Still open: native lasso buffer binding, pen-service idle/contact barrier,
coherent event routing to a non-default display, and restoration on display
loss/process death. There is no Gate B pass, no enabled writer, no second page,
and no production package change in this investigation.

## Read-only hardware result

The exact-source r1 independent review was clean; all 34 executable observer
mock cases, 15 Python tests, 280 viewport assertions, 45,459 display assertions
and five repository baseline suites passed (85,407 v2 assertions/271 mutations).
Observer SHA-256: `ce150ce682e4e14782d4452ae46cd67f4bda68ea639855e661735844f2a90030`.

The first runner call refused attachment because the supplied process label
was the Android package, not Frida's name. Read-only enumeration independently
identified PID 1425 as `rattaDrawPath` and PID 2027 as `Document`; `/proc/1425/cmdline`
still identified `com.ratta.drawpath`. The corrected exact-name call succeeded,
then unloaded/detached. Process start tick 2642 and library digest matched before
and after. The stock PDF/mark hashes remain exactly those in DISPLAY_HARDWARE.md.

Live metadata confirmed ALL three member pointers reference `/dev/ebc`:
frame offset 0, draw offset 2,628,288 and alternate-frame offset 5,256,576.
The requested mapping is 7,884,928 bytes; the kernel's page-rounded mapping is
7,888,896 bytes. These are distinct lengths, not a corrupt buffer.
The device descriptor reports 1872 x 1404 while `SCREEN_WIDTH/HEIGHT` report
1404 x 1872. Do not infer pen-axis orientation from one of these pairs alone.
Document-specific screen dimensions are zero while File Manager is foreground.
No native getter, pixel read, setter, page launch, gesture or pen injection ran.
Evidence: ignored `build/pen-boundary-20260906/buffers-verified.jsonl`.

## Unattended input-device mechanism check

`native/pen_device_probe.c` is a standalone, short-lived input-device diagnostic,
not a reader hook. `--inspect-idle` only queries identity/capabilities/current
pen state. `--prove-exclusive-idle` additionally acquires and releases EVIOCGRAB
on the exact Wacom device and proves a separately opened descriptor is rejected
with EBUSY while the first owns it, then can acquire after release. It does not
hold a long-lived barrier, read/replay input samples, launch Document, alter
annotations, alter device capabilities, or disable any service/module.

Run only with File Manager foreground and Document closed. Device identity is
checked on held descriptors: no symlink-following; character device; Wacom-pen;
expected X/Y/pressure ranges and pen/touch/rubber capabilities; matching inode
and device for both opens. Pressure, tool-in-range and pen buttons must be idle.
Every exit closes opened descriptors, which releases their grab. The helper
is not admitted as an ongoing handwriting interlock; `held=false pen_ready=false`
is deliberate. It cannot protect a later separately launched Document session.
The pure control-flow core has tests for every injected operation failure,
broken exclusivity, duplicate descriptors and cleanup after acquisition.

Build with `build-pen-device-probe.ps1 -Ndk <installed NDK>`. Review the full
updated source subset before running either AArch64 executable on the tablet.
Run `pen-grab-core-test` as ordinary adb UID 2000: it uses only fake operations.
The real probe needs root for the exact device node; it must never be used as
an excuse to start native writing before the coherent output/input adapter.

Kernel reference: [Linux evdev grab/release implementation](https://github.com/torvalds/linux/blob/v5.4/drivers/input/evdev.c).
This documents the expected exclusive-device mechanism, not a Nomad hardware
pass or a guarantee about firmware-specific consumers and already queued input.

### Hardware result — 2026-09-07, approximately 00:06 Asia/Jerusalem

The r2 independent review of the full 29-file source subset was clean. The
reviewer reran the 34 Node cases. All 29 source files matched that exact snapshot
before deployment. NDK 27.0.12077973 produced AArch64/API30 helpers with
`-Wall -Wextra -Werror`:

- `pen-device-probe`: `c280995392cd261b45ebf545c716991c8a2d4a9f33e6a9a13b3edbee5e99226a`
- `pen-grab-core-test`: `611b5526d10bba90a30e1afd64c4e5c90074a6716c55abf0f3b760e34a38acbe`

The exact serial, File Manager foreground, pinned DrawPath library, and stock
PDF/mark hashes were verified again before staging. Device binary hashes matched.
The fake-operation executable ran as UID 2000: **18 cases PASS**, including
every injected operation failure, broken exclusivity and duplicate descriptors.
Then the real root helper returned:

```text
PEN_INSPECT_IDLE exact_nomad_device=true held=false
PEN_EXCLUSIVITY_PROVED held=false pen_ready=false
PEN_INSPECT_IDLE exact_nomad_device=true held=false
```

Document/DrawPath PIDs remained 2027/1425, and both stock fixture hashes remained
unchanged. The two exact helper files and their empty temporary directory were
removed. No helper process remains; local binaries and evidence are retained in
`build/pen-5ff34cfb4df64c03943dc499d980239e/` and `build/pen-boundary-20260906/`.
No input was generated, no native writing was enabled, and no module was changed.

This passes ONLY the instantaneous acquisition/exclusion/release mechanism gate.
It does not establish a held lease, drain already queued contacts, validate
physical pen delivery, or authorize Document to write in the display-only host.

## Additional static lasso producer findings

On the pinned Document libraries, `SnCommon::init_layer_cimage` at 0x15d68c
calls `rattaCreateImage(short,short,unsigned char,unsigned char)`. That delegates
to the three-argument allocator at 0xabc9c, which allocates a 24-byte CIMAGE
descriptor and a separate pixel plane through `umalloc` (0x100a10), resolved to
libc `malloc`. Descriptor fields include signed-short width/height at 0/2,
stride at 4, pixel pointer at 8, and channel count at 0x10.

This establishes heap allocation at creation, not the lifetime binding of every
lasso output. `MOVEOBJECT::begin2ShiftTrails` at 0xa6084 copies selected trails
and contains stored-dimension/coordinate normalization. Keep the native canonical
canvas fixed; changing native page dimensions to match a smaller physical frame
cannot be assumed to be presentation-only. The binding from CIMAGE into each
MOVEOBJECT output Mat still requires exact tracing before any redirection.
