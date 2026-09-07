# Native engine boundary: pinned static findings, 2026-09-07

This is evidence for Gate B, not a native-page or stylus hardware pass.
Firmware binaries/decompiled source remain local inspection inputs, not repository
payloads. Digests and the previous device mechanism results are in
`NATIVE_PEN_BOUNDARY.md`.

## Actual startup, not the obsolete Activity entry

The DrawPath Java `DrawService.onStartCommand` calls
`startDraw(boolean isA6X, String logDirectory)` once. On Nomad its normal log
directory is `/data/vendor/eink/logd/realTimeHandWriting`; it broadcasts
`android.intent.action.drawAppStart` afterward. Its `onNativeCallback(String)`
broadcasts the supplied action. Do not execute this service in a second process
unmodified or use a second process's UID as an assumed hardware barrier.

On pinned DrawPath `librecgnition.so`:

- `Java_com_ratta_drawpath_MainActivity_startDraw`, 0x6051c, is a four-byte RET.
  Calling it would prove nothing about the pen engine.
- `Java_com_ratta_drawpath_DrawService_startDraw`, 0x605b8, size 1972, is real.
  It initializes logging, reads/sets a system property, calls
  `initBinderServer` (0x7ffc4), `bindingCPU`, initializes singleton workers,
  invokes `BaseThead::start` six times, and joins the Binder server threads.
- Startup calls include constructors for ThreadSampleEmr, ThreadDrawPath,
  ThreadRecognition, ThreadCastTheScreen and the remaining update workers.
  The output constructor independently opens/maps physical `/dev/ebc`.
- `initBinderServer` obtains Android's default service manager and creates a
  BnMyService. It is not a process-private mailbox.
- The ELF has 28 `.init_array` entries. A linear scan ending at the first RET
  is NOT a trustworthy initializer call graph: initializers tail-call
  `__cxa_atexit`, then unrelated constructors follow. In particular initializer
  0xc0998 ends at the tail call at 0xc0a84, before the EBC constructor at
  0xc0a88. No claim that all initializer paths are safe has been established.

## More than one client cache must agree

`com.supernote.document.handwrite.HandWriteClient` obtains `service_myservice`
and caches its Binder. Its native application identity is `superNoteDocument`.

Separately, `com.example.libsupernote.JniHandWriteClient.getBinder()` obtains the
same service. The Java method returns a non-null existing member when supplied;
the observed fallback returns ServiceManager.getService directly. More
importantly, Document's native library retains its own global Binder reference.
Redirecting only the first Java client would leave native tool operations using
the original engine.

Pinned `libratta_sn_process.so` symbols:

| Symbol | RVA | Size |
| --- | ---: | ---: |
| `getGlobalBinder(JNIEnv*)` | 0x13c87c | 684 |
| `deleteGlobalBinder` | 0x13cb6c | 56 |
| `jni_init_handwriteclient` | 0x181528 | 244 |
| `jni_free_handwriteclient` | 0x18161c | 16 |
| `globalBinder` | 0x3bbbc0 | pointer |
| `g_jni_handwriteclient_class` | 0x3bc190 | pointer |
| cached `getInstance` / `getBinder` methods | 0x3bc198 / 0x3bc1a0 | pointers |
| cached Binder class / `transact` method | 0x3bc718 / 0x3bc720 | pointers |

These are inspection observations, not addresses authorized for mutation.

## Lasso preview is not the same physical-output problem

The observed Document lasso selection path is:

1. `HandWritePresenter.lassoSelection`: `begin2ShiftTrails`.
2. `getShiftBodyPosition`; Java creates an Android Bitmap.
3. Native `loadShiftData(bitmap, 1)`; Java delivers it to selection listeners.

JNI `loadShiftData` at 0x2dd31c (size 5208) allocates CIMAGE/Mat data, converts
gray pixels to BGRA, writes the Bitmap and unlocks it through AndroidBitmap.
Its local `begin2ShiftTrails` helper passes the selected CIMAGE to MOVEOBJECT
and a null optional second CIMAGE. The examined move/resize/rotate paths operate
on native trails/selection images. JNI does not import
`MOVEOBJECT::cacheUpdate2framebuff`, `getDrawBufferMat`, or `getFbBufferMat`.
This supports retaining lasso preview inside the unchanged Android canvas;
import absence alone does NOT prove every native tool avoids physical output.

`MOVEOBJECT::begin2ShiftTrails` normalizes stored trail dimensions/coordinates
when they differ from the page. Therefore half-size native page dimensions
would change annotation meaning, not just presentation. Keep canonical native
page dimensions fixed; transform the completed canvas only once.

## Hardware-access boundary observed read-only

Both `/dev/ebc` and `/dev/input/event7` are mode 0666 on this firmware. The adb
shell UID 2000 also has group `input`. SELinux reports enforcing, but that does
not by itself prove a proposed worker cannot access hardware. The prior root
EVIOCGRAB proof did not establish that root is required for opening these nodes.

A private worker must have an explicit, verified denial/virtualization boundary
for physical input, EBC mappings/refresh, global Binder registration, system
property changes, logs and any other side effects BEFORE native startup. Merely
starting another Activity, cloning a Java client or dropping root is insufficient.

## Painter aliases and background input: the actual lower-level dependency

The DrawPath `ThreadDrawPath` constructor is at 0xaab00 (size 2988). At
0xaae44 it reads ThreadUpdateEpdc + 0xa0, and at 0xaae54 it reads + 0x98.
It retains these pointers in its own members 0x18f8 (draw) and 0x1900 (frame).
At 0xaaf04..0xaaf48 it places the draw pointer into CIMAGE member 0x1910,
using EPDC_WIDTH/EPDC_HEIGHT (GOT 0x13ead8/0x13eae0), and creates a Mat at
0x1928. `rPainter::setImage2paint` receives that Mat at 0xab0c8. The frame
pointer is also copied into a separate CIMAGE at member 0x1ab0.

Consequently, changing ThreadUpdateEpdc's getter or pointer member after startup
would not redirect the painter's already retained CIMAGE/Mat. This is concrete
static alias evidence, not merely a hypothetical cache concern. The singleton
symbol is 0x167850, size 6912, guard 0x169350; these additional members have NOT
been sampled on-device by the previously reviewed scalar observer.

`ThreadDrawPath::run` (0xadde8, size 29812) calls `getFbBufferMat` at 0xaef30,
0xb0230 and 0xb1888, alongside Mat copies; it invokes `drawErasedTrails`,
`SFCommunicate::sync_pw_buffer`, background backup updates and three physical
refresh call sites. An offscreen engine therefore needs the canonical Android
page/background as INPUT as well as a redirected wet-ink OUTPUT plane. A blank
replacement pen plane alone cannot establish faithful erase/composition behavior.

The constructor starts an update worker itself (0xab188); blocking only the
six top-level `startDraw` thread starts would miss this nested startup path.
No constructor, setter or worker has been called during this inspection.

## Transaction dispatch, not the named service stubs

Further local static inspection at approximately 05:20 on 2026-09-07 confirmed
that seven BnMyService methods at 0x6cc18..0x6cc30 are literal four-byte RETs:
askTrailData, askDeletedlData, clearScreen, setWritableAndNonWritableArea,
setPenInfo, setWalcomEmrInfo and setDebugMode. Calling these typed methods is
NOT a private equivalent of the stock client's Binder operations. Their Bp
counterparts contain substantial Parcel code.

The real BnMyService::onTransact is 0x6cc40, size 31652. Its inspected direct
calls include interface validation, String16/application identity and numeric
Parcel fields, tool configuration, trail queues, recognition and output work:

- 0x6e394: ThreadDrawPath::setPen; 0x6e4c4: setShiftValue.
- 0x6dbbc: TrailContainer queue push; 0x6e5a0: wait_and_pop.
- 0x6de54: SFCommunicate::sync_pw_buffer; 0x6df18: enableOverlay.
- 0x6d164: recognition trigger configuration; 0x6ce70: debug-image saving.

These are call sites, not a complete transaction-code/field schema or proof
that each branch is valid offscreen. Some requests block or touch output and
logging. A future private endpoint must preserve the actual dispatch/Parcel
semantics, bound blocking behavior and explicitly classify each side effect.
Do not replace unknown operations with success or synthesize tool results.

BnMyService construction at 0x801dc (size 688) has direct calls to RefBase,
IMyService, BBinder and String16 construction. initBinderServer at 0x7ffc4
also obtains the default global service manager. Neither was executed. A
local dispatcher without global registration remains a candidate, not a
tested loader or a safe substitute for the worker startup sequence.

## Refresh-channel distinction on this firmware

The Java HandWriteClient also contains a cached SurfaceFlinger Binder and
transaction 1102 with the android.ui.ISurfaceComposer interface. However its
Communicate and setFullAuto paths first check system type. DocumentConstants
returns 11 for the Nomad; that path invokes the e-ink manager's enableFullUiAuto
instead. The older SurfaceFlinger branch must NOT be recorded as an observed
Nomad transaction merely because it exists in the decompiled class. Actual
refresh ownership still needs to be coordinated with the canonical presenter.

In pinned DrawPath, SFCommunicate::Init, Communicate, set_pw_rect, exit_pw,
start_writing, stop_writing and set_pw_xrect at 0xcabc4..0xcabf4 each return
zero immediately. In contrast sync_pw_buffer at 0xcabfc (size 1552) obtains and
retains a draw-buffer Mat, and calls Mat::setTo at 0xcb008. Lazy initialization
can construct ThreadUpdateEpdc at 0xcb0c4/0xcb110. Its examined direct calls
do not make it an offscreen-frame export API. The misleadingly broad method
name is not evidence of a safe canonical background-input endpoint.

## Packaged dependency inventory (not the loaded dependency closure)

Read-only ELF inspection inside the pinned DrawPath APK found the following
arm64 libraries. The recognition entry matches the separately inspected ELF.
No archive member was extracted or loaded by this inventory.

| Library | SHA-256 | init_array entries |
| --- | --- | ---: |
| librecgnition.so | 3ce8bcf151e92899cb06c64e529723c560718aea36f070761c4ee9fe99bd57e2 | 28 |
| libbinder.so | 92255144e68336f94a134f6b77526be18ffa7b66ea12b8f650d7a166dbf99c57 | 22 |
| libc++_shared.so | ef50b47c713cf7778c42efd33fde62663f1a80a9764c803541b90e1bc8068949 | 1 |
| libomp.so | 10f837c340d07023b6b1830e0ca8770e4ca3a49da2fb2e1d51b6125b1416d2ae | 1 |
| libopencv_java4.so | 0107988932251f9a5c2107f3d1f88789340ca63934dba3e9e7b3ca32f8d3b57b | 61 |
| libutils.so | 1fffdb43d209477b3934ecafc1828d9051495d2b08df224adedb043cace0e0a1 | 2 |

OpenCV introduces libjnigraphics, libz and libmediandk. The bundled Binder/utils
introduce libcutils, platform libc++, libprocessgroup and libvndksupport, in
addition to libc/libm/libdl/liblog. The APK thus contains 87 initializer entries
outside the main recognition library alone. This count does NOT imply 87 unsafe
initializers, or describe which libraries the running linker actually selected.
That loaded closure and its initializer/transitive behavior are still unproved.

## Current decision

Additional read-only ELF work recovered exact unwind-FDE bounds for all 28
`.init_array` targets. This avoids the earlier first-RET/tail-call overrun.
In particular 0xc0998 has FDE size 240 bytes and ends at 0xc0a88, before the
separate hardware-opening constructor. Enumerating direct BL/tail-B targets
within these bounds found ordinary static initialization, Android String16,
and embedded logging/flag registration; unresolved/transitive callees remain.
This is NOT a complete side-effect proof.

The ELF's declared direct dependencies are liblog, libopencv_java4, libbinder,
libomp, libm, libc++_shared, libdl and libc. Their transitive dependencies and
initializers must also be included in any future pre-start loader boundary.
No library was loaded to obtain these findings.

Do not mutate the live DrawPath mapping or start another unmodified native
engine. First review the bounded isolation alternatives and prove the selected
one independently of Document and user annotations. The full-screen stock
reader remains unchanged. No Gate B claim, new APK or enabled writer follows
from these static findings.
