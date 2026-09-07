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
