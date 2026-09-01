# Native Spread process-containment audit

## Trigger

With the LSPosed APK enabled, Supernote's native highlighter stopped working
in both Native Spread documents and ordinary documents. Disabling LSPosed or
uninstalling the APK restored highlighting. This proved that the defect was
process-wide rather than a spread-layout-only annotation bug.

## Root cause

The module hooks classes in the single `com.supernote.document` process. The
old fail-closed logic treated an unresolved or stale module component binding
as a reason to suppress the firmware callback. That is correct only after an
exact document has opted into Native Spread. Before opt-in it caused methods
such as text-selection/highlight callbacks, native pen callbacks, navigation,
and writer operations to be dropped merely because the APK was installed.

Activity creation and destruction also entered the module's exclusive owner
lifecycle and JNI writer-gate paths before any document authority existed.

## v0.0.126 containment contract

One per-activity control claim is published only after the current PDF and its
persisted sidecars have been verified and the config explicitly enables Native
Spread. It remains published through that document's transactional page and
recovery work, then is removed only at a safe verified Off boundary.

Without that claim:

- owner-lifetime hooks return before taking module locks;
- missing or stale component identities delegate to firmware;
- no hook suppresses a result or changes an argument;
- pen, touch, selection, highlighter, digest, lasso, history, navigation, and
  embedded-link behavior remains native;
- activity startup/teardown does not enter the module's exclusive lifecycle or
  JNI writer-gate path;
- config discovery may inspect the sidecar but cannot arm spread hardware.

When a verified claimed document returns to Off, the claim is removed first.
The module then disables its native eraser gate and asks the native reader to
restore its normal writable/selection regions while all nested hooks are inert.

## Hook-family audit

| Hook family | Ordinary-document boundary |
|---|---|
| Activity lifecycle and presentation | Tracks identity only; no suppression, geometry, exclusive lock, or JNI gate without a claim |
| Pen and touch callbacks | Exact claimed callback/activity required; unknown ordinary callbacks pass through |
| Page turns and embedded links | Exact claimed view model required; ordinary calls and arguments are unchanged |
| Text selection and highlighting | Exact claim required for model gates, coordinate remapping, menu anchors, overlays, and digest composition |
| Handwriting, eraser, Undo/Redo | Exact claimed presenter/client/view required; ordinary writer calls are unchanged |
| Lasso and native note data | Exact claimed presenter/view/note identity required before geometry or trail changes |
| Native C++ eraser detours | Gate defaults false; disabled wrappers call the original exactly once with unchanged inputs and preserve the result |

## Automated evidence

- Native Spread safety invariants: pass.
- Native PDF renderer invariants: pass.
- Trace-helper fail-closed tests: pass.
- Java and native APK build: pass.
- APK v2/v3 signature and version verification: pass.
- Fourteen digest-advanced containment mutations: all rejected.

The remaining release gate is hardware validation. It begins with an ordinary
PDF before any Native Spread document is opened, because ordinary-reader
inertness is now a prerequisite rather than a secondary regression check.
