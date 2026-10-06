# T014 atomic configuration and native/JS key transport

Source-only slice on the owned `agent/page-turner-bridge` checkout, based on
84ac014. NOT registered, copied by the installer, imported into App, packaged or
installed. Completed T013C/code51 and its released reservation remain unchanged.

## Wire authority

Each mounted JS owner must obtain a fresh namespace from
`ReaderKeyModule.createRequestNamespace()`. It returns a native UUID on each call,
not a reusable module constant. Its configuration counter starts at1 and never
reuses a value; counter exhaustion fails rather than wraps. A new mount/reload
must acquire a new namespace. Do not replace this with Date/time or a JS counter
alone, or reuse a namespace after native-view recreation.

The sole `routeSpec` prop contains exactly requestId, documentId, enabled and
keyCodes. RequestId is canonical lower-case UUID plus a positive safe-integer
counter; documentId is the currently opened original PDF path, not a persisted
page/annotation authority. Direction, presentation and current UI eligibility are
JS request-identity inputs, not native page ownership. Unknown fields, malformed
types/keys and changed content under a reused request terminally revoke routing.
Identical prop replay is a no-op. The native manager commits the complete validated
configuration only at onAfterUpdateTransaction, never individual field setters.

One `topReaderKey` / `onReaderKey` event transports both state and key envelopes.
Every event explicitly canCoalesce=false. A native view-local monotonic safe
sequence stamps publication order; both immutable native generation/activation
and config-request identity are serialized before enqueue. The Sink captures
the exact committed config object, not mutable pending/current props. Native
instance ID/generation remain the existing reviewed Host/Core authority.

Common envelope fields: schemaVersion1, kind(state/key), requestId, sequence,
activationId, documentId, generation, eligible, disposed. Key envelopes also
carry Android action/keyCode/deviceId/downTime/repeatCount. No inverse, timestamps
from Date, new page/save state, global Activity or stock-reader listener exists.

JS accepts only the exact current request/document and native instance. The first
state for each NEW request anchors the continuing native sequence after ignored
old-request packets; a key cannot anchor it. Subsequent current-request packets
must be consecutive. State generations strictly increase; key generation/activation
must exactly equal the last eligible state. Replays/gaps/malformed/foreign packets
fail closed, never queue a future turn. Stale-request packets never update state.

A synchronous UI fence invalidates publication BEFORE the next React effect/prop
commit. It cannot be cleared by queued old native state. A fresh request is required.
Every accepted key also rereads current UI context and uses the existing logical
navigation callbacks. Reentrant context callbacks must not revive a key or focus
check: config/spec/state and revocation are checked again after that callback.

Focus is an explicit manager command with the exact applied requestId. Stale
commands do nothing. The native Host still refuses another control's current
focus; no descendant-focus blocking or automatic native focus acquisition.
Ordinary ReactViewManager styles/children/commands remain available. Drop releases
the manager Binding and publishes the existing terminal state; no persistent hook.

## Focused evidence and limits

Actual Java source under bounded callback/queue doubles: Core2134 assertions,
Host25, new atomic bridge49. Existing four accepted-defect mutants rejected.
Actual Android35/ReactNative0.79.2 compile PASS for all six native key classes,
including manager/module/event. Dependency annotation/deprecation warnings are
retained; they are not native runtime evidence.32 JS/controller/current-App route/
transport tests PASS, including strict payloads, stale config/focus identity,
stream gap/replay, held-repeat/UP and synchronous/reentrant revocation.

First independent source review identified a reentrant-context P2. The actual
source regression failed before correction and passes afterward for fence,
disposal, forced configuration and lifecycle-state change during key AND focus
checks. Independent correction confirmation is now CLEAN for the full isolated
slice. Reviews retained locally at tmp/t014-transport-review1.md and review2.md.
Reviews inspect source only; root executes checks. No RN callback ordering,
native device focus/delivery, real HID mapping or Bluetooth feature PASS inferred.

## Next bounded source integration

1. One reader-owned native wrapper around pageArea, never around a stock reader
   or as a listener on both PDF surfaces. Keep ordinary onLayout/PanResponder
   behavior and measured-layout patch markers intact.
2. Load/persist per-document explicit enabled=false and opt-in key profiles through
   existing preferences. No default system-volume takeover. Request namespace
   asynchronously before enabling the wrapper; cancel late results on unmount.
3. Make modal/Jump/Edit/Close/global transition/native-busy/render/presentation/
   document/direction changes revoke synchronously. Existing logical next/previous
   callbacks and saved-ink cleanup/epoch remain the sole page owner.
4. Make OFF/native drop non-focusable, and confirm ordinary text/control focus
   is retained. UI focus requests must be exact config-bound and never timers or
   key retries. A failed transport must be visible in diagnostic status.
5. Copy/register required Java/JS files explicitly; test generated App/package
   assembly. Review any exact scoped frozen-pin changes before accepting them.
6. Focused integrated checks plus one independent full integrated review, exact
   candidate version/build/signature, then a FRESH issue23 reservation/preflight.

Earliest device gate is one bounded injected-key disposable T008 trial. No
speculative emulator prerequisite. OFF/Settings/Jump/Edit/Close must not navigate;
current physical arrows/logical page commands must move exact expected pages
once per contact in both Single/Spread. Stop on missing/foreign/stale packet,
wrong document/page, unexpected native-reader or annotation change, uncertain
cleanup or device conflict. Preserve code51 rollback and verify source/.mark,
other plugins/preferences and owned-cache cleanup before release. Actual paired
turner buttons/hold and human display acceptance are separate awake-only gates.
No current package build, hardware action, consumed-reservation reuse or merge.
