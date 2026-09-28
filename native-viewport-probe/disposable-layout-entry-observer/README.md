# Synthetic layout method-entry observer (offline-tested candidate)

This directory is separate from the stock-reader hierarchy observer. It is
for the disposable API-30 emulator app only: package
`com.techrebbe.supernote.layoutfencetrial`, one fresh process per variant, no
document, PDF, pen, Nomad, or stock process. No device trial has run.

`layout_entry_observer.js` temporarily replaces
`android.view.ViewGroup.layout(int,int,int,int)` process-wide. It selects one
`TrialActivity`, verifies the exact provider-pinned Activity and root tokens,
retains its `TrialRoot`, and compares Java object identity with JNI
`isSameObject` on every callback. It stages only bounded primitive entry data
before forwarding. The original overload is called exactly once on every
normal callback path, including non-target views and observation failures; no
`send`, logging, View setter, or hierarchy mutation occurs in the callback.
Any JS/bridge fault can still affect the hooked process, so this is not a
read-only stock-reader mechanism. An original Java exception or observer fault
is an UNKNOWN trial, never evidence of successful forwarding.

The script has one-shot `arm`, `snapshot`, and `disarm` RPC methods. Disarm
requires no callback in flight, explicitly sets `.implementation = null`,
checks the same wrapper, and releases retained references. Host evidence must
also include an app-main-thread quiescence barrier, an app-owned post-revert
sentinel that produces no new hook callbacks, script unload/detach, and a final
exact post-unload state/paint witness. A property check alone does not prove
ART restoration. The app independently owns restoration and its watchdog.

`run_emulator_trial.py` is an explicit, single-variant emulator backend. It
requires `--execute-synthetic-api30-only` and supplied absolute paths and
SHA-256 assertions for the source-pinned, already-installed signed APK, its signer,
the official Frida 17.9.11 x86_64 server, and a compiled observer bundle. It
admits only `emulator-5554`, qemu=1, API 30, x86_64, the exact synthetic package,
and a fresh PID/process incarnation with one Activity/root and exact nine-child
paint. It stages one owned server/forward and cleans up only their verified
identities. It neither installs the APK nor selects a device by discovery.

The one-shot sequence is: app prearm (independent 30-second exact-process
self-kill watchdog), bounded Frida attach/arm, one app-owned root invalidate
refresh, a newly completed exact paint, one app command (5-second active trial
deadline), independent proof-cut comparison, quiescence barrier, hook revert,
`after-disarm` sentinel with no new callback, script unload/detach,
`after-unload` sentinel, exact post-unload evidence, then provider finish.
Only after a fully verified finish does the runner use exact-serial
`am force-stop` on the synthetic package to prepare for a fresh next variant.
Any uncertain post-prearm path uses the app's exact-token abort and/or its
independent self-kill watchdog; it never uses a host PID kill or package-wide
force-stop as a fallback. Before prearm or Frida attach, ambiguous app launch
or initial paint instead permits one exact synthetic-package force-stop after
rechecking the emulator and installed APK, then reports UNKNOWN and halts.
No write, arm, trial, revert, unload, or sentinel is automatically retried.
Unknown CLI wire rendering or deadline drift is UNKNOWN.
The runner's local lock is exclusive. On Windows, new locks use handle-owned
delete-on-close; an existing lock is never removed or treated as stale by the
runner. A missing/replaced lock or a new owner appearing during release is
conservatively UNKNOWN, without deleting the replacement. Cleanup uncertainty
dominates the verdict; `primaryCode` and `cleanupCodes` retain earlier fixed
failure codes in the UNKNOWN result for audit.

Frida 17's bare Python script loader does not provide `Java` automatically.
`build_layout_entry_bundle.py` uses the project's installed, authenticated
Frida 17.9.11 compiler and `frida-java-bridge` 7.0.13 without npm/network.
Its reviewed bundle is 476101 bytes with SHA-256
`241fd6a94067b26a737df8ddf6c192b82895006472c434cae4cbd06dc29a2d66`.
The raw observer source alone is not an executable Frida 17 bundle; the runner
requires an explicit bundle path and matching SHA-256.

The executable pins the final synthetic APK SHA-256
`d4c38a2c2b914819ec41c13e7e4b08fa78eba1767f40335b135dac99092bad0c`,
signer `4d4f0f18e10114c7a801bcdb87dd4fd2d75ebc24ca0ad5bcb6967009e62ead6a`,
server `9dcb1c12fa528070f2f6590b245e2c66cb1f931e0975bc911d9ff476394879d7`
(110837320 bytes), and bundle digest/size above. CLI hashes cannot redefine
these authorities.

Run the offline mocks with:

```text
node native-viewport-probe/disposable-layout-entry-observer/test_layout_entry_observer.js
python -m unittest discover -s native-viewport-probe/disposable-layout-entry-observer -p 'test_*.py'
```

Even a later emulator PASS means only an observed method-entry sequence for
that one synthetic path, with independent scene/paint and post-hook witnesses.
It does not establish every state write, final compositing, or stock-reader
behavior: `observationOnly=true`, `compositingAdmitted=false`,
`completeMutationCoverage=false`, and Port revision `-1`.
