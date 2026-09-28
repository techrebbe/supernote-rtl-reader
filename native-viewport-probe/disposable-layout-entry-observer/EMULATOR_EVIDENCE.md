# Disposable emulator evidence

This is synthetic API-30 emulator evidence only. It does not certify Supernote
reader mutation coverage, final compositing, pen geometry, or Nomad behavior.

## 2026-09-28: parent-plus-one restore diagnostic build

- Reviewed source commit: `b892b01` on `agent/disposable-owned-child`.
- Synthetic signed APK SHA-256: `7b970be2c80a64b10921d011e5236ad6754b6a78395313fcc700db4faf64c9af`;
  temporary emulator-only signer SHA-256:
  `4d4f0f18e10114c7a801bcdb87dd4fd2d75ebc24ca0ad5bcb6967009e62ead6a`.
- Exact target: `emulator-5554`, `ro.kernel.qemu=1`, API 30, x86_64.
- One bounded `parent-plus-one` run returned `UNKNOWN`. Primary code:
  `REFRESHED_PAINT_UNAVAILABLE`; dominant cleanup code:
  `SERVER_CLEANUP_UNCERTAIN`. No layout command was sent, so the new
  `restoreEntryDrift` diagnostic was not exercised in this run.
- The first refresh poll did observe a later completed, exact-nine frame with
  the current view matching it. Its sampled paint age was 784 ms; the provider
  round trip took 798 ms. The conservative receipt-age bound was 1,582 ms;
  adding the host's 500 ms delivery reserve exceeded the app's 2,000 ms
  freshness window. Later polls were older. This is a transport-budget result,
  not evidence that a completed paint was absent.
- Independent postflight found no app process, Frida process, TCP listener,
  ADB forward, or local runner lock. The exact staged temporary server file
  remained. Its SHA-256 matched the reviewed server digest
  `9dcb1c12fa528070f2f6590b245e2c66cb1f931e0975bc911d9ff476394879d7`;
  after those checks it was removed from the emulator and its absence was
  verified. The automated cleanup verdict remains UNKNOWN rather than PASS.

Next bounded trial requires independently reviewed timing and cleanup changes.
It must remain one-shot, retain app-side exact fresh-paint authority, and stop
on any uncertain identity or cleanup. No Nomad, PDF, or pen action occurred.
