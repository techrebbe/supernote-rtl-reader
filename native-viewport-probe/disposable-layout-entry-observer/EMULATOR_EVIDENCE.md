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

## 2026-09-28: stricter network-table preflight

- Reviewed source commit: `87b9b4c` on `agent/disposable-owned-child`.
- One bounded `parent-plus-one` attempt returned `UNKNOWN` with
  `SERVER_NET_TABLE_INVALID` before staging the server or launching the app.
- Read-only inspection found the emulator uses `rem_address` in the tcp header
  and `remote_address` in the tcp6 header. The new parser expected the former
  in both tables; this is a precise dialect mismatch, not evidence of a
  listener or layout result.
- Independent postflight found no synthetic app or Frida process, staged
  server file, ADB forward, or local runner lock. No PDF or pen action occurred.

The next attempt requires an exact-header variant fix, offline tests, and
independent review. The failed preflight is not a synthetic layout PASS.

## 2026-09-28: changed-frame and restore-entry diagnostic

- Reviewed source commit: `46b3dad` on `agent/disposable-owned-child`.
- Exact target: synthetic API-30 x86_64 `emulator-5554`; no PDF, pen, or
  Nomad action. The one-shot `parent-plus-one` runner exited `UNKNOWN` with
  `APP_SCENE_DRIFT` / `RESTORE_ENTRY_DRIFT`, not PASS. Cleanup reported no
  uncertainty.
- The refresh proof observed a later completed exact-nine frame with the
  current view matching. Sample age was 571 ms, provider round trip 579 ms,
  and conservative receipt-age bound 1,150 ms, inside the 2,000 ms app gate.
  The app accepted the command, changed the root right edge from 1058 to
  1059, and recorded changed completed paint revision 4.
- The restore-entry witness retained the same root, root token, scene,
  nine children, geometry, parent pre-call revision 2, observed write ordinal
  2, and root layout-call count 2. The only differences between the first
  changed frame and restore entry were completed-paint revision 4 to 5 and
  its timestamp. A second same-state paint completed before restoration.
- Independent postflight found no synthetic app process, Frida process,
  ADB forward, staged Frida server file, or local runner lock. This clean
  postflight does not promote the layout result beyond UNKNOWN.

The next design review must decide how to handle an intervening same-state
completed paint without accepting actual identity, geometry, child, or
mutation drift. This synthetic result is not Nomad insertion authority.

## 2026-09-29: synchronous restore-request candidate

- Candidate source keeps the exact restore-entry comparator and watchdog, but
  requests restoration synchronously after the first changed completed paint.
  Focused host tests, the unsigned build, and independent source review passed.
- The new emulator-only signed APK SHA-256 is
  `a63937e0cc2008f18332eae1857bdbcdf7a1f94350182bee302a6446be56742a`;
  its signer remains
  `4d4f0f18e10114c7a801bcdb87dd4fd2d75ebc24ca0ad5bcb6967009e62ead6a`.
  It was installed on exact API-30 x86_64 `emulator-5554` only.
- One bounded `parent-plus-one` retry returned `UNKNOWN` with
  `APP_SCENE_DRIFT` / `UNREQUESTED_SECOND_PAINT`. The fresh frame and command
  were accepted: changed root right=1059 at completed revision 4, with
  `WAIT_RESTORE_CALL`. By the first trial poll, root right=1058 and parent
  layout/write revision 3 had restored, but completed revision 6 was recorded
  and the session was tainted as `UNREQUESTED_SECOND_PAINT`. This is not a
  verified rollback or a PASS.
- The runner reported no cleanup uncertainty. Independent postflight found
  no synthetic app process, Frida process, ADB forward, staged server file,
  or local runner lock. No Nomad, PDF, or pen action occurred.

The next review must locate whether the extra completed paint is an ordinary
post-restore traversal or a real uncontrolled draw before changing the
admission rule. The fail-closed UNKNOWN result is preserved.

## 2026-09-29: normal-restore redraw omission

- The next candidate retained the strict unsolicited-paint check and all
  UNKNOWN cleanup redraws, while removing the additional `root.invalidate()`
  from the normal restore request. Host tests, offline build, and independent
  source review passed. The signed emulator-only APK SHA-256 was
  `1b23a3be88a21193160329fffa4039735b685fbb5e01e594888ab12f5ca5d610`;
  the signer remained the same disposable key.
- One exact `emulator-5554` `parent-plus-one` run again returned `UNKNOWN` /
  `APP_SCENE_DRIFT` / `UNREQUESTED_SECOND_PAINT`. The changed frame completed
  at revision 4 with root right=1059. By the first poll, root right=1058 and
  parent layout/write revision 3 had restored, but revision 6 was complete
  before the explicit second-paint request could be credited. Removing that
  one invalidate was insufficient to prevent the intervening paint.
- The runner reported no cleanup uncertainty. Independent postflight found
  no synthetic app process, Frida process, ADB forward, staged server file,
  or local runner lock. No Nomad, PDF, or pen action occurred.

Further synthetic retries should not relabel revision 6 as an authorized
second paint. The next useful work is a separate event-order diagnosis; this
UNKNOWN result grants no stock-reader mutation authority.
