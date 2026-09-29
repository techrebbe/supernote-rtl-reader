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

## 2026-09-29: bounded intervening-frame candidate

- The reviewed candidate admits at most one exact post-restore redraw as a
  non-voting witness, then requires a distinct explicitly requested frame and
  independently checked host/app revision and timing evidence. It does not
  weaken identity, bounds, counter, or cleanup checks. The focused 101 Python
  tests, 13 JavaScript cases, and 192/9/70 Java checks passed.
- The separately reviewed fresh emulator-only APK has SHA-256
  `74600cc25405710723ce919c4f590f1431f9df4cc50ddfb2f0d83688f88bd498`
  and signer SHA-256
  `f1a37e18769ea6e7da195cc8d7b32622d96a4238b264ef7107caca07d3da9c61`.
  Its DEX and manifest match the reviewed unsigned build. The old synthetic
  package, whose pinned installed APK was
  `1b23a3be88a21193160329fffa4039735b685fbb5e01e594888ab12f5ca5d610`,
  was removed from verified API-30 x86_64 `emulator-5554` because its temporary
  signing key was unavailable. Only that disposable package was installed
  again; its new installed APK hash was independently verified. This erased
  that synthetic app's private state; no PDF, Nomad, or pen input was touched.
- One `parent-plus-one` run returned `UNKNOWN` / `TRIAL_UNCERTAIN`, not PASS.
  The refresh proof did reach one later completed exact-nine frame with
  `commandViable=true`, `sampleAgeMs=566`, `pollRoundTripMs=562`, and
  `ageUpperAtReceiptMs=1128` against the 2,000 ms app freshness gate. The
  generic code does not establish whether the command was accepted or whether
  restoration passed; the current error surface needs a fixed-phase diagnostic
  before any retry.
- The independently reviewed fixed-phase diagnostic covers all 17 lifecycle
  phases with injected-error/cleanup-order tests (105 Python tests total). One
  bounded diagnostic rerun with the same exact APK and inputs returned
  `UNKNOWN` / `TRIAL_UNCERTAIN_DETACH`. Fresh paint was again viable:
  `sampleAgeMs=553`, `pollRoundTripMs=578`,
  `ageUpperAtReceiptMs=1131`. The fixed phase establishes that the host
  progressed through app rollback/evidence, observer disarm, sentinel, and
  script unload without a reported failure, but the Frida worker detach did
  not return a verified result. It is not a completed PASS or proof of native
  view rollback.
- Offline analysis found a deterministic worker-launcher defect: a successful
  `_child()` return was wrapped in `raise SystemExit(0)` inside an
  `except BaseException`, which caught that normal exit and rewrote it to 2.
  The reviewed fix moves the final `SystemExit(status)` outside the handler;
  a device-free subprocess test proves clean detach exits 0 and malformed
  worker operations still exit 2. All 106 Python observer tests pass.
- One final bounded `parent-plus-one` confirmation returned
  `PASS_SYNTHETIC_EDGE_ONLY`: two target method entries, hook removed,
  post-unload verified, exact synthetic PID 22257 and process incarnation
  `7ccd1b32-2b35-4cc4-ba6a-95bf095fd5df`. The result explicitly retained
  `observationOnly=true`, `compositingAdmitted=false`,
  `completeMutationCoverage=false`, and `portRevision=-1`.
- Independent postflight found no synthetic app process, Frida process, ADB
  forward, staged Frida file, or local runner lock. Clean postflight does not
  promote the two earlier UNKNOWN results; the final PASS applies only to the
  single synthetic edge above. No Nomad insertion is authorized.

## 2026-09-29: one-variable extension probes

- With the same exact reviewed APK and runner, a `parent-minus-one` trial
  returned `UNKNOWN` / `APP_SCENE_DRIFT` / `UNREQUESTED_SECOND_PAINT`.
  Its command response showed changed right bound 1057, followed by the
  restored baseline right bound 1058 and completed revision 6. The current
  one-extra-restored-frame rule was intentionally limited to `parent-plus-one`,
  so it rejected this extra frame. Its independent postflight was clean.
- A separate `direct-root-layout` trial returned the same fixed UNKNOWN reason.
  Its command response showed changed right bound 1059, followed by restored
  right bound 1058 and completed revision 6. Its independent postflight was
  also clean. Neither result proves verified rollback or Nomad behavior.
- These observations justify an offline review of whether the existing
  strict same-identity, same-geometry, same-counters, one-extra-frame rule can
  apply to other synthetic commands. The rule must still reject actual scene
  drift and require a distinct explicitly requested later paint; no retry is
  warranted until that contract and tests are reviewed. This paragraph records
  the earlier plus-one-only implementation, not the current candidate.

## 2026-09-29: four-restore-variant candidate prepared

- The one non-voting, exact restored-frame allowance now covers only the four
  commands with a separate restore phase: `parent-plus-one`,
  `parent-minus-one`, `direct-root-layout`, and `direct-root-offset`. It still
  rejects a duplicate extra frame, any geometry/identity/counter drift, an
  early request, and an extra frame in `unchanged-bounds` or `away-back-aba`.
  Each admitted path requires a distinct later explicitly requested paint.
- Offline checks passed: 108 Python observer tests, 13 JavaScript cases, and
  407/9/70 Java checks. Independent source review found no new blocker after
  the reviewed artifact pins below were updated.
- The freshly built, separately reviewed emulator-only unsigned APK SHA-256 is
  `80b69835828589e545caac5ebf8c287c2d180d0271837d75b7033c504230ac90`.
  The signed APK SHA-256 is
  `e34b29c8945f8eaba3a3abe15a3a445f1b23a2b296d1c5c24a64fefff0785ed0`,
  with single signer SHA-256
  `1bac41f739e24ee981404973f51b7dd7688dce12e96826d6e250e473f899f65d`.
  Its signed and unsigned manifests/DEX are identical; it requests no
  permissions and contains no personal files. No runtime result is claimed
  for this candidate until the one-shot emulator gate runs.

## 2026-09-29: four-restore-variant emulator observations

- The exact signed APK above replaced only the previous disposable synthetic
  package on verified API-30 x86_64 `emulator-5554`; its installed SHA-256
  matched `e34b29c8945f8eaba3a3abe15a3a445f1b23a2b296d1c5c24a64fefff0785ed0`.
  The old temporary signing key was unavailable, so uninstall erased only
  that test app's private state. No Nomad, PDF, annotation, or pen action
  occurred.
- The first `parent-minus-one` invocation failed local preflight with
  `WORKER_PATH_INVALID` because the Frida Python site path was one directory
  too deep. The runner rejected it before contacting ADB. Independent checks
  found no app/Frida process, ADB forward, staged server, or local lock.
- With the corrected existing Frida site path, one `parent-minus-one` run
  returned `PASS_SYNTHETIC_EDGE_ONLY`, with two target entries, hook removal,
  and post-unload verification. Independent postflight was clean.
- A separate `direct-root-layout` run returned the same scoped PASS, also
  with two target entries, hook removal, post-unload verification, and clean
  independent postflight.
- One `direct-root-offset` run returned `UNKNOWN` / `APP_TRIAL_TIMEOUT` after
  a viable pre-command refresh. The host's bounded polling deadline starts
  before the blocking command call; this code does not prove that the app's
  own trial deadline expired. It also does not locate whether the first
  offset paint, restore, or second paint stalled. Independent postflight was
  clean. No immediate retry or broader device test was performed; a bounded
  token-free latest-poll diagnostic was prepared first.
- A separately reviewed, host-only timeout projection (112 Python tests) made
  no additional provider query and left verdict/cleanup rules unchanged. One
  diagnostic `direct-root-offset` rerun remained `UNKNOWN` /
  `APP_TRIAL_TIMEOUT`: its command response had the first changed-bounds paint
  complete at revision 4 and `WAIT_RESTORE_CALL`. The first and last returned
  polls both had baseline bounds, parent revision 2/write ordinal 3/layout 2,
  `restoreAfter=true`, `restoredFrame=false`, and `WAIT_RESTORE_PAINT`. No
  further completed paint occurred through the host cutoff. This localizes
  the synthetic stall to scheduling the restored paint after the offset's
  parent layout, not the direct write or initial changed-bounds paint.
  Independent postflight again found no app/Frida process, ADB forward,
  staged server, or lock. No retry is warranted before a scoped fix/review.

## 2026-09-29: direct-offset restored-paint candidate prepared

- A command-specific redraw was added only after the parent has returned an
  exact verified baseline-geometry cut for `direct-root-offset`. It does not
  run on the other five commands, before accepted restore geometry, or after
  the restored paint. The one-extra-frame and distinct requested-paint checks
  remain unchanged.
- Offline checks passed: 112 Python observer tests, 13 JavaScript cases, and
  472/9/70 Java checks. Independent source review found no new integrity
  blocker. The new unsigned emulator-only APK SHA-256 is
  `758853b5fbc04420f5a60c557b4444748a750a4425755bb060d79f229612e940`;
  the signed APK SHA-256 is
  `544d512a21e2a0f550f16d78fdc742ba944023a43748204a87f4927d76aa30cf`;
  and its single signer SHA-256 is
  `204e63fe1e5784bb8597e322fe607f7c4ba5a3d269d3af22a90240bdb3601afd`.
  Independent artifact review verified identical manifest/DEX content,
  package isolation, no requested permissions, and no personal assets.
  This paragraph makes no runtime claim until the reviewed emulator gate runs.

## 2026-09-29: direct-offset redraw confirmation and control finding

- The exact reviewed signed APK above replaced only the disposable package on
  verified API-30 x86_64 `emulator-5554`, and the installed hash matched
  `544d512a21e2a0f550f16d78fdc742ba944023a43748204a87f4927d76aa30cf`.
- One `direct-root-offset` run returned `PASS_SYNTHETIC_EDGE_ONLY`, one target
  method entry, hook removed, and post-unload verified. Independent postflight
  showed no app/Frida process, ADB forward, staged server, or lock. The
  command-specific restored-paint request therefore closed the previously
  observed synthetic WAIT_RESTORE_PAINT stall; it does not prove stock-reader
  compositing or complete mutation coverage.
- Separate `parent-plus-one`, `parent-minus-one`, and `direct-root-layout`
  regression runs each returned the same scoped PASS with two target entries.
  Each had a separate clean independent postflight.
- The `unchanged-bounds` no-restore control returned `UNKNOWN` /
  `APP_TRIAL_TIMEOUT`. Its accepted command response and both returned polls
  stayed at `WAIT_FIRST_PAINT`, `firstAfter=true`, `firstFrame=false`, exact
  original bounds, unchanged completed-paint revision 3, and an otherwise
  clean scene. Independent postflight was clean. This identifies a different
  same-bounds no-op layout that did not schedule its first paint. The next
  step is a separate narrowly reviewed no-op redraw rule, not a repeated
  trial or a stock Nomad test. `away-back-aba` was not run after this UNKNOWN.

## 2026-09-29: unchanged-bounds first-paint candidate prepared

- The no-op layout now requests one redraw only after an exact verified
  `UNCHANGED` parent-return cut. A lookalike/replayed cut, an unverified
  layout, any other command, and a completed first paint cannot claim it.
  The no-extra-frame and distinct requested-paint gates remain intact.
- Offline checks passed: 112 Python observer tests, 13 JavaScript cases, and
  586/9/70 Java checks. Independent source review found no new blocker.
  The new unsigned emulator-only APK SHA-256 is
  `f4008244fd63aa2c67880022b9116e3e1441aff6db977e301d008a752b2bab60`;
  the signed APK SHA-256 is
  `e04e8bfbd42c058bdf59d8ccadad39e35b72e03a019f3f7aea81e594906b9b87`;
  and its one signer SHA-256 is
  `62c9966a8b614096cdc4949a25e93b394b8b03830ef221be8257677c69cf7be2`.
  Independent artifact review verified byte-identical manifest/DEX content,
  package isolation, no permissions or assets, and valid signature/alignment.
  No runtime result is claimed here until the reviewed emulator gate runs.

## 2026-09-29: exact final-build six-command emulator matrix

- The exact signed APK SHA-256
  `e04e8bfbd42c058bdf59d8ccadad39e35b72e03a019f3f7aea81e594906b9b87`
  was installed only on the verified API-30 x86_64 `emulator-5554`; the
  installed package hash matched before the matrix. No Nomad, PDF, annotation,
  pen, or original document was touched.
- Each command ran once in a fresh synthetic-app process. All six returned
  `PASS_SYNTHETIC_EDGE_ONLY`, `hookRemoved=true`,
  `postUnloadVerified=true`, `observationOnly=true`,
  `compositingAdmitted=false`, `completeMutationCoverage=false`, and
  `portRevision=-1`. Observed target-method entry counts were:

  | Command | Target entries |
  | --- | ---: |
  | `parent-plus-one` | 2 |
  | `parent-minus-one` | 2 |
  | `direct-root-layout` | 2 |
  | `direct-root-offset` | 1 |
  | `unchanged-bounds` | 1 |
  | `away-back-aba` | 2 |

- After **each** one-shot run, an independent postflight found no synthetic
  app PID, no Frida server PID, no ADB port forward, no staged server, and no
  observer lock. The final `direct-root-layout` run had incarnation
  `7019ffdc-e364-4811-9332-a1e5c9c2bde3` and received the same clean
  postflight. Earlier UNKNOWN observations above remain historical failures
  of earlier candidate builds; they are not retroactively reclassified.
- The final-build result establishes only that this disposable synthetic host
  observed its bounded layout/paint/rollback paths under the six named
  commands. It does **not** establish final e-ink pixels, stock Supernote
  reader behavior, complete mutation or paint-order authority, pen mapping,
  annotation persistence, or permission to insert a native visual child.
  Those require separately reviewed integration boundaries and a fresh
  reserved Nomad hardware gate.
