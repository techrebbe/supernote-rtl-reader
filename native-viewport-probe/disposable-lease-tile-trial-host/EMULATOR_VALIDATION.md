# API-30 disposable tile trial — 2026-09-28

Scope: **emulator only** (`emulator-5554`, `ro.kernel.qemu=1`, API 30).
No Nomad, Supernote package, PDF, annotation, pen, network, or personal
document was accessed. This is a synthetic `FrameLayout` lifecycle test, not
proof that the stock reader admits a visual child or that a display pixel was
composited.

## Exact local package and checks

- Host evidence tests: `TILE_TRIAL_HOST_PASS checks=33`.
- Offline unsigned APK SHA-256:
  `3363feeaa3478ec43772c47dbf892589328ce32c5f75f8962b1c7555c5d8cac6`.
- Signed emulator APK SHA-256:
  `116bc147caef0ebdd985b692bd4c44d30e32b7cfa5ddd5fa31205530d7fd145d`.
- Ephemeral, two-day test certificate SHA-256:
  `eb6acc93f930792e815550025f8e90ff9586e87bfef06f17d67bdb63225b4a52`.
- Signature verification: v3 true, one signer. Emulator installation: `Success`.
- The app declares no permissions. Its package is
  `com.techrebbe.supernote.leasetiletrial`, distinct from the Nomad module.

## One-shot result

The first controller attempt used a PowerShell function that emitted both a
status line and the raw provider result. The caller treated the resulting
array as a failed `start-tile`, despite the app accepting and painting the
tile. The controller did not send `stop-tile`; the app's two-second expiry
removed the exact tile. Because the nine-child repaint completed after that
deadline, the app correctly reported `UNKNOWN/FRAME_AFTER_DEADLINE`. This is
**not** counted as a pass. It used a separate process incarnation and was not
retried in place.

After correcting the controller's response parsing, a fresh disposable app
process completed one explicit-stop trial:

| Evidence | Observation |
| --- | --- |
| Process | PID `14329`, incarnation `20501b11-acfd-409c-8d07-fb66bbc6c571` throughout |
| Activity/root | `29ac63ac-05a9-43d4-a136-55366475d952` / `1b5acd28-3242-4206-aced-755cc6d2cee4` throughout |
| Baseline | 9 structural children, 9 actual completed `drawChild` calls, paint revision 1 |
| Inserted | App-owned tile identity `10778471` at index 1; 10 structural children and 10 completed draws, revision 2 |
| Stopped | `stop-tile` accepted; exact tile removed; 9 structural children and 9 completed draws, revision 3 |
| Final | `RESTORED/EXACT_NINE_RESTORED_AFTER_TEN_PAINT`, original children exact, tile no longer parented |

The gapless event window for this incarnation was sequence 1–14. Relevant
monotonic timestamps (milliseconds) were: baseline paint `42611607`, expiry
armed `42612398` with deadline `42614398`, tile add `42612398`, expected
add-layout and ten-child paint `42612410`, explicit remove `42613506`, and
expected remove-layout plus restored nine-child paint `42613511`. The exact
removal and repaint completed before expiry; there was no `UNKNOWN` event.

Original child identity hashes in both baseline and restored cuts, in order:

`118555726,65194351,197772924,256604933,226301786,83660171,120245864,76399233,40193830`

The ten-child cut inserts only tile `10778471` after the first identity. A
second state read still reported the same PID/incarnation, `RESTORED`, nine
structural and nine painted children, and those same nine original identities.

An optional later screenshot attempt was refused before insertion because its
baseline paint was over the one-second freshness limit. The new process
reported `READY`, `startAttempted=false`, nine structural/nine painted
children, no tile parent, and no temporary screenshot file. It is not counted
as pixel evidence and was not retried in that process.

## Boundary

This passes the **isolated emulator view-lifecycle card**: an app-owned child
can be inserted at an exact index, painted, removed by exact reference, and
followed by a fresh matching paint without disturbing its nine synthetic
siblings. It does not prove stock Supernote paint order, e-ink composition,
input transparency, writer ownership, PDF page geometry, or `.mark` safety.
The already-consumed Nomad hierarchy-capture reservation is not renewed by
this result. Do not install this app on the Nomad.
