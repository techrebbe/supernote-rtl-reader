# Display-only hardware gate — 2026-09-06

**PASS for the bounded Android calibration/display gate only.** Native Document,
handwriting, tools, persisted annotation geometry and two live pages remain
unimplemented/unproven. Captured composition is not an e-ink latency measurement.

## Provenance

- Nomad `SN078C10015092`, Android 11 / API 30, 1404 x 1872, 300 dpi.
  Firmware: `Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys`.
- Native Document 1.02.446 / 102446; PID 2027 unchanged throughout.
- Separate probe `com.techrebbe.supernote.viewportdisplayprobe`, code 2,
  `0.0.2-display-only`; no permissions, native libraries, reader hooks,
  app-side root commands, Document launch, input forwarding or save operations.
- APK SHA-256: `afd5ac43c130dba466a4a569073e53bccbc3c34d496ff91106e0b51358fac0cc`.
- Temporary test-only signer certificate SHA-256:
  `b0a6859721488d06624a90e4c077fee7ad379ce638d65a6535910b0696be75eb`.
  No user keystore or credential upload was involved.
- All 20 source snapshot files matched before installation. Full updated r4
  independent review: no remaining actionable findings; 15 Python tests rerun
  independently in memory. Host: 280 viewport assertions, 45,459 layout/lifecycle
  assertions, Android build/package and all five repository baseline checks PASS
  (including 85,407 v2 core assertions and 271 mutations).

## Observations

Version 1 created a display but ordinary calibration launch was denied. It
released the display and was removed. Version 2 waited for an explicit root
launch of ONLY its own non-exported calibration, bound to the observed display
ID and live owner UUID. No Android security setting was weakened.

Instance `4f4250a7-cc33-452a-841a-576cd20994c1` owned display 2, host task 4498
and calibration task 4499. The calibration measured 1404 x 1872 (`canonical=true`).
These placements retained the same display/canvas/task:

| Physical layout | Frame: x, y, width, height |
| --- | --- |
| Portrait FULL | 0, 0, 1404, 1872 |
| Landscape LEFT | 0, 78, 936, 1248 |
| Landscape RIGHT | 936, 78, 936, 1248 |
| Landscape centered FULL | 409, 0, 1053, 1404 |
| Return to portrait | 0, 0, 1404, 1872 |

With controls hidden, all borders, labels and the circle were visible without
crop or apparent stretch. Before/after portrait PNGs were byte-identical:
`4bb496cc21fcface6b55e323e9fe24f45c65125795ce1f5c093a5189ab4bf6bd`.

- Duplicate valid root launch rejected; original task 4499 remained the only
  calibration. Wrong owner UUID also rejected without disturbing it.
- BACK on display 2 ended calibration, removed its task/display and reported
  `calibration ended; close and reopen probe to restart`. No task migrated to 0.
- Rotating the stopped host did not recreate a display.
- Explicit close/reopen created instance `e8aa7a4f-9511-4374-b3ff-60724c86d541`,
  display 3, host task 4502 and calibration task 4503; again 1404 x 1872.
- Closing that host with calibration still live removed both tasks/display and
  returned to File Manager. Only display 0 remained.

The deliberately rejected duplicate used `am start -W`, whose command-line
waiter did not return despite completed rejection. The local wait was interrupted
and only its identified remote `cmd activity start -W` client (PID 2300) was
terminated. Subsequent negative launch omitted `-W` and used log/task evidence.
No Document/DrawPath process was killed. Future negative launches must not use
unbounded `-W`. Restored-instance/process-death admission remains host-tested,
not separately hardware-tested by this batch.

## Restored state

The user's document was closed normally before installation. No reader module,
plugin or LSPosed configuration changed. Restored `accelerometer_rotation=1`,
`user_rotation=0`; temporary APK uninstalled; File Manager foreground.
No physical pen action occurred. Stock fixture hashes before/after matched:

- PDF: `e470c33c6525e02acf88e51352d73b7ed8b6c1591be8d40629a42c708484e720`.
- `.pdf.mark`: `b95c02b05abd9a4f5a3106ffbe442f1f893256a66f8cac3628f04d300992ffd6`.

Local ignored evidence: `build/display-hardware-20260906/` contains
`v2-probe-log.txt`, task/display cleanup dumps and portrait/left/right/centered
screenshots. Review: `../../reviews/native-viewport-display-20260906-r4/` and
adjacent `-review.log`, excluding device data and credentials.

## Next boundary

Retain this display/lifecycle primitive. Prepare and review ONE genuine native
Document adapter on a disposable original PDF, verifying native task/page/note
identity and one coherent frame for pen input, drawing and disabled regions.
The separate pen service is not redirected by this calibration result or by
consuming Android MotionEvents. Do not manually launch Document here and write.
No second live page or tool-specific coordinate correction is introduced.
