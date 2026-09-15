# Native page platform collector

## Result and boundary

`native-platform-collector/native_page_platform_collector.cpp` is a standalone
Android API-30/AArch64 executable for the frozen `--wire-v1` service. It accepts
exactly that one literal argument, never reads stdin or an environment value,
requires real/effective UID 2000, opens no writable file, and emits no diagnostic
text. Success writes one complete NPPCAP01 value to stdout and exits 0. Any
failure writes no collector bytes (unless the final stdout itself fails partway)
and exits 64 (invocation), 65 (wrong UID), 70 (capture/admission), or 71 (final
write). ADB shell-v2 therefore carries stdout, stderr, and exit status separately.

This is source/build evidence, not a Nomad hardware admission. No device was
contacted and no package, system partition, repository, or network state was
changed. The pinned firmware's literal raw `dumpsys` dialect and SELinux execute
label remain device-fixture gates described below.

## One bounded transaction

One retained parent process owns a 20-second `CLOCK_MONOTONIC` deadline. It uses
an exact absolute-path allowlist only:

- `/system/bin/getprop ro.serialno`
- `/system/bin/getprop ro.build.fingerprint`
- `/system/bin/cmd package path com.techrebbe.supernote.nativepagehost`
- `/system/bin/dumpsys activity activities`
- `/system/bin/dumpsys window windows`
- `/system/bin/dumpsys display`

Each child gets `/dev/null` as stdin, only its two private output pipes, a fixed
`PATH=/system/bin` and `LC_ALL=C`, and no inherited descriptor above 2. The
parent polls stdout/stderr concurrently, applies the member-specific byte limit,
kills and reaps only its own child on timeout, and rejects timeout, signal,
nonzero status, any stderr byte, missing EOF, NUL/CR/control bytes, missing final
LF, and oversized lines. It buffers all evidence before writing stdout.

Before the three manager reads, the parent binds the exact serial, boot UUID,
firmware fingerprint, PackageManager base-APK path, open-file identity and full
APK SHA-256, plus the complete relevant process set. It repeats all of those
facts afterward and requires exact equality. Relevant processes are discovered
directly from bounded `/proc` reads, not `ps`/`pidof`: exact cmdline, proc-dir UID,
PID, and `/proc/PID/stat` field 22. Secondary (`package:suffix`), duplicate,
raced, missing-host, reordered, or out-of-scope identities fail closed. The APK
is opened with `O_NOFOLLOW`, must be a bounded regular file, and its pinned full
digest cryptographically entails the emitted version/DEX/signer constants.

Every stage is checked against a nondecreasing monotonic timestamp and the one
deadline. The frozen NPPCAP01/process-facts grammar has no device timestamp
slot, so these values cannot be emitted without a wire revision; the existing
host transport still supplies its own `startedNs <= capturedNs <= finishedNs`
bracket around the entire shell-v2 operation.

## Normalized payloads and wire

The portable core parses only the pinned Android-11 source dialect and constructs
the exact downstream grammars. It filters to the two closed packages, requires
unique AM task/process/component/configuration/lifecycle evidence, requires each
WM window to carry an exact AM peer plus owner/frame/surface/buffer/focus facts,
and requires a complete logical-display inventory with a process-bound virtual
owner. Unsafe raw display unique IDs are represented as `sha256:<hex>` rather
than dropped. Missing, duplicate, contradictory, malformed, unexpected, or
oversized authority rejects the whole transaction.

The final bytes are exactly:

```text
NPPCAP01
tag 0x01 | u32be length | sha256(payload) | ActivityManager payload
tag 0x02 | u32be length | sha256(payload) | WindowManager payload
tag 0x03 | u32be length | sha256(payload) | process-facts payload
tag 0x04 | u32be length | sha256(payload) | DisplayManager payload
tag 0x00 | sha256(every preceding byte)
```

There are no separators/newlines outside the four member payloads. All four are
nonempty and bounded at 2 MiB, 2 MiB, 256 KiB, and 1 MiB respectively; the whole
wire is bounded at 8 MiB. The process payload is ASCII/LF and exactly matches
`_parse_process_facts` in `native_page_private_adb_platform_backend.py`, including
serial, boot UUID, sorted PID/start-ticks/UID/package rows, and the pinned host
package record.

## Reversible executable authority

Do not modify `/system`. Stage only after independent source review, then use
root once to create this fixed tree and atomically install the reviewed bytes:

```text
/data/local/native-page-platform-collector                 root:root 0555 directory
/data/local/native-page-platform-collector/v1              root:root 0555 directory
/data/local/native-page-platform-collector/v1/native-page-platform-collector
                                                            root:root 0555 regular file
```

Before installation, independently verify that `/data` and `/data/local` are
not shell-writable and that no path component is a symlink. After installation,
verify owner, group, mode, regular-file type, link count 1, SHA-256, and an SELinux
label that permits UID 2000 to execute/read but not write. Verify a UID-2000 open
for write and rename both fail. Removal by root restores the prior state; there
is no `/system` remount or persistent service registration.

For the current reproducible build, the executable is 1,599,768 bytes and SHA-256
`93e8b7fa474dd73411923cbd5182cb160bae1e490edbf224ac9e6d5ca77c022a`.
The build script recomputes this value and generates the service from it. The
proposed service is a fixed `/system/bin/sh` program which uses only absolute
`/system/bin/stat` and `/system/bin/sha256sum`, checks both controlled directories,
checks root/root/0555/regular/link-count-one file metadata, checks the expected
digest before execution, runs the fixed argument, then rechecks exact inode
metadata and digest before preserving the collector status. It produces no
wrapper stdout; a check failure is nonzero and any tool stderr also seals the
host transport.

The exact proposed `PLATFORM_CAPTURE_SERVICE` value is:

```text
shell,v2,raw:exec /system/bin/sh -c 'p=/data/local/native-page-platform-collector/v1/native-page-platform-collector;d0=/data/local/native-page-platform-collector;d1=/data/local/native-page-platform-collector/v1;want=93e8b7fa474dd73411923cbd5182cb160bae1e490edbf224ac9e6d5ca77c022a;z=0:0:555:directory;m0=$(/system/bin/stat -c %u:%g:%a:%F "$d0")||exit 120;m1=$(/system/bin/stat -c %u:%g:%a:%F "$d1")||exit 121;[ "$m0" = "$z" ]&&[ "$m1" = "$z" ]||exit 122;before=$(/system/bin/stat -c %u:%g:%a:%F:%h:%d:%i "$p")||exit 123;case "$before" in 0:0:555:regular\ file:1:*) ;; *) exit 124;;esac;sum=$(/system/bin/sha256sum "$p")||exit 125;[ "$sum" = "$want  $p" ]||exit 126;"$p" --wire-v1;rc=$?;after=$(/system/bin/stat -c %u:%g:%a:%F:%h:%d:%i "$p")||exit 127;endsum=$(/system/bin/sha256sum "$p")||exit 128;[ "$after" = "$before" ]&&[ "$endsum" = "$sum" ]||exit 129;exit "$rc"'
```

Its ASCII SHA-256, and therefore the required new
`PLATFORM_CAPTURE_SERVICE_SHA256`, is
`7bfefc9b933f4ca3fe359e07d1b6f15af092f57659b790d181c3b36ac14905e7`.

Hash-before-exec is not, by itself, atomic. Here, the checked root-owned 0555
directories remove rename/replacement authority from UID 2000; only already
trusted root can exploit the small hash/exec interval. Exact inode metadata and
digest after the child returns detect a root replacement during capture, and the
host rejects the otherwise complete stdout because shell-v2 status is nonzero.
This does not defend against malicious root, which is outside the runtime trust
boundary.

## Required existing-file integration changes

No existing file was edited by this work. Production remains fail closed until
these reviewed changes are made together:

1. In `native_page_private_adb.py`, replace
   `shell,v2,raw:exec /system/bin/native-page-platform-collector --wire-v1`
   with the exact hash/stat wrapper emitted as `proposedService` in
   `build-manifest.json`; update `PLATFORM_CAPTURE_SERVICE_SHA256` automatically
   from that literal. This removes the nonexistent `/system/bin` installation
   and binds the executable bytes.
2. Update the frozen-literal assertions in
   `test_native_page_private_adb_platform_backend.py` and add before/after
   hash/stat/status mutations. The backend itself needs no NPPCAP01 parser change
   for the present collector.
3. If device-side timestamps must be evidence rather than internal deadline
   checks, define NPPCAP02 (or a versioned process-facts header) with device
   `CLOCK_MONOTONIC` start/capture/finish fields, parse/bind them in
   `native_page_private_adb_platform_backend.py`, and add clock-order mutations.
   Adding lines to NPPCAP01 is impossible: its current process parser treats
   every line between package and `END` as a process row.

## Verification and remaining gates

Run `native-platform-collector/build-and-test.ps1 -Ndk <NDK-root>`. It compiles
and runs the portable tests, builds the API-30 AArch64 PIE twice, requires
byte-identical SHA-256, checks ELF64/little-endian/ET_DYN/AArch64 and a 4 MiB
bound, and writes an ignored `build-manifest.json` containing source hashes and
the exact proposed service/service digest. It never contacts a device.

The portable suite covers known SHA-256 vectors, exact successful normalization,
all member and aggregate digests, ordering, unsafe-display-ID binding, and
mutations for truncation, duplicated facts/focus/display/process identity,
borrowed PID/UID, invalid serial/boot, wrong APK, payload bits, and aggregate
digest bits.

Hardware admission still requires read-only captures of the three exact raw
Nomad outputs to confirm the deliberately narrow source dialect—especially WM
`mSurfaceFrame`/`mBufferSize` and DisplayInfo owner/flag spellings—plus a check of
`cmd package path`, `/proc` visibility under UID 2000, toybox `stat` formatting,
SELinux execution from the proposed directory, and shell-v2 exit/stderr behavior.
Any literal difference is a parser review/change, never a permissive fallback.
