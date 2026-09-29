# Disposable Frida hook lifecycle probe

This is a local Windows-only Frida 17.9.11 experiment. The runtime probe
requires a separately built, local `fake_service.exe`; it never invokes a
compiler. It starts that exact child, checks the child-reported PID, and
attaches to that PID only. It never searches for or attaches to Nomad, stock
apps, or an emulator. No network access is needed.

Build the fake child explicitly from this directory using the local GCC:

```powershell
& 'C:\Strawberry\c\bin\gcc.exe' -O0 -Wall -Wextra -Werror .\fake_service.c -o .\fake_service.exe
```

Then run with the bundled Python:

```powershell
& 'C:\Users\mmkap\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe' .\run_probe.py
```

The runtime host starts its 25-second watchdog before file checks and Frida
import; on expiry it attempts exact-child cleanup with two bounded waits of up
to two seconds each. It records SHA-256 for the local regular, non-symlink
source, hook, and executable before and after a completed run. A pass means one JS
`Interceptor` callback was observed, the listener/script/session were
detached, and eight subsequent calls to the original setter succeeded with no
callback seen during the sentinel and a bounded 0.5-second quiet window. It
does **not** establish an unlimited absence of future callbacks, stock-reader
behavior, or native Gum C quiescence. An injection restriction or access denial
is a hard stop, not a reason to retry with broader privileges or another target.

The host also pins the SHA-256 of the reviewed local C source, JS hook, and
prebuilt Windows executable. Rebuilding with a different compiler or source
requires a new artifact review and an explicit pin update; matching hashes
identify this local test artifact but do not independently prove a portable,
reproducible build.
