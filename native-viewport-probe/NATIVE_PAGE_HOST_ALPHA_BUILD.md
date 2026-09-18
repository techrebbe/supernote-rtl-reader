# Native Page Host local alpha build

This is a deliberately narrow local path for installing the visual-only native
page host while the hardware concept is still being tested. It does not change
`build-native-page-host.ps1`, its two-pass reproducible unsigned APK, its
`package-authority.json`, or any formal release gate.

The build helper first completes that authoritative unsigned build and validates
the emitted APK against its adjacent authority record. Only then does it create
a separate signed copy. The deterministic local outputs are:

- `build/native-page-host-alpha/native-page-host-alpha.apk`
- `build/native-page-host-alpha/native-page-host-alpha.json`

Both are ignored local artifacts. The signed APK is not a release artifact and
never becomes compiler-output authority. The helpers and runner independently
pin the actual APK, signer, package/version, embedded DEX, reviewed unsigned APK,
and reviewed unsigned authority; the adjacent JSON is a record, not an authority.

The fixed local alpha identities are:

- signed APK SHA-256: `3798c204360db82941db7516e774517b273a51e025cce4848a642a5de61c6a03`
- signer certificate SHA-256: `d3f9ce76640125df1037e4536b680e29684da5ae7c171147f3206e26c7e568b4`
- package/version: `com.techrebbe.supernote.nativepagehost`, version code `2`,
  version name `0.0.2-native-page-visual-only`
- reviewed unsigned APK SHA-256: `670c755fabb00df87c6b6714c3dc8b878aa22e3190d95585b24adce295756178`
- reviewed package-authority SHA-256: `94783276471ad4797b9a4ebf2200ae7adfd1ce1fe6ad888e2b5df09b403cb647`
- embedded DEX SHA-256: `15d24cef8f4c70cf167ab6e93ac817fc2e85af4bfca6bb392e2535dc04863ab6`

For this disposable probe the helper materializes only the native-page-host
inputs from checkpoint `2eeadd701d25dfeaf978108c358326e8edfaf87d`, with the
repository's LF bytes, into a private temporary directory. This avoids Windows
checkout line-ending drift without editing the reviewed source or accepting
working-tree substitutions. The formal build still compiles twice and must
reproduce those exact unsigned APK and DEX bytes before local signing is allowed.

## Build and sign

From `native-viewport-probe`:

```powershell
.\build-native-page-host-alpha.ps1
```

The already-established, test-only signing identity lives beneath the current
Windows user's local application-data folder. Its random password is stored only
as a Windows user-protected DPAPI envelope. No password is accepted on the
command line, printed, stored in the repository, or uploaded. The helper pins
both its certificate and the final signed bytes, invokes the pinned
`apksigner.jar` directly through the pinned `java.exe`, and removes JVM launch
injection variables around every keytool/sign/verify operation.

The identity and output paths must have no symlink, junction, or other reparse
component. Deleting or losing the local identity is a hard stop: the helper does
not generate or rotate a signer that would invalidate the fixed APK authority.

## Install or update one explicit device

Use the one-click coordinator, which creates and retains the required session
lock across install, execution, verified cleanup, and any fresh-package rollback:

```powershell
.\run-native-page-alpha.ps1 -Serial SN078C10015092
```

The installer validates the local APK and metadata before contacting the device.
It admits only serial `SN078C10015092`, model `Supernote Nomad`, Android SDK `30`,
owner user `0`,
and firmware fingerprint
`Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys`.
It also requires the wrapper's live exclusive per-device session lock at
`%LOCALAPPDATA%\SupernoteAlpha\NativePageHostLocks\SN078C10015092\session.lock`
and requires that no host process, task, or package-owned display is live.

If the exact APK is already installed, the helper makes no package change. If
the package is absent, it installs the alpha. A fresh install requires a later
uninstall to restore the prior absent-package state; this helper never uninstalls.
On the pinned Nomad firmware, `pm path` reports that absence as exit code `1`
with zero output lines. The installer admits only that exact absent tuple;
exit code `0` requires exactly one canonical `package:/.../base.apk` line, and
all other status/output combinations fail before installation.
If a different older alpha with the same pinned signer is present, replacement
requires direct manual use of the installer with both the same live session lock
and the explicit `-AllowPersistentUpgrade` switch. The one-click coordinator
never authorizes that mode.

That update is upgrade-compatible, but it is intentionally classified as not
exact rollback: neither the older APK nor any app-data migration is restored.
Without that explicit authorization the helper stops before changing the device.
It also refuses a mismatched signer or downgrade.

After an install, the helper reads the installed base APK back and requires the
exact APK hash, signer, package, version code, and version name. It never clears
data, grants permissions, launches the host, starts Document, or changes device
settings.

Installation merely prepares the visual host. The separate alpha runner owns
the bounded launch/attach/cleanup session; neither helper claims a native reader,
pen, save, exact device rollback, or hardware pass.

## Focused checks

```powershell
python .\test_native_page_host_alpha_helpers.py
```

These checks parse both PowerShell helpers, verify the published APK/DEX and
metadata against independent fixed authority, execute the hostile-JVM-environment
signing path, exercise exclusive-lock rejection, exercise identity/output
junction rejection, and retain checks for the no-uninstall/data-clear/downgrade
boundary.
