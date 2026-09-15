param([Parameter(Mandatory=$true)][string]$Ndk)
$entryScriptHandle = [IO.FileStream]::new($PSCommandPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
try {
# The reviewed caller remains the trust root for selecting/invoking this script.
# This first-statement handle binds evidence to entry-time bytes; it cannot
# authenticate the already-parsed program by making a circular self-claim.
$entryScriptPath = [IO.Path]::GetFullPath($PSCommandPath)
$entryHasher = [Security.Cryptography.SHA256]::Create()
try {
    $entryScriptSha256 = [Convert]::ToHexString($entryHasher.ComputeHash($entryScriptHandle)).ToLowerInvariant()
    $entryScriptHandle.Position = 0
} finally { $entryHasher.Dispose() }
$ErrorActionPreference = 'Stop'

# A concurrent runspace attempts write and replacement-prerequisite DELETE
# access to the live script. No bytes are written and no rename is performed,
# even if the protection fails; such a failure aborts the build immediately.
$entryProbe = [PowerShell]::Create()
try {
    [void]$entryProbe.AddScript({
        param($path)
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class PenLeaseEntryProbe {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern SafeFileHandle CreateFileW(string path, uint access,
        uint share, IntPtr security, uint creation, uint flags, IntPtr template);
}
'@
        foreach ($access in @([uint32]0x40000000,[uint32]0x00010000)) {
            $handle = [PenLeaseEntryProbe]::CreateFileW($path,$access,7,[IntPtr]::Zero,3,0,[IntPtr]::Zero)
            $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            try { if (-not $handle.IsInvalid -or $errorCode -ne 32) { throw 'Entry script write/replacement protection failed' } }
            finally { $handle.Dispose() }
        }
        'ENTRY_WRITE_AND_REPLACEMENT_DENIED'
    }).AddArgument($entryScriptPath)
    $entryProbeAsync = $entryProbe.BeginInvoke()
    $entryProbeResult = @($entryProbe.EndInvoke($entryProbeAsync))
    if ($entryProbe.HadErrors -or $entryProbeResult.Count -ne 1 -or
            $entryProbeResult[0] -cne 'ENTRY_WRITE_AND_REPLACEMENT_DENIED') {
        throw 'Concurrent entry-script replacement regression failed'
    }
} finally { $entryProbe.Dispose() }

# The Windows launcher is authenticated and retained before the first Linux
# ELF. Host diagnostics trust the Windows/WSL service and kali-linux bootstrap;
# Linux tool/DSO endpoint scans below are observations, not retained authority.
$wslLauncher = 'C:\Windows\System32\wsl.exe'
$wslDistribution = 'kali-linux'
$expectedWslLauncherSha256 = '27CC8DD52BE326E138A89F8889241B1D8C51DD1978B22EB70BE77036CCDEE3C2'
$wslLauncherLock = [IO.FileStream]::new($wslLauncher,[IO.FileMode]::Open,
    [IO.FileAccess]::Read,[IO.FileShare]::Read)
$wslLauncherSignature = Get-AuthenticodeSignature -LiteralPath $wslLauncher
if ($wslLauncherSignature.Status -ne 'Valid' -or
        $wslLauncherSignature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation' -or
        (Get-FileHash -Algorithm SHA256 -LiteralPath $wslLauncher).Hash -cne $expectedWslLauncherSha256) {
    $wslLauncherLock.Dispose()
    throw 'Exact System32 WSL launcher authentication failed'
}
function Invoke-WslExact([string[]]$Arguments) {
    $launch = [Diagnostics.ProcessStartInfo]::new()
    $launch.FileName = $wslLauncher
    $launch.UseShellExecute = $false
    $launch.CreateNoWindow = $true
    $launch.RedirectStandardOutput = $true
    $launch.RedirectStandardError = $true
    # Nothing inherited can reach wsl.exe or the first Linux ELF via WSLENV.
    # In particular PATH, LD_*, GLIBC_TUNABLES, BASH_ENV and ENV are absent.
    $launch.Environment.Clear()
    foreach ($entry in @{SystemRoot='C:\Windows';WINDIR='C:\Windows';SystemDrive='C:'}.GetEnumerator()) {
        $launch.Environment[$entry.Key] = $entry.Value
    }
    foreach ($argument in @('--distribution',$wslDistribution,'--exec',
            '/usr/bin/env','-i','PATH=/usr/bin:/bin','LC_ALL=C','LANG=C','TZ=UTC') + $Arguments) {
        $launch.ArgumentList.Add($argument)
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $launch
    try {
        if (-not $process.Start()) { throw 'Exact WSL launch failed' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $script:LASTEXITCODE = $process.ExitCode
        $errorText = $stderr.GetAwaiter().GetResult()
        if ($errorText.Length -gt 0) { [Console]::Error.Write($errorText) }
        $outputText = $stdout.GetAwaiter().GetResult()
        if ($outputText.Length -gt 0) { $outputText.TrimEnd("`r","`n") -split '\r?\n' }
    } finally { $process.Dispose() }
}

# Hostile parent environment must not change launcher selection, distro,
# bootstrap loader inputs, or the clean environment visible to the test ELF.
$hostileNames = @('PATH','WSLENV','LD_PRELOAD','LD_AUDIT','LD_LIBRARY_PATH','GLIBC_TUNABLES')
$hostileSaved = @{}
try {
    foreach ($name in $hostileNames) {
        $hostileSaved[$name] = [Environment]::GetEnvironmentVariable($name,'Process')
        [Environment]::SetEnvironmentVariable($name,'/pen-lease-hostile-must-not-load','Process')
    }
    [Environment]::SetEnvironmentVariable('WSLENV','LD_PRELOAD/u:LD_AUDIT/u:LD_LIBRARY_PATH/u:PATH/p','Process')
    $cleanProbe = @(Invoke-WslExact -Arguments @('/usr/bin/env'))
    if ($LASTEXITCODE -ne 0 -or $cleanProbe.Count -ne 4 -or
            @($cleanProbe | Where-Object { $_ -notin @('PATH=/usr/bin:/bin','LC_ALL=C','LANG=C','TZ=UTC') }).Count -ne 0) {
        throw 'Hostile PATH/WSLENV/loader-environment regression failed'
    }
} finally {
    foreach ($name in $hostileNames) {
        [Environment]::SetEnvironmentVariable($name,$hostileSaved[$name],'Process')
    }
}

$expectedRevision = '27.0.12077973'
$expectedClangSha256 = '83BA04EC516C95AAFF278319C36CD928B7B005F5C9CDEF5ED0926E979665811D'
$expectedDriverSha256 = '9E73A92FF2B8447E59D6D82AACDD9ED135F60DC65EC3A045D60A7B626703D16D'
$expectedNdkFileCount = 7936
$expectedNdkByteCount = [uint64]2361027326
$expectedNdkManifestSha256 = '3EDBD1488372DD8D5C3CC27EDE8B420509B48E832453C02F97C881640F0E637D'
$expectedWslManifestLineCount = 4686
$expectedWslManifestByteCount = 481547
$expectedWslManifestSha256 = '54C607ED41A1C58EC2C59A87CFEA1693BB8463ACE18ABD20E40C13E682E10FB6'
$expectedWslLoaderStateLineCount = 7
$expectedWslLoaderStateByteCount = 625
$expectedWslLoaderStateSha256 = 'E26393CA97717C965C443D89DF6F64F2A6172D8BBC7F491E7771730D40131AA9'
$expectedWslRuntimeLineCount = 181
$expectedWslRuntimeByteCount = 25053
$expectedWslRuntimeSha256 = '0B731FE639FF98827470DF64311221957466DA2B2E33C3EF76C798F318EC63ED'
$expectedWslLoader = '/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2'
$expectedWslCc = '/usr/bin/x86_64-linux-gnu-gcc-15'
$expectedWslCcSha256 = '952B3C58DC156504E8394C7F41988A3FE503F7707B7A6ECCE727E714976A4BD3'
$expectedWslCcVersion = '15.2.0'
$expectedWslTarget = 'x86_64-linux-gnu'
$expectedAndroidArtifactSha256 = [ordered]@{
    'pen-input-lease' = '32E17E2DEAAE42EBEAC82BE358BE2FBD3689E91A3B72BA956C741F13D29AE068'
    'pen-input-lease-core-test-android' = 'C8D8CA3D1455130C7EEC9B8CF95D1E783E874BABEEE1E9976DC206DCF5F1DB38'
    'pen-input-lease-adapter-test-android' = 'E13D71DCDD9610D53856A457FD91C4B9DD56D5BA6F95ECFA25CAB31F3388A9C6'
}
$expectedHostArtifactSha256 = [ordered]@{
    'pen-input-lease-host' = 'FADA9923BBFED7A79911AB8A4E56FEE9E96EF5B4860D88558BBDCA9788D1D0E9'
    'pen-input-lease-core-test' = '9454B4215ED1941CA344C7F40245CFD5974EBBC7F52AF3FFC3E09C66B91E4FF5'
    'pen-input-lease-adapter-test' = 'F0A6D52B7B76D9687B30A9EE2AF91716AE9F936AE003BEEFC7DC621B4C1B5398'
}
$expectedSanitizerArtifactSha256 = [ordered]@{
    'pen-input-lease-host-asan' = 'BF83BF2FBEBDF75E9D3F6C180EFCCDA4BDB1F14E27CBB44D3D6DBCC5B088055C'
    'pen-input-lease-core-test-asan' = '438FEB503D476A842345CDADE350320F1B057C7AA80E294971905662567342AA'
    'pen-input-lease-adapter-test-asan' = '124506A19A875FCDFB96D746AD36ED90BEEC09003C683B327074F6138F7FFD8D'
}

function Test-ExactClosure([int]$actualCount,[uint64]$actualBytes,[string]$actualHash,
        [int]$expectedCount,[uint64]$expectedBytes,[string]$expectedHash) {
    return $actualCount -eq $expectedCount -and $actualBytes -eq $expectedBytes -and
        $actualHash -ceq $expectedHash
}

# Prove the comparison itself fails closed for each independently authenticated
# field before it is used for either toolchain.
if ((Test-ExactClosure $expectedNdkFileCount $expectedNdkByteCount $expectedNdkManifestSha256 `
        ($expectedNdkFileCount + 1) $expectedNdkByteCount $expectedNdkManifestSha256) -or
    (Test-ExactClosure $expectedNdkFileCount $expectedNdkByteCount $expectedNdkManifestSha256 `
        $expectedNdkFileCount ($expectedNdkByteCount + 1) $expectedNdkManifestSha256) -or
    (Test-ExactClosure $expectedNdkFileCount $expectedNdkByteCount $expectedNdkManifestSha256 `
        $expectedNdkFileCount $expectedNdkByteCount ('0' + $expectedNdkManifestSha256.Substring(1)))) {
    throw 'Toolchain closure mutation self-test failed'
}
$resolvedNdk = (Resolve-Path -LiteralPath $Ndk).Path
if ((Split-Path -Leaf $resolvedNdk) -ne $expectedRevision) {
    throw "NDK directory is not the pinned revision $expectedRevision"
}
$properties = Join-Path $resolvedNdk 'source.properties'
$clang = Join-Path $resolvedNdk 'toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe'
$driver = Join-Path $resolvedNdk 'toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android30-clang.cmd'
foreach ($required in @($properties,$clang,$driver)) {
    if (!(Test-Path -LiteralPath $required -PathType Leaf)) { throw "Required pinned NDK file is unavailable: $required" }
}
$revisionLine = @(Get-Content -LiteralPath $properties | Where-Object { $_ -match '^Pkg\.Revision\s*=' })
if ($revisionLine.Count -ne 1 -or (($revisionLine[0] -split '=',2)[1].Trim()) -ne $expectedRevision) {
    throw 'Pinned NDK source.properties revision mismatch'
}
$clangSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $clang).Hash
$driverSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $driver).Hash
if ($clangSha256 -ne $expectedClangSha256 -or $driverSha256 -ne $expectedDriverSha256) {
    throw 'Pinned NDK compiler provenance mismatch'
}

$out = Join-Path $PSScriptRoot ('build/pen-input-lease-' + [guid]::NewGuid().ToString('N'))
$hostOut = Join-Path $out 'host'
$snapshotRoot = Join-Path $out 'immutable-source-snapshot'
New-Item -ItemType Directory -Path $hostOut,$snapshotRoot -Force | Out-Null
$nativeOriginal = Join-Path $PSScriptRoot 'native'
$inputs = [ordered]@{
    'native/pen_input_lease.c' = (Join-Path $nativeOriginal 'pen_input_lease.c')
    'native/pen_input_lease_core.h' = (Join-Path $nativeOriginal 'pen_input_lease_core.h')
    'native/pen_input_lease_core_test.c' = (Join-Path $nativeOriginal 'pen_input_lease_core_test.c')
    'native/pen_input_lease_adapter_test.c' = (Join-Path $nativeOriginal 'pen_input_lease_adapter_test.c')
    'build-pen-input-lease.ps1' = (Join-Path $PSScriptRoot 'build-pen-input-lease.ps1')
}
$snapshotLocks = [Collections.Generic.List[IO.FileStream]]::new()
$ndkLocks = [Collections.Generic.List[IO.FileStream]]::new()
$snapshotHashes = [ordered]@{}
$ndkManifestPath = Join-Path $out 'pinned-ndk-file-manifest.tsv'
$wslManifestPath = Join-Path $out 'pinned-wsl-host-toolchain-manifest.tsv'
$wslLoaderStatePath = Join-Path $out 'pinned-wsl-loader-state-manifest.tsv'
$wslRuntimePath = Join-Path $out 'pinned-wsl-runtime-resolution-manifest.tsv'

$compilerEnvironmentNames = @(
    'CPATH','C_INCLUDE_PATH','CPLUS_INCLUDE_PATH','OBJC_INCLUDE_PATH',
    'LIBRARY_PATH','COMPILER_PATH','GCC_EXEC_PREFIX','CCC_OVERRIDE_OPTIONS',
    'GCC_SPECS','DEPENDENCIES_OUTPUT','SUNPRO_DEPENDENCIES',
    'CLANG_CONFIG_FILE_SYSTEM_DIR','CLANG_CONFIG_FILE_USER_DIR','INCLUDE','LIB','CL','_CL_'
)
$savedCompilerEnvironment = [ordered]@{}
foreach ($name in $compilerEnvironmentNames) {
    $savedCompilerEnvironment[$name] = [Environment]::GetEnvironmentVariable($name,'Process')
    Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
}

try {
    # Authenticate and lock an exact allowlist of the entire pinned NDK. This
    # intentionally covers more than the dependency subset reported by clang:
    # every possible NDK-resident driver, linker, resource header, sysroot CRT,
    # header, and library is either in this manifest or compilation fails.
    $ndkItems = @(Get-ChildItem -LiteralPath $resolvedNdk -Recurse -Force)
    if (@($ndkItems | Where-Object {
            ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
        }).Count -ne 0) {
        throw 'Pinned NDK contains a reparse point'
    }
    $ndkPaths = @($ndkItems | Where-Object { -not $_.PSIsContainer } |
        ForEach-Object { $_.FullName })
    [Array]::Sort($ndkPaths,[StringComparer]::Ordinal)
    $ndkManifest = [Text.StringBuilder]::new()
    [uint64]$ndkBytes = 0
    foreach ($path in $ndkPaths) {
        $relative = [IO.Path]::GetRelativePath($resolvedNdk,$path).Replace('\','/')
        if ($relative.IndexOfAny([char[]]@("`t","`r","`n")) -ge 0) {
            throw 'Pinned NDK contains a non-canonical path'
        }
        $lock = [IO.FileStream]::new($path,[IO.FileMode]::Open,
            [IO.FileAccess]::Read,[IO.FileShare]::Read)
        $ndkLocks.Add($lock)
        $length = [uint64]$lock.Length
        $ndkBytes += $length
        $hasher = [Security.Cryptography.SHA256]::Create()
        try {
            $hash = [Convert]::ToHexString($hasher.ComputeHash($lock))
            $lock.Position = 0
        } finally {
            $hasher.Dispose()
        }
        [void]$ndkManifest.Append($relative).Append("`t").Append($length).
            Append("`t").Append($hash.ToLowerInvariant()).Append("`n")
    }
    $ndkManifestText = $ndkManifest.ToString()
    $ndkManifestHash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes($ndkManifestText)))
    if (-not (Test-ExactClosure $ndkPaths.Count $ndkBytes $ndkManifestHash `
            $expectedNdkFileCount $expectedNdkByteCount $expectedNdkManifestSha256)) {
        throw "Pinned NDK closure mismatch: files=$($ndkPaths.Count) bytes=$ndkBytes hash=$ndkManifestHash"
    }
    [IO.File]::WriteAllText($ndkManifestPath,$ndkManifestText,[Text.UTF8Encoding]::new($false))

    # Copy every exact source/header/test input once while denying writers and
    # deletion. Then retain read-sharing-only handles to the private snapshot
    # for the entire build, so Windows/DrvFS cannot replace or mutate compiler,
    # test, or attestation inputs after their hashes become authoritative.
    foreach ($entry in $inputs.GetEnumerator()) {
        $sourceItem = Get-Item -LiteralPath $entry.Value -Force
        if ($sourceItem.PSIsContainer -or
                (($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            throw "Unsafe source input: $($entry.Key)"
        }
        $destination = Join-Path $snapshotRoot $entry.Key
        New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
        $isEntryScript = $entry.Key -ceq 'build-pen-input-lease.ps1'
        $sourceHandle = if ($isEntryScript) { $entryScriptHandle } else {
            [IO.FileStream]::new($sourceItem.FullName,[IO.FileMode]::Open,
                [IO.FileAccess]::Read,[IO.FileShare]::Read)
        }
        $sourceHandle.Position = 0
        try {
            $destinationHandle = [IO.FileStream]::new($destination,[IO.FileMode]::CreateNew,
                [IO.FileAccess]::Write,[IO.FileShare]::None)
            try {
                $sourceHandle.CopyTo($destinationHandle)
                $destinationHandle.Flush($true)
            } finally {
                $destinationHandle.Dispose()
            }
        } finally {
            if (-not $isEntryScript) { $sourceHandle.Dispose() }
        }
        $lock = [IO.FileStream]::new($destination,[IO.FileMode]::Open,
            [IO.FileAccess]::Read,[IO.FileShare]::Read)
        $snapshotLocks.Add($lock)
        $hasher = [Security.Cryptography.SHA256]::Create()
        try {
            $snapshotHashes[$entry.Key] = ([Convert]::ToHexString(
                $hasher.ComputeHash($lock))).ToLowerInvariant()
            $lock.Position = 0
        } finally {
            $hasher.Dispose()
        }
        if ($isEntryScript -and $snapshotHashes[$entry.Key] -cne $entryScriptSha256) {
            throw 'Build snapshot differs from retained entry-time script bytes'
        }
    }

    $native = Join-Path $snapshotRoot 'native'
    $productionSource = Join-Path $native 'pen_input_lease.c'
    $coreSource = Join-Path $native 'pen_input_lease_core_test.c'
    $adapterSource = Join-Path $native 'pen_input_lease_adapter_test.c'
    $headerSource = Join-Path $native 'pen_input_lease_core.h'

$androidCommon = @(
    '--no-default-config','-std=c11','-O2','-Wall','-Wextra','-Werror',
    '-fstack-protector-strong','-D_FORTIFY_SOURCE=2','-fPIE','-pie',
    '-Wl,-z,relro,-z,now','-Wl,--fatal-warnings',
    "-ffile-prefix-map=$snapshotRoot=/rtl-reader-pen-lease-source",
    "-fdebug-prefix-map=$snapshotRoot=/rtl-reader-pen-lease-source",
    "-fmacro-prefix-map=$snapshotRoot=/rtl-reader-pen-lease-source"
)
function Invoke-AndroidCompile([string]$source,[string]$destination,[string[]]$extra=@()) {
    & $driver @androidCommon @extra $source -o $destination
    if ($LASTEXITCODE -ne 0) { throw "Android compilation failed: $source" }
}
$androidProduction = Join-Path $out 'pen-input-lease'
$androidCore = Join-Path $out 'pen-input-lease-core-test-android'
$androidAdapter = Join-Path $out 'pen-input-lease-adapter-test-android'
Invoke-AndroidCompile $productionSource $androidProduction
Invoke-AndroidCompile $coreSource $androidCore
Invoke-AndroidCompile $adapterSource $androidAdapter @('-Wno-unused-function')

# Compile the same exact inputs again and require byte-for-byte deterministic artifacts.
$repeatProduction = Join-Path $out 'pen-input-lease.repeat'
$repeatCore = Join-Path $out 'pen-input-lease-core-test-android.repeat'
$repeatAdapter = Join-Path $out 'pen-input-lease-adapter-test-android.repeat'
Invoke-AndroidCompile $productionSource $repeatProduction
Invoke-AndroidCompile $coreSource $repeatCore
Invoke-AndroidCompile $adapterSource $repeatAdapter @('-Wno-unused-function')
foreach ($pair in @(@($androidProduction,$repeatProduction),@($androidCore,$repeatCore),@($androidAdapter,$repeatAdapter))) {
    $first = (Get-FileHash -Algorithm SHA256 -LiteralPath $pair[0]).Hash
    $second = (Get-FileHash -Algorithm SHA256 -LiteralPath $pair[1]).Hash
    if ($first -ne $second) { throw "Non-deterministic Android build: $($pair[0])" }
}
$androidIdentityMismatches = [Collections.Generic.List[string]]::new()
foreach ($artifact in @($androidProduction,$androidCore,$androidAdapter)) {
    $name = Split-Path -Leaf $artifact
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifact).Hash
    if (-not $expectedAndroidArtifactSha256.Contains($name) -or
            $actual -cne $expectedAndroidArtifactSha256[$name]) {
        $androidIdentityMismatches.Add("$name=$actual")
    }
}
if ($androidIdentityMismatches.Count -ne 0) {
    throw "Cross-invocation Android identity mismatch: $($androidIdentityMismatches -join '; ')"
}

# Host safety tests are platform-runtime-trusted diagnostics, not hermetic
# evidence. Package/loader files are observed before and after use but Linux
# handles do not retain those namespaces against mutation during execution.
$wslPackages = @(
    'binutils','binutils-common','binutils-x86-64-linux-gnu',
    'coreutils','dash','debianutils','dpkg',
    'cpp-15','cpp-15-x86-64-linux-gnu','gcc','gcc-15','gcc-15-base',
    'gcc-15-x86-64-linux-gnu','libacl1','libasan8','libatomic1','libattr1','libbinutils',
    'libbz2-1.0','libc6','libc6-dev','libcap2','libcc1-0','libctf-nobfd0','libctf0',
    'libgcc-15-dev','libgcc-s1','libgmp10','libgomp1','libisl23',
    'libjansson4','liblsan0','liblzma5','libmd0','libmpc3','libmpfr6',
    'libpcre2-8-0','libquadmath0','libselinux1','libsframe3','libssl3t64',
    'libstdc++6','libsystemd0','libtsan2','libubsan1','libzstd1',
    'linux-libc-dev','openssl-provider-legacy','tar','zlib1g'
)
$wslManifestScript = 'set -eu; PATH=/usr/bin:/bin; export PATH; { for package do /usr/bin/dpkg-query -W -f="P\t\${binary:Package}\t\${Version}\n" "$package"; done; /usr/bin/dpkg-query -L "$@" | LC_ALL=C /usr/bin/sort -u | while IFS= read -r path; do if [ -L "$path" ]; then printf "L\t%s\t%s\n" "$path" "$(/usr/bin/readlink -- "$path")"; elif [ -f "$path" ]; then printf "F\t%s\t%s\t%s\n" "$path" "$(/usr/bin/stat -c %s -- "$path")" "$(/usr/bin/sha256sum -- "$path" | /usr/bin/cut -d" " -f1)"; elif [ -e "$path" ] && [ ! -d "$path" ]; then exit 71; fi; done; } | LC_ALL=C /usr/bin/sort'
function Get-WslToolchainManifest {
    $lines = @(Invoke-WslExact (@('/usr/bin/dash','-c',$wslManifestScript,'dash') + $wslPackages))
    if ($LASTEXITCODE -ne 0) { throw 'WSL host-toolchain manifest generation failed' }
    $text = [string]::Join("`n",$lines) + "`n"
    $bytes = [Text.Encoding]::UTF8.GetBytes($text)
    return [PSCustomObject]@{
        Lines = $lines.Count
        Bytes = $bytes.Length
        Sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
        Text = $text
    }
}
$wslManifest = Get-WslToolchainManifest
if (-not (Test-ExactClosure $wslManifest.Lines $wslManifest.Bytes $wslManifest.Sha256 `
        $expectedWslManifestLineCount $expectedWslManifestByteCount $expectedWslManifestSha256)) {
    throw "WSL host-toolchain closure mismatch: lines=$($wslManifest.Lines) bytes=$($wslManifest.Bytes) hash=$($wslManifest.Sha256)"
}
[IO.File]::WriteAllText($wslManifestPath,$wslManifest.Text,[Text.UTF8Encoding]::new($false))

# These loader-state observations can detect drift, not prove its absence
# between scans. The first checker ELF already trusts the WSL/distro bootstrap.
$wslLoaderStateScript = 'set -eu; PATH=/usr/bin:/bin; LC_ALL=C; LANG=C; export PATH LC_ALL LANG; if [ -e /etc/ld.so.preload ] || [ -L /etc/ld.so.preload ]; then exit 73; fi; set -- /etc/ld.so.conf.d/*; [ "$#" -eq 4 ] && [ "$1" = /etc/ld.so.conf.d/fakeroot-x86_64-linux-gnu.conf ] && [ "$2" = /etc/ld.so.conf.d/ld.wsl.conf ] && [ "$3" = /etc/ld.so.conf.d/libc.conf ] && [ "$4" = /etc/ld.so.conf.d/x86_64-linux-gnu.conf ] || exit 74; printf "A\t/etc/ld.so.preload\n"; for path in /etc/ld.so.cache /etc/ld.so.conf "$@"; do [ -f "$path" ] && [ ! -L "$path" ] || exit 75; printf "F\t%s\t%s\t%s\n" "$path" "$(/usr/bin/stat -c %s -- "$path")" "$(/usr/bin/sha256sum -- "$path" | /usr/bin/cut -d" " -f1)"; done'
function Get-WslLoaderStateManifest {
    $lines = @(Invoke-WslExact -Arguments @('/usr/bin/dash','-c',$wslLoaderStateScript))
    if ($LASTEXITCODE -ne 0) { throw 'WSL loader-state manifest generation failed' }
    $text = [string]::Join("`n",$lines) + "`n"
    $bytes = [Text.Encoding]::UTF8.GetBytes($text)
    return [PSCustomObject]@{
        Lines = $lines.Count
        Bytes = $bytes.Length
        Sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
        Text = $text
    }
}
$wslLoaderState = Get-WslLoaderStateManifest
if (-not (Test-ExactClosure $wslLoaderState.Lines $wslLoaderState.Bytes `
        $wslLoaderState.Sha256 $expectedWslLoaderStateLineCount `
        $expectedWslLoaderStateByteCount $expectedWslLoaderStateSha256)) {
    throw "WSL loader state mismatch: lines=$($wslLoaderState.Lines) bytes=$($wslLoaderState.Bytes) hash=$($wslLoaderState.Sha256)"
}
[IO.File]::WriteAllText($wslLoaderStatePath,$wslLoaderState.Text,
    [Text.UTF8Encoding]::new($false))

$wslOwnedFiles = [Collections.Generic.Dictionary[string,object]]::new(
    [StringComparer]::Ordinal)
foreach ($line in $wslManifest.Text.Split("`n",[StringSplitOptions]::RemoveEmptyEntries)) {
    $fields = $line.Split("`t")
    if ($fields.Count -eq 4 -and $fields[0] -ceq 'F') {
        if ($wslOwnedFiles.ContainsKey($fields[1])) {
            throw "Duplicate WSL package-file authority: $($fields[1])"
        }
        $wslOwnedFiles.Add($fields[1],[PSCustomObject]@{
            Bytes = [uint64]::Parse($fields[2],[Globalization.CultureInfo]::InvariantCulture)
            Sha256 = $fields[3].ToUpperInvariant()
        })
    }
}
if (-not $wslOwnedFiles.ContainsKey($expectedWslLoader)) {
    throw 'Pinned WSL dynamic loader is outside the package-file closure'
}
$wslCc = @(Invoke-WslExact -Arguments @('/usr/bin/readlink','-f','/usr/bin/cc'))
if ($LASTEXITCODE -ne 0 -or $wslCc.Count -ne 1 -or $wslCc[0] -cne $expectedWslCc) {
    throw 'WSL host compiler path mismatch'
}
$wslCc = $wslCc[0]
$wslCcHashLine = @(Invoke-WslExact -Arguments @('/usr/bin/sha256sum','--',$wslCc))
if ($LASTEXITCODE -ne 0 -or $wslCcHashLine.Count -ne 1) { throw 'WSL host compiler hash failed' }
$wslCcSha256 = ($wslCcHashLine[0] -split '\s+',2)[0].ToUpperInvariant()
$wslCcVersion = @(Invoke-WslExact -Arguments @($wslCc,'-dumpfullversion','-dumpversion'))
if ($LASTEXITCODE -ne 0 -or $wslCcVersion.Count -ne 1) { throw 'WSL host compiler version failed' }
$wslTarget = @(Invoke-WslExact -Arguments @($wslCc,'-dumpmachine'))
if ($LASTEXITCODE -ne 0 -or $wslTarget.Count -ne 1) { throw 'WSL host compiler target failed' }
$wslSpecs = @(Invoke-WslExact -Arguments @($wslCc,'-print-file-name=specs'))
if ($LASTEXITCODE -ne 0 -or $wslSpecs.Count -ne 1 -or $wslSpecs[0] -cne 'specs') {
    throw 'An unowned WSL GCC specs override is present'
}
if ($wslCcSha256 -cne $expectedWslCcSha256 -or
        $wslCcVersion[0] -cne $expectedWslCcVersion -or
        $wslTarget[0] -cne $expectedWslTarget) {
    throw 'WSL host compiler identity mismatch'
}

function Get-WslCompilerProgram([string]$name) {
    if ($name -notmatch '^[a-z0-9-]+$') { throw 'Unsafe GCC subprogram name' }
    $arguments = @('/usr/bin/env','-i','PATH=/usr/bin:/bin','LC_ALL=C','LANG=C','TZ=UTC',
        $wslCc,"-print-prog-name=$name")
    $reported = @(Invoke-WslExact $arguments)
    if ($LASTEXITCODE -ne 0 -or $reported.Count -ne 1 -or
            -not $reported[0].StartsWith('/')) {
        throw "WSL GCC subprogram resolution failed: $name"
    }
    $resolved = @(Invoke-WslExact -Arguments @('/usr/bin/readlink','-f','--',$reported[0]))
    if ($LASTEXITCODE -ne 0 -or $resolved.Count -ne 1 -or
            -not $resolved[0].StartsWith('/')) {
        throw "WSL GCC subprogram canonicalization failed: $name"
    }
    return $resolved[0]
}
$wslCc1 = Get-WslCompilerProgram 'cc1'
$wslAssembler = Get-WslCompilerProgram 'as'
$wslLinker = Get-WslCompilerProgram 'ld'
$wslCollect2 = Get-WslCompilerProgram 'collect2'

function Convert-ToWslMountPath([string]$windowsPath) {
    $full = [IO.Path]::GetFullPath($windowsPath)
    if ($full -notmatch '^([A-Za-z]):\\(.*)$') {
        throw 'Only an absolute Windows drive path can enter the WSL build boundary'
    }
    $drive = $Matches[1].ToLowerInvariant()
    $tail = $Matches[2].Replace('\','/')
    if ($tail.IndexOfAny([char[]]@("`0","`r","`n")) -ge 0) {
        throw 'Unsafe Windows path cannot enter the WSL build boundary'
    }
    return "/mnt/$drive/$tail"
}
$wslRoot = Convert-ToWslMountPath $snapshotRoot
$wslNative = "$wslRoot/native"
$wslHost = Convert-ToWslMountPath $hostOut
$hostSystemIncludes = @('-nostdinc',
    '-isystem','/usr/lib/gcc/x86_64-linux-gnu/15/include',
    '-isystem','/usr/include/x86_64-linux-gnu',
    '-isystem','/usr/include')
$hostCommon = @('-std=c11','-O2','-Wall','-Wextra','-Werror',"-I$wslNative",
    "-ffile-prefix-map=$wslRoot=/rtl-reader-pen-lease-source",
    "-fdebug-prefix-map=$wslRoot=/rtl-reader-pen-lease-source",
    "-fmacro-prefix-map=$wslRoot=/rtl-reader-pen-lease-source") + $hostSystemIncludes
$wslCleanEnvironment = @('/usr/bin/env','-i','PATH=/usr/bin:/bin','LC_ALL=C','LANG=C','TZ=UTC')
$wslSnapshotBuildEnvironment = @('/usr/bin/env','-i','-C',$wslRoot,
    'PATH=/usr/bin:/bin','LC_ALL=C','LANG=C','TZ=UTC')
function Invoke-Host([string[]]$arguments,[string]$failure) {
    Invoke-WslExact $arguments
    if ($LASTEXITCODE -ne 0) { throw $failure }
}
function Get-WslFileSha256([string]$path) {
    $arguments = $wslCleanEnvironment + @('/usr/bin/sha256sum','--',$path)
    $line = @(Invoke-WslExact $arguments)
    if ($LASTEXITCODE -ne 0 -or $line.Count -ne 1 -or
            $line[0] -notmatch '^([0-9a-f]{64})\s') {
        throw "WSL artifact hash failed: $path"
    }
    return $Matches[1].ToUpperInvariant()
}
function Get-WslResolvedPath([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path) -or
            $path.IndexOfAny([char[]]@("`0","`t","`r","`n")) -ge 0) {
        throw 'Unsafe WSL executable or DSO path'
    }
    $arguments = $wslCleanEnvironment + @('/usr/bin/readlink','-f','--',$path)
    $resolved = @(Invoke-WslExact $arguments)
    if ($LASTEXITCODE -ne 0 -or $resolved.Count -ne 1 -or
            -not $resolved[0].StartsWith('/') -or
            $resolved[0].IndexOfAny([char[]]@("`0","`t","`r","`n")) -ge 0) {
        throw "WSL path resolution failed: $path"
    }
    return $resolved[0]
}
function Get-WslFileLength([string]$path) {
    $arguments = $wslCleanEnvironment + @('/usr/bin/stat','-c','%s','--',$path)
    $line = @(Invoke-WslExact $arguments)
    [uint64]$length = 0
    if ($LASTEXITCODE -ne 0 -or $line.Count -ne 1 -or
            -not [uint64]::TryParse($line[0],[Globalization.NumberStyles]::None,
                [Globalization.CultureInfo]::InvariantCulture,[ref]$length)) {
        throw "WSL file-size query failed: $path"
    }
    return $length
}
function Assert-WslPackageFile([string]$path,[uint64]$length,[string]$sha256) {
    if (-not $wslOwnedFiles.ContainsKey($path)) {
        throw "Runtime dependency is outside the pinned WSL package closure: $path"
    }
    $authority = $wslOwnedFiles[$path]
    if ($authority.Bytes -ne $length -or $authority.Sha256 -cne $sha256) {
        throw "Runtime dependency differs from pinned package authority: $path"
    }
}
function Get-WslRuntimeResolutionManifest([Collections.IDictionary]$programs) {
    $manifest = [Text.StringBuilder]::new()
    foreach ($entry in $programs.GetEnumerator()) {
        $label = [string]$entry.Key
        $path = Get-WslResolvedPath ([string]$entry.Value)
        $length = Get-WslFileLength $path
        $hash = Get-WslFileSha256 $path
        $generated = $label.StartsWith('artifact/',[StringComparison]::Ordinal)
        if (-not $generated) { Assert-WslPackageFile $path $length $hash }
        $authorityPath = if ($generated) { '@generated/' + $label.Substring(9) } else { $path }
        [void]$manifest.Append('B').Append("`t").Append($label).Append("`t").
            Append($authorityPath).Append("`t").Append($length).Append("`t").
            Append($hash.ToLowerInvariant()).Append("`n")

        $arguments = $wslCleanEnvironment + @($expectedWslLoader,'--list',$path)
        $loaded = @(Invoke-WslExact $arguments)
        if ($LASTEXITCODE -ne 0 -or $loaded.Count -lt 1) {
            throw "Pinned loader failed to resolve runtime dependencies: $label"
        }
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($rawLine in $loaded) {
            $line = $rawLine.Trim()
            if ($line -ceq 'statically linked' -and $loaded.Count -eq 1) {
                [void]$manifest.Append('S').Append("`t").Append($label).
                    Append("`tstatically-linked`n")
                continue
            }
            if ($line -match '^linux-vdso\.so\.1\s+\(0x[0-9a-fA-F]+\)$') {
                if (-not $seen.Add('linux-vdso.so.1')) {
                    throw "Duplicate virtual DSO in loader output: $label"
                }
                [void]$manifest.Append('V').Append("`t").Append($label).
                    Append("`tlinux-vdso.so.1`n")
                continue
            }
            if ($line -notmatch '^(?<soname>\S+)\s+=>\s+(?<path>/\S+)\s+\(0x[0-9a-fA-F]+\)$') {
                throw "Unrecognized pinned-loader output for $label`: $line"
            }
            $soname = $Matches.soname
            if (-not $seen.Add($soname)) {
                throw "Duplicate resolved DSO in loader output for $label`: $soname"
            }
            $resolvedDso = Get-WslResolvedPath $Matches.path
            $dsoLength = Get-WslFileLength $resolvedDso
            $dsoHash = Get-WslFileSha256 $resolvedDso
            Assert-WslPackageFile $resolvedDso $dsoLength $dsoHash
            [void]$manifest.Append('D').Append("`t").Append($label).Append("`t").
                Append($soname).Append("`t").Append($resolvedDso).Append("`t").
                Append($dsoLength).Append("`t").Append($dsoHash.ToLowerInvariant()).
                Append("`n")
        }
    }
    $text = $manifest.ToString()
    $bytes = [Text.Encoding]::UTF8.GetBytes($text)
    return [PSCustomObject]@{
        Lines = if ($text.Length -eq 0) { 0 } else { ($text.Split("`n").Count - 1) }
        Bytes = $bytes.Length
        Sha256 = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))
        Text = $text
    }
}
$hostProduction = "$wslHost/pen-input-lease-host"
$hostCore = "$wslHost/pen-input-lease-core-test"
$hostAdapter = "$wslHost/pen-input-lease-adapter-test"
Invoke-Host ($wslCleanEnvironment + @($wslCc) + $hostCommon + @("$wslNative/pen_input_lease.c",'-o',$hostProduction)) 'Host production compilation failed'
Invoke-Host ($wslCleanEnvironment + @($wslCc) + $hostCommon + @("$wslNative/pen_input_lease_core_test.c",'-o',$hostCore)) 'Host core-test compilation failed'
Invoke-Host ($wslCleanEnvironment + @($wslCc) + $hostCommon + @('-Wno-unused-function',"$wslNative/pen_input_lease_adapter_test.c",'-o',$hostAdapter)) 'Host adapter-test compilation failed'
$hostRepeatProduction = "$wslHost/pen-input-lease-host.repeat"
$hostRepeatCore = "$wslHost/pen-input-lease-core-test.repeat"
$hostRepeatAdapter = "$wslHost/pen-input-lease-adapter-test.repeat"
Invoke-Host ($wslCleanEnvironment + @($wslCc) + $hostCommon + @("$wslNative/pen_input_lease.c",'-o',$hostRepeatProduction)) 'Repeated host production compilation failed'
Invoke-Host ($wslCleanEnvironment + @($wslCc) + $hostCommon + @("$wslNative/pen_input_lease_core_test.c",'-o',$hostRepeatCore)) 'Repeated host core-test compilation failed'
Invoke-Host ($wslCleanEnvironment + @($wslCc) + $hostCommon + @('-Wno-unused-function',"$wslNative/pen_input_lease_adapter_test.c",'-o',$hostRepeatAdapter)) 'Repeated host adapter-test compilation failed'
foreach ($pair in @(
        @($hostProduction,$hostRepeatProduction),
        @($hostCore,$hostRepeatCore),
        @($hostAdapter,$hostRepeatAdapter))) {
    $first = Get-WslFileSha256 $pair[0]
    $second = Get-WslFileSha256 $pair[1]
    if ($first -cne $second) { throw "Non-deterministic host build: $($pair[0])" }
}
$hostIdentityMismatches = [Collections.Generic.List[string]]::new()
foreach ($artifact in @($hostProduction,$hostCore,$hostAdapter)) {
    $name = Split-Path -Leaf $artifact
    $actual = Get-WslFileSha256 $artifact
    if (-not $expectedHostArtifactSha256.Contains($name) -or
            $actual -cne $expectedHostArtifactSha256[$name]) {
        $hostIdentityMismatches.Add("$name=$actual")
    }
}
if ($hostIdentityMismatches.Count -ne 0) {
    throw "Cross-invocation host identity mismatch: $($hostIdentityMismatches -join '; ')"
}

# Sanitizer executions exercise the pure controller and the production adapter/process contract.
$sanitizer = @('-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fno-omit-frame-pointer','-fsanitize=address,undefined',"-I$wslNative",
    "-ffile-prefix-map=$wslRoot=/rtl-reader-pen-lease-source",
    "-fdebug-prefix-map=$wslRoot=/rtl-reader-pen-lease-source",
    "-fmacro-prefix-map=$wslRoot=/rtl-reader-pen-lease-source") + $hostSystemIncludes
$asanCore = "$wslHost/pen-input-lease-core-test-asan"
$asanProduction = "$wslHost/pen-input-lease-host-asan"
$asanAdapter = "$wslHost/pen-input-lease-adapter-test-asan"
Invoke-Host ($wslSnapshotBuildEnvironment + @($wslCc) + $sanitizer + @('native/pen_input_lease_core_test.c','-o',$asanCore)) 'Sanitized core-test compilation failed'
Invoke-Host ($wslSnapshotBuildEnvironment + @($wslCc) + $sanitizer + @('native/pen_input_lease.c','-o',$asanProduction)) 'Sanitized production compilation failed'
Invoke-Host ($wslSnapshotBuildEnvironment + @($wslCc) + $sanitizer + @('-Wno-unused-function','native/pen_input_lease_adapter_test.c','-o',$asanAdapter)) 'Sanitized adapter-test compilation failed'
$asanRepeatCore = "$wslHost/pen-input-lease-core-test-asan.repeat"
$asanRepeatProduction = "$wslHost/pen-input-lease-host-asan.repeat"
$asanRepeatAdapter = "$wslHost/pen-input-lease-adapter-test-asan.repeat"
Invoke-Host ($wslSnapshotBuildEnvironment + @($wslCc) + $sanitizer + @('native/pen_input_lease_core_test.c','-o',$asanRepeatCore)) 'Repeated sanitized core-test compilation failed'
Invoke-Host ($wslSnapshotBuildEnvironment + @($wslCc) + $sanitizer + @('native/pen_input_lease.c','-o',$asanRepeatProduction)) 'Repeated sanitized production compilation failed'
Invoke-Host ($wslSnapshotBuildEnvironment + @($wslCc) + $sanitizer + @('-Wno-unused-function','native/pen_input_lease_adapter_test.c','-o',$asanRepeatAdapter)) 'Repeated sanitized adapter-test compilation failed'
foreach ($pair in @(
        @($asanProduction,$asanRepeatProduction),
        @($asanCore,$asanRepeatCore),
        @($asanAdapter,$asanRepeatAdapter))) {
    if ((Get-WslFileSha256 $pair[0]) -cne (Get-WslFileSha256 $pair[1])) {
        throw "Non-deterministic sanitized host build: $($pair[0])"
    }
}
foreach ($artifact in @($asanProduction,$asanCore,$asanAdapter)) {
    $name = Split-Path -Leaf $artifact
    $actual = Get-WslFileSha256 $artifact
    if (-not $expectedSanitizerArtifactSha256.Contains($name) -or
            $actual -cne $expectedSanitizerArtifactSha256[$name]) {
        throw "Cross-invocation sanitized artifact identity mismatch: $name=$actual"
    }
}

$linkedArtifacts = [ordered]@{}
foreach ($configuration in @('plain','asan')) {
    $flags = if ($configuration -eq 'plain') { $hostCommon } else { $sanitizer }
    $object = "$wslHost/production-linked-$configuration.o"
    $binary = "$wslHost/production-linked-$configuration-test"
    $repeat = "$binary.repeat"
    Invoke-Host ($wslSnapshotBuildEnvironment + @($wslCc) + $flags + @(
        '-Dmain=pen_input_lease_production_main','-c','native/pen_input_lease.c','-o',$object)) 'Link-wrapped production object failed'
    foreach ($destination in @($binary,$repeat)) {
        Invoke-Host ($wslSnapshotBuildEnvironment + @($wslCc) + $flags + @(
            '-Wno-unused-function','-DPEN_INPUT_LEASE_LINK_WRAPPER',
            'native/pen_input_lease_adapter_test.c',$object,
            '-Wl,--wrap=open,--wrap=close,--wrap=fstat,--wrap=lstat,--wrap=ioctl,--wrap=recv,--wrap=send,--wrap=fork,--wrap=waitpid,--wrap=_exit,--wrap=getrandom',
            '-o',$destination)) 'Link-wrapped production test compilation failed'
    }
    if ((Get-WslFileSha256 $binary) -cne (Get-WslFileSha256 $repeat)) {
        throw 'Link-wrapped production test is not deterministic'
    }
    $linkedArtifacts[$configuration] = $binary
}

# Observe executables used by host compilation/testing and their resolved DSOs.
# This is diagnostic checkpoint evidence, not retained-through-use authority. Loader
# addresses are intentionally discarded; resolved paths, sizes, and hashes are
# compared to the package-file closure. Generated artifacts use stable logical
# names so random private-snapshot paths cannot perturb deterministic evidence.
$runtimePrograms = [ordered]@{
    'tool/dash' = '/usr/bin/dash'
    'tool/env' = '/usr/bin/env'
    'tool/dpkg-query' = '/usr/bin/dpkg-query'
    'tool/readlink' = '/usr/bin/readlink'
    'tool/sha256sum' = '/usr/bin/sha256sum'
    'tool/stat' = '/usr/bin/stat'
    'tool/cut' = '/usr/bin/cut'
    'tool/sort' = '/usr/bin/sort'
    'tool/loader' = $expectedWslLoader
    'tool/gcc' = $wslCc
    'tool/gcc-cc1' = $wslCc1
    'tool/gcc-as' = $wslAssembler
    'tool/gcc-ld' = $wslLinker
    'tool/gcc-collect2' = $wslCollect2
    'artifact/pen-input-lease-host' = $hostProduction
    'artifact/pen-input-lease-core-test' = $hostCore
    'artifact/pen-input-lease-adapter-test' = $hostAdapter
    'artifact/pen-input-lease-host.repeat' = $hostRepeatProduction
    'artifact/pen-input-lease-core-test.repeat' = $hostRepeatCore
    'artifact/pen-input-lease-adapter-test.repeat' = $hostRepeatAdapter
    'artifact/pen-input-lease-host-asan' = $asanProduction
    'artifact/pen-input-lease-core-test-asan' = $asanCore
    'artifact/pen-input-lease-adapter-test-asan' = $asanAdapter
    'artifact/pen-input-lease-host-asan.repeat' = $asanRepeatProduction
    'artifact/pen-input-lease-core-test-asan.repeat' = $asanRepeatCore
    'artifact/pen-input-lease-adapter-test-asan.repeat' = $asanRepeatAdapter
}
foreach ($entry in $linkedArtifacts.GetEnumerator()) {
    $runtimePrograms['artifact/production-linked-' + $entry.Key + '-test'] = $entry.Value
    $runtimePrograms['artifact/production-linked-' + $entry.Key + '-test.repeat'] = $entry.Value + '.repeat'
}
$wslRuntime = Get-WslRuntimeResolutionManifest $runtimePrograms
if (-not (Test-ExactClosure $wslRuntime.Lines $wslRuntime.Bytes $wslRuntime.Sha256 `
        $expectedWslRuntimeLineCount $expectedWslRuntimeByteCount `
        $expectedWslRuntimeSha256)) {
    throw "WSL runtime resolution mismatch: lines=$($wslRuntime.Lines) bytes=$($wslRuntime.Bytes) hash=$($wslRuntime.Sha256)"
}
[IO.File]::WriteAllText($wslRuntimePath,$wslRuntime.Text,
    [Text.UTF8Encoding]::new($false))
$wslLoaderStateBeforeTests = Get-WslLoaderStateManifest
if ($wslLoaderStateBeforeTests.Text -cne $wslLoaderState.Text -or
        $wslLoaderStateBeforeTests.Sha256 -cne $wslLoaderState.Sha256) {
    throw 'WSL loader state changed before host-test execution'
}

Invoke-Host ($wslCleanEnvironment + @($hostCore)) 'Host core test failed'
Invoke-Host ($wslCleanEnvironment + @($hostAdapter,$hostProduction)) 'Host production-adapter test failed'
Invoke-Host ($wslCleanEnvironment + @('ASAN_OPTIONS=detect_leaks=1:halt_on_error=1','UBSAN_OPTIONS=halt_on_error=1',$asanCore)) 'Sanitized core test failed'
Invoke-Host ($wslCleanEnvironment + @('ASAN_OPTIONS=detect_leaks=1:halt_on_error=1','UBSAN_OPTIONS=halt_on_error=1',$asanAdapter,$asanProduction)) 'Sanitized production-adapter test failed'
Invoke-Host ($wslCleanEnvironment + @($linkedArtifacts['plain'])) 'Link-wrapped production test failed'
Invoke-Host ($wslCleanEnvironment + @('ASAN_OPTIONS=detect_leaks=1:halt_on_error=1','UBSAN_OPTIONS=halt_on_error=1',$linkedArtifacts['asan'])) 'Sanitized link-wrapped production test failed'

# GCC's interprocedural analyzer is independent of the runtime sanitizer pass.
$analyzer = @('-std=c11','-O0','-Wall','-Wextra','-Werror','-fanalyzer',"-I$wslNative",'-c') + $hostSystemIncludes
Invoke-Host ($wslSnapshotBuildEnvironment + @($wslCc) + $analyzer + @('native/pen_input_lease.c','-o',"$wslHost/pen_input_lease.analyzer.o")) 'Production static analyzer failed'
Invoke-Host ($wslSnapshotBuildEnvironment + @($wslCc) + $analyzer + @('native/pen_input_lease_core_test.c','-o',"$wslHost/pen_input_lease_core_test.analyzer.o")) 'Core-test static analyzer failed'
Invoke-Host ($wslSnapshotBuildEnvironment + @($wslCc) + $analyzer + @('-Wno-unused-function','native/pen_input_lease_adapter_test.c','-o',"$wslHost/pen_input_lease_adapter_test.analyzer.o")) 'Adapter static analyzer failed'

$wslManifestAfter = Get-WslToolchainManifest
if ($wslManifestAfter.Sha256 -cne $wslManifest.Sha256 -or
        $wslManifestAfter.Text -cne $wslManifest.Text) {
    throw 'WSL host-toolchain closure changed during compilation or testing'
}
$wslLoaderStateAfter = Get-WslLoaderStateManifest
if ($wslLoaderStateAfter.Sha256 -cne $wslLoaderState.Sha256 -or
        $wslLoaderStateAfter.Text -cne $wslLoaderState.Text) {
    throw 'WSL loader state changed during compilation or testing'
}
$wslRuntimeAfter = Get-WslRuntimeResolutionManifest $runtimePrograms
if ($wslRuntimeAfter.Sha256 -cne $wslRuntime.Sha256 -or
        $wslRuntimeAfter.Text -cne $wslRuntime.Text) {
    throw 'WSL runtime resolution changed during compilation or testing'
}

$ndkItemsAfter = @(Get-ChildItem -LiteralPath $resolvedNdk -Recurse -Force)
if (@($ndkItemsAfter | Where-Object {
        ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0
    }).Count -ne 0) {
    throw 'Pinned NDK gained a reparse point during the build'
}
$ndkPathsAfter = @($ndkItemsAfter | Where-Object { -not $_.PSIsContainer } |
    ForEach-Object { $_.FullName })
[Array]::Sort($ndkPathsAfter,[StringComparer]::Ordinal)
if ($ndkPathsAfter.Count -ne $ndkPaths.Count) {
    throw 'Pinned NDK file allowlist changed during the build'
}
for ($index = 0; $index -lt $ndkPaths.Count; $index++) {
    if ($ndkPathsAfter[$index] -cne $ndkPaths[$index]) {
        throw 'Pinned NDK file allowlist changed during the build'
    }
}

$sourceHashes = [ordered]@{}
foreach ($entry in $snapshotHashes.GetEnumerator()) {
    $sourceHashes[$entry.Key] = $entry.Value
    $snapshotPath = Join-Path $snapshotRoot $entry.Key
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $snapshotPath).Hash.ToLowerInvariant()
    if ($actual -cne $entry.Value) { throw "Immutable source snapshot changed: $($entry.Key)" }
}
$artifactHashes = [ordered]@{}
foreach ($artifact in @($androidProduction,$androidCore,$androidAdapter)) {
    $artifactHashes[(Split-Path -Leaf $artifact)] = (Get-FileHash -Algorithm SHA256 -LiteralPath $artifact).Hash.ToLowerInvariant()
}
$hostArtifactHashes = [ordered]@{}
foreach ($artifact in @($hostProduction,$hostCore,$hostAdapter)) {
    $hostArtifactHashes[(Split-Path -Leaf $artifact)] =
        (Get-WslFileSha256 $artifact).ToLowerInvariant()
}
$sanitizerArtifactHashes = [ordered]@{}
foreach ($artifact in @($asanProduction,$asanCore,$asanAdapter)) {
    $sanitizerArtifactHashes[(Split-Path -Leaf $artifact)] =
        (Get-WslFileSha256 $artifact).ToLowerInvariant()
}
$provenance = [ordered]@{
    schema = 'rtl-reader-pen-input-lease-build-v1'
    ndkRevision = $expectedRevision
    clangSha256 = $clangSha256.ToLowerInvariant()
    androidDriverSha256 = $driverSha256.ToLowerInvariant()
    ndkClosureScope = 'entire-pinned-ndk-tree'
    ndkClosureFileCount = $ndkPaths.Count
    ndkClosureByteCount = $ndkBytes
    ndkClosureManifestSha256 = $ndkManifestHash.ToLowerInvariant()
    target = 'aarch64-linux-android30'
    androidFlags = @($androidCommon | ForEach-Object {
        $_.Replace($snapshotRoot,'<immutable-source-snapshot>')
    })
    androidArtifactIdentityPinnedAcrossInvocations = $true
    wslHostCompiler = $wslCc
    wslHostCompilerVersion = $wslCcVersion[0]
    wslHostCompilerTarget = $wslTarget[0]
    wslHostCompilerSha256 = $wslCcSha256.ToLowerInvariant()
    wslHostFlags = @($hostCommon | ForEach-Object {
        $_.Replace($wslRoot,'<immutable-source-snapshot>')
    })
    wslHostEnvironment = $wslCleanEnvironment
    wslHostDefaultSpecsOverride = $false
    wslHostEvidenceClass = 'platform-runtime-trusted-diagnostic'
    wslHostTrustedBootstrap = 'Windows OS, WSL service, kali-linux bootstrap and initial Linux dynamic loader'
    wslHostHermetic = $false
    wslHostRuntimeAuthorityRetainedThroughUse = $false
    wslLauncher = $wslLauncher
    wslLauncherSha256 = $expectedWslLauncherSha256.ToLowerInvariant()
    wslLauncherAuthenticatedAndRetained = $true
    wslDistribution = $wslDistribution
    wslWindowsLaunchEnvironment = @('SystemRoot=C:\Windows','WINDIR=C:\Windows','SystemDrive=C:')
    hostilePathWslenvLoaderRegression = 'pass'
    wslHostClosureScope = 'endpoint-observed-allowlisted-compiler-runtime-package-files'
    wslHostClosureLineCount = $wslManifest.Lines
    wslHostClosureByteCount = $wslManifest.Bytes
    wslHostClosureManifestSha256 = $wslManifest.Sha256.ToLowerInvariant()
    wslHostLoader = $expectedWslLoader
    wslHostLoaderPreloadAbsent = $true
    wslHostLoaderStateLineCount = $wslLoaderState.Lines
    wslHostLoaderStateByteCount = $wslLoaderState.Bytes
    wslHostLoaderStateSha256 = $wslLoaderState.Sha256.ToLowerInvariant()
    wslHostRuntimeResolutionLineCount = $wslRuntime.Lines
    wslHostRuntimeResolutionByteCount = $wslRuntime.Bytes
    wslHostRuntimeResolutionSha256 = $wslRuntime.Sha256.ToLowerInvariant()
    wslHostRuntimeDependenciesPackageOwned = $true
    wslHostLoaderStateAndResolutionMatchedAtCheckpoints = $true
    wslHostArtifactSha256 = $hostArtifactHashes
    wslHostSanitizerArtifactSha256 = $sanitizerArtifactHashes
    wslHostLinkedProductionSha256 = [ordered]@{
        plain = (Get-WslFileSha256 $linkedArtifacts['plain']).ToLowerInvariant()
        asan = (Get-WslFileSha256 $linkedArtifacts['asan']).ToLowerInvariant()
    }
    wslHostArtifactIdentityPinnedAcrossInvocations = $true
    wslHostSanitizerIdentityPinnedAcrossInvocations = $true
    toolchainClosureMutationChecks = $true
    sourceSha256 = $sourceHashes
    sourceSnapshotHeldReadOnly = $true
    sourceSnapshotInputCount = $snapshotHashes.Count
    buildScriptEntrySha256 = $entryScriptSha256
    buildScriptEntryHandleRetained = $true
    buildScriptTrustRoot = 'reviewed caller; entry-time retention is not self-authentication'
    concurrentEntryScriptWriteAndReplacementRegression = 'pass'
    artifactSha256 = $artifactHashes
    deterministicRebuild = $true
    deterministicRebuildScope = 'Android plus unsanitized and ASan/UBSan WSL host executable artifacts'
    ephemeralDiagnosticArtifactsExcludedFromIdentity = @(
        'GCC analyzer objects'
    )
    hostCoreTest = 'pass'
    hostProductionAdapterTest = 'pass'
    hostUnmodifiedLinkedProductionTest = 'pass'
    hostUnmodifiedLinkedProductionAsanUbsanTest = 'pass'
    hostAsanUbsan = 'pass'
    hostGccAnalyzer = 'pass'
    deviceExecuted = $false
}
$provenancePath = Join-Path $out 'pen-input-lease-provenance.json'
[IO.File]::WriteAllText($provenancePath,($provenance | ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))

Write-Output "PEN_INPUT_LEASE_BUILD_PASS output=$out"
Write-Output ($provenance | ConvertTo-Json -Depth 6 -Compress)
Write-Output 'BUILT AND HOST-TESTED ONLY. Do not run on a device before exact-source review and a dedicated hardware gate.'
Write-Output $androidProduction
} finally {
    $wslLauncherLock.Dispose()
    foreach ($lock in $snapshotLocks) { $lock.Dispose() }
    foreach ($lock in $ndkLocks) { $lock.Dispose() }
    foreach ($entry in $savedCompilerEnvironment.GetEnumerator()) {
        if ($null -eq $entry.Value) {
            Remove-Item -LiteralPath "Env:$($entry.Key)" -ErrorAction SilentlyContinue
        } else {
            Set-Item -LiteralPath "Env:$($entry.Key)" -Value $entry.Value
        }
    }
}
} finally { $entryScriptHandle.Dispose() }
