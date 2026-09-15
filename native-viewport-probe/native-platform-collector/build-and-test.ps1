param(
    [Parameter(Mandatory = $true)][string]$Ndk,
    [string]$HostCxx = 'g++',
    [string]$Python = 'python',
    [string]$PosixTestDistribution = 'kali-linux'
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$root = Split-Path -Parent $here
$out = Join-Path $root ('build/native-platform-collector-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $out | Out-Null

function Get-Sha256Bytes([byte[]]$Bytes) {
    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($Bytes)
    ).ToLowerInvariant()
}

function Read-OrdinaryFileAuthority(
    [Parameter(Mandatory = $true)][string]$ExpectedPath
) {
    $expectedFull = [IO.Path]::GetFullPath($ExpectedPath)
    $before = Get-Item -LiteralPath $expectedFull -Force -ErrorAction Stop
    if (!($before -is [IO.FileInfo]) -or
        (($before.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw ('Downstream authority is not an ordinary non-reparse file: ' + $expectedFull)
    }
    $resolved = [IO.Path]::GetFullPath($before.FullName)
    if (![string]::Equals($resolved, $expectedFull,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw ('Downstream authority resolved to an unexpected path: ' + $expectedFull)
    }
    $bytes = [IO.File]::ReadAllBytes($resolved)
    $hash = Get-Sha256Bytes $bytes
    $after = Get-Item -LiteralPath $expectedFull -Force -ErrorAction Stop
    if (!($after -is [IO.FileInfo]) -or
        (($after.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or
        ![string]::Equals([IO.Path]::GetFullPath($after.FullName), $expectedFull,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw ('Downstream authority changed type or path while read: ' + $expectedFull)
    }
    $afterBytes = [IO.File]::ReadAllBytes($expectedFull)
    if ($before.Length -ne $after.Length -or
        $before.LastWriteTimeUtc.Ticks -ne $after.LastWriteTimeUtc.Ticks -or
        $bytes.Length -ne $afterBytes.Length -or
        $hash -ne (Get-Sha256Bytes $afterBytes)) {
        throw ('Downstream authority drifted while read: ' + $expectedFull)
    }
    return [PSCustomObject]@{
        Path = $expectedFull
        Bytes = $bytes
        Sha256 = $hash
    }
}

$hostCompiler = (Get-Command $HostCxx -ErrorAction Stop).Source
$pythonCommand = Get-Command $Python -CommandType Application -ErrorAction Stop
$pythonPath = (Resolve-Path -LiteralPath $pythonCommand.Source -ErrorAction Stop).ProviderPath
$pythonHashBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $pythonPath).Hash.ToLowerInvariant()
$pythonVersion = (& $pythonPath --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($pythonVersion)) {
    throw 'Pinned Python identity could not be read'
}
$backendAuthorityPath = Join-Path $root 'native_page_private_adb_platform_backend.py'
$platformAuthorityPath = Join-Path $root 'native_page_visual_platform_authority.py'
$backendAuthorityBefore = Read-OrdinaryFileAuthority $backendAuthorityPath
$platformAuthorityBefore = Read-OrdinaryFileAuthority $platformAuthorityPath
$downstreamContractText =
    "NATIVE_PAGE_PLATFORM_COLLECTOR_DOWNSTREAM_CONTRACT_V1`n" +
    "native_page_private_adb_platform_backend.py=$($backendAuthorityBefore.Sha256)`n" +
    "native_page_visual_platform_authority.py=$($platformAuthorityBefore.Sha256)`n" +
    "END`n"
$downstreamContractHash = Get-Sha256Bytes (
    [Text.UTF8Encoding]::new($false).GetBytes($downstreamContractText))
$downstreamStage = Join-Path $out 'downstream-authority'
New-Item -ItemType Directory -Path $downstreamStage | Out-Null
$stagedBackendPath = Join-Path $downstreamStage 'native_page_private_adb_platform_backend.py'
$stagedPlatformPath = Join-Path $downstreamStage 'native_page_visual_platform_authority.py'
[IO.File]::WriteAllBytes($stagedBackendPath, $backendAuthorityBefore.Bytes)
[IO.File]::WriteAllBytes($stagedPlatformPath, $platformAuthorityBefore.Bytes)
$stagedBackendBefore = Read-OrdinaryFileAuthority $stagedBackendPath
$stagedPlatformBefore = Read-OrdinaryFileAuthority $stagedPlatformPath
if ($stagedBackendBefore.Sha256 -ne $backendAuthorityBefore.Sha256 -or
    $stagedPlatformBefore.Sha256 -ne $platformAuthorityBefore.Sha256) {
    throw 'Staged downstream authority does not match its reviewed source identity'
}
$hostTest = Join-Path $out 'collector-core-test.exe'
& $hostCompiler -std=c++17 -O2 -Wall -Wextra -Werror -pedantic -static `
    (Join-Path $here 'collector_core.cpp') `
    (Join-Path $here 'collector_core_test.cpp') -o $hostTest
if ($LASTEXITCODE -ne 0) { throw 'Portable collector core compilation failed' }
& $hostTest
if ($LASTEXITCODE -ne 0) { throw 'Portable collector core tests failed' }
& $pythonPath (Join-Path $here 'test_downstream_contract.py') `
    $hostTest $stagedBackendPath $stagedPlatformPath `
    $backendAuthorityBefore.Sha256 $platformAuthorityBefore.Sha256 `
    $downstreamContractHash
if ($LASTEXITCODE -ne 0) { throw 'Frozen downstream parser contract tests failed' }
$backendAuthorityAfter = Read-OrdinaryFileAuthority $backendAuthorityPath
$platformAuthorityAfter = Read-OrdinaryFileAuthority $platformAuthorityPath
$stagedBackendAfter = Read-OrdinaryFileAuthority $stagedBackendPath
$stagedPlatformAfter = Read-OrdinaryFileAuthority $stagedPlatformPath
if ($backendAuthorityAfter.Sha256 -ne $backendAuthorityBefore.Sha256 -or
    $platformAuthorityAfter.Sha256 -ne $platformAuthorityBefore.Sha256 -or
    $stagedBackendAfter.Sha256 -ne $backendAuthorityBefore.Sha256 -or
    $stagedPlatformAfter.Sha256 -ne $platformAuthorityBefore.Sha256) {
    throw 'Downstream authority identity changed during its contract test'
}
& $pythonPath (Join-Path $here 'test_collector_hardening_contract.py')
if ($LASTEXITCODE -ne 0) { throw 'Collector hardening source contract tests failed' }
$wsl = @(Get-Command 'wsl.exe' -CommandType Application -ErrorAction Stop)[0].Source
function Convert-ToWslMountPath([string]$WindowsPath) {
    $full = [IO.Path]::GetFullPath($WindowsPath)
    if ($full -notmatch '^([A-Za-z]):\\(.*)$') {
        throw 'POSIX test path is not an absolute Windows drive path'
    }
    return '/mnt/' + $Matches[1].ToLowerInvariant() + '/' +
        $Matches[2].Replace('\', '/')
}
$wslHere = Convert-ToWslMountPath $here
$wslOut = Convert-ToWslMountPath $out
& $wsl -d $PosixTestDistribution -- test -d $wslHere
if ($LASTEXITCODE -ne 0) {
    throw 'Pinned POSIX test environment path conversion failed'
}
$posixTest = $wslOut + '/command-runner-posix-test'
$posixArguments = @(
    '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', '-pedantic', '-pthread',
    ($wslHere + '/collector_core.cpp'),
    ($wslHere + '/command_runner_posix_test.cpp'),
    '-Wl,--wrap=execve', '-o', $posixTest
)
& $wsl -d $PosixTestDistribution -- g++ @posixArguments
if ($LASTEXITCODE -ne 0) { throw 'Exact POSIX command-runner compilation failed' }
& $wsl -d $PosixTestDistribution -- $posixTest
if ($LASTEXITCODE -ne 0) { throw 'Exact POSIX command-runner behavior tests failed' }
$posixCompilerVersion = (& $wsl -d $PosixTestDistribution -- g++ --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($posixCompilerVersion)) {
    throw 'POSIX test compiler identity could not be read'
}
$pythonHashAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath $pythonPath).Hash.ToLowerInvariant()
if ($pythonHashAfter -ne $pythonHashBefore) {
    throw 'Pinned Python executable changed during tests'
}

$ndkPath = (Resolve-Path -LiteralPath $Ndk -ErrorAction Stop).ProviderPath
$ndkProperties = Join-Path $ndkPath 'source.properties'
if (!(Test-Path -LiteralPath $ndkProperties -PathType Leaf)) {
    throw 'NDK source.properties is unavailable'
}
$ndkPropertiesLines = [IO.File]::ReadAllLines($ndkProperties)
$revisionLines = @($ndkPropertiesLines | Where-Object { $_ -match '^Pkg\.Revision\s*=\s*(\S+)\s*$' })
if ($revisionLines.Count -ne 1 -or $revisionLines[0] -notmatch '^Pkg\.Revision\s*=\s*(\S+)\s*$') {
    throw 'NDK revision is missing or ambiguous'
}
$ndkRevision = $Matches[1]
$ndkPropertiesHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ndkProperties).Hash.ToLowerInvariant()
$clang = Join-Path $ndkPath 'toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android30-clang++.cmd'
if (!(Test-Path -LiteralPath $clang)) { throw 'Android AArch64 API30 compiler unavailable' }
$clang = (Resolve-Path -LiteralPath $clang -ErrorAction Stop).ProviderPath
$clangExecutable = Join-Path (Split-Path -Parent $clang) 'clang++.exe'
if (!(Test-Path -LiteralPath $clangExecutable -PathType Leaf)) {
    throw 'Underlying pinned clang++ executable unavailable'
}
$clangWrapperHashBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $clang).Hash.ToLowerInvariant()
$clangExecutableHashBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $clangExecutable).Hash.ToLowerInvariant()
$clangVersion = (& $clang --version 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($clangVersion)) {
    throw 'Pinned clang identity could not be read'
}
$first = Join-Path $out 'native-page-platform-collector.first'
$second = Join-Path $out 'native-page-platform-collector'
$arguments = @(
    '-std=c++17', '-D_GNU_SOURCE', '-O2', '-Wall', '-Wextra', '-Werror',
    '-fPIE', '-pie', '-static-libstdc++', '-Wl,-z,relro,-z,now,--build-id=sha1',
    (Join-Path $here 'collector_core.cpp'),
    (Join-Path $here 'native_page_platform_collector.cpp')
)
$canonicalArguments = @(
    '-std=c++17', '-D_GNU_SOURCE', '-O2', '-Wall', '-Wextra', '-Werror',
    '-fPIE', '-pie', '-static-libstdc++', '-Wl,-z,relro,-z,now,--build-id=sha1',
    'native-platform-collector/collector_core.cpp',
    'native-platform-collector/native_page_platform_collector.cpp'
)
$compileRecipe = [ordered]@{
    schema = 'native-page-platform-collector-compile-command-v1'
    compilerWrapperSha256 = $clangWrapperHashBefore
    compilerExecutableSha256 = $clangExecutableHashBefore
    ndkSourcePropertiesSha256 = $ndkPropertiesHash
    arguments = @($canonicalArguments)
    output = '<OUTPUT>'
}
$compileRecipeJson = $compileRecipe | ConvertTo-Json -Depth 4 -Compress
$compileCommandHash = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData(
        [Text.Encoding]::UTF8.GetBytes($compileRecipeJson))
).ToLowerInvariant()
& $clang @arguments -o $first
if ($LASTEXITCODE -ne 0) { throw 'First Android collector compilation failed' }
& $clang @arguments -o $second
if ($LASTEXITCODE -ne 0) { throw 'Second Android collector compilation failed' }
$firstHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $first).Hash.ToLowerInvariant()
$collectorHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $second).Hash.ToLowerInvariant()
if ($firstHash -ne $collectorHash) { throw 'Android collector build is not byte reproducible' }
$clangWrapperHashAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath $clang).Hash.ToLowerInvariant()
$clangExecutableHashAfter = (Get-FileHash -Algorithm SHA256 -LiteralPath $clangExecutable).Hash.ToLowerInvariant()
if ($clangWrapperHashAfter -ne $clangWrapperHashBefore -or
    $clangExecutableHashAfter -ne $clangExecutableHashBefore) {
    throw 'Pinned clang identity changed during compilation'
}

$bytes = [IO.File]::ReadAllBytes($second)
if ($bytes.Length -le 0 -or $bytes.Length -gt 4MB -or
    [Text.Encoding]::ASCII.GetString($bytes[0..3]) -ne ([char]0x7f + 'ELF') -or
    $bytes[4] -ne 2 -or $bytes[5] -ne 1 -or
    [BitConverter]::ToUInt16($bytes, 16) -ne 3 -or
    [BitConverter]::ToUInt16($bytes, 18) -ne 0xb7) {
    throw 'Collector is not a bounded little-endian ELF64 AArch64 PIE'
}

$deployPath = '/data/local/native-page-platform-collector/v1/native-page-platform-collector'
$service = "shell,v2,raw:exec /system/bin/sh -c 'p=$deployPath;d0=/data/local/native-page-platform-collector;d1=/data/local/native-page-platform-collector/v1;want=$collectorHash;z=0:0:555:directory;m0=`$(/system/bin/stat -c %u:%g:%a:%F `"`$d0`")||exit 120;m1=`$(/system/bin/stat -c %u:%g:%a:%F `"`$d1`")||exit 121;[ `"`$m0`" = `"`$z`" ]&&[ `"`$m1`" = `"`$z`" ]||exit 122;before=`$(/system/bin/stat -c %u:%g:%a:%F:%h:%d:%i `"`$p`")||exit 123;case `"`$before`" in 0:0:555:regular\ file:1:*) ;; *) exit 124;;esac;sum=`$(/system/bin/sha256sum `"`$p`")||exit 125;[ `"`$sum`" = `"`$want  `$p`" ]||exit 126;`"`$p`" --wire-v1;rc=`$?;after=`$(/system/bin/stat -c %u:%g:%a:%F:%h:%d:%i `"`$p`")||exit 127;endsum=`$(/system/bin/sha256sum `"`$p`")||exit 128;[ `"`$after`" = `"`$before`" ]&&[ `"`$endsum`" = `"`$sum`" ]||exit 129;exit `"`$rc`"'"
$serviceHash = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($service))
).ToLowerInvariant()
$admissionPath = Join-Path $here 'collector-admission.txt'
$admissionLines = [IO.File]::ReadAllLines($admissionPath)
if ($admissionLines.Count -ne 9 -or
    $admissionLines[0] -ne 'NATIVE_PAGE_PLATFORM_COLLECTOR_ADMISSION_V1' -or
    $admissionLines[1] -notmatch '^state=(pending-independent-review|independently-reviewed)$' -or
    $admissionLines[2] -notmatch '^collectorSha256=([0-9a-f]{64})$' -or
    $admissionLines[3] -notmatch '^serviceSha256=([0-9a-f]{64})$' -or
    $admissionLines[4] -notmatch '^compileCommandSha256=([0-9a-f]{64})$' -or
    $admissionLines[5] -notmatch '^downstreamBackendSha256=([0-9a-f]{64})$' -or
    $admissionLines[6] -notmatch '^downstreamPlatformSha256=([0-9a-f]{64})$' -or
    $admissionLines[7] -notmatch '^downstreamContractSha256=([0-9a-f]{64})$' -or
    $admissionLines[8] -ne 'END') {
    throw 'Collector admission policy grammar is invalid'
}
$admissionState = $admissionLines[1].Substring('state='.Length)
$expectedCollectorHash = $admissionLines[2].Substring('collectorSha256='.Length)
$expectedServiceHash = $admissionLines[3].Substring('serviceSha256='.Length)
$expectedCompileCommandHash = $admissionLines[4].Substring('compileCommandSha256='.Length)
$expectedBackendAuthorityHash = $admissionLines[5].Substring('downstreamBackendSha256='.Length)
$expectedPlatformAuthorityHash = $admissionLines[6].Substring('downstreamPlatformSha256='.Length)
$expectedDownstreamContractHash = $admissionLines[7].Substring('downstreamContractSha256='.Length)
if ($expectedCollectorHash -ne $collectorHash -or
    $expectedServiceHash -ne $serviceHash -or
    $expectedCompileCommandHash -ne $compileCommandHash -or
    $expectedBackendAuthorityHash -ne $backendAuthorityBefore.Sha256 -or
    $expectedPlatformAuthorityHash -ne $platformAuthorityBefore.Sha256 -or
    $expectedDownstreamContractHash -ne $downstreamContractHash) {
    throw ("Collector admission mismatch. actualCollector={0} actualService={1} actualCompileCommand={2} actualDownstreamBackend={3} actualDownstreamPlatform={4} actualDownstreamContract={5}" -f `
        $collectorHash, $serviceHash, $compileCommandHash,
        $backendAuthorityBefore.Sha256, $platformAuthorityBefore.Sha256,
        $downstreamContractHash)
}
$admissionReady = $admissionState -eq 'independently-reviewed'
$sources = [ordered]@{}
foreach ($name in @('build-and-test.ps1', 'collector-admission.txt',
                     'command_runner_posix_test.cpp',
                     'collector_core.hpp', 'collector_core.cpp',
                     'collector_core_test.cpp',
                     'native_page_platform_collector.cpp',
                     'README.md',
                     'test_collector_hardening_contract.py',
                     'test_downstream_contract.py')) {
    $sources[$name] = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $here $name)).Hash.ToLowerInvariant()
}
$manifest = [ordered]@{
    schema = 'native-page-platform-collector-build-v1'
    binary = $second
    bytes = $bytes.Length
    sha256 = $collectorHash
    reproducibleSecondBuildSha256 = $firstHash
    elfClass = 64
    elfData = 'little-endian'
    elfType = 'ET_DYN'
    elfMachine = 'AArch64'
    api = 30
    deploymentPath = $deployPath
    proposedService = $service
    proposedServiceSha256 = $serviceHash
    compileCommand = $compileRecipe
    compileCommandSha256 = $compileCommandHash
    executedArgumentsDiagnostic = @($arguments | ForEach-Object { [string]$_ })
    toolchain = [ordered]@{
        ndkRoot = $ndkPath
        ndkRevision = $ndkRevision
        ndkSourceProperties = $ndkProperties
        ndkSourcePropertiesSha256 = $ndkPropertiesHash
        clangWrapper = $clang
        clangWrapperSha256 = $clangWrapperHashBefore
        clangExecutable = $clangExecutable
        clangExecutableSha256 = $clangExecutableHashBefore
        clangVersion = $clangVersion
    }
    python = [ordered]@{
        path = $pythonPath
        sha256 = $pythonHashBefore
        version = $pythonVersion
    }
    downstreamContract = [ordered]@{
        authority = 'native-page-platform-collector-downstream-contract-v1'
        canonicalSha256 = $downstreamContractHash
        canonicalText = $downstreamContractText
        modules = [ordered]@{
            native_page_private_adb_platform_backend = [ordered]@{
                sourcePathDiagnostic = $backendAuthorityPath
                sha256 = $backendAuthorityBefore.Sha256
            }
            native_page_visual_platform_authority = [ordered]@{
                sourcePathDiagnostic = $platformAuthorityPath
                sha256 = $platformAuthorityBefore.Sha256
            }
        }
    }
    posixBehaviorTest = [ordered]@{
        distribution = $PosixTestDistribution
        compilerVersion = $posixCompilerVersion
        checks = 11
    }
    admission = [ordered]@{
        policy = $admissionPath
        state = $admissionState
        readyForDeployment = $admissionReady
    }
    sources = $sources
}
$manifestPath = Join-Path $out 'build-manifest.json'
[IO.File]::WriteAllText($manifestPath,
    ($manifest | ConvertTo-Json -Depth 4), [Text.UTF8Encoding]::new($false))
Remove-Item -LiteralPath $first
Write-Output ('OUTPUT=' + $out)
Write-Output ('COLLECTOR_SHA256=' + $collectorHash)
Write-Output ('PROPOSED_SERVICE_SHA256=' + $serviceHash)
Write-Output ('COMPILE_COMMAND_SHA256=' + $compileCommandHash)
Write-Output ('ADMISSION_STATE=' + $admissionState)
Write-Output ('MANIFEST=' + $manifestPath)
Write-Output 'HOST TESTED / REPRODUCIBLE ANDROID ARM64 BUILT ONLY. Admission state is reported above; no independent authorization is implied. No device or package action.'
