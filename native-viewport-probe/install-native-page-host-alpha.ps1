[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('SN078C10015092')]
    [string]$Serial,
    [Parameter(Mandatory = $true)]
    [IO.FileStream]$SessionLock,
    [string]$Jdk = $(
        if ($env:RTL_READER_BUILD_JDK) {
            $env:RTL_READER_BUILD_JDK
        } else {
            'C:\Program Files\Java\jdk-17'
        }
    ),
    [string]$AndroidSdk = $(
        if ($env:ANDROID_SDK_ROOT) {
            $env:ANDROID_SDK_ROOT
        } elseif ($env:ANDROID_HOME) {
            $env:ANDROID_HOME
        } else {
            Join-Path $env:LOCALAPPDATA 'Android\Sdk'
        }
    ),
    [string]$Apk = '',
    [string]$Metadata = '',
    [switch]$AllowPersistentUpgrade
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSBoundParameters.ContainsKey('Apk')) {
    if ([string]::IsNullOrWhiteSpace($Apk)) {
        throw 'Apk may not be explicitly empty.'
    }
} else {
    # Resolve script-relative defaults after parameter binding; Windows
    # PowerShell may expose an empty PSScriptRoot inside default expressions.
    $Apk = Join-Path $PSScriptRoot 'build\native-page-host-alpha\native-page-host-alpha.apk'
}
if ($PSBoundParameters.ContainsKey('Metadata')) {
    if ([string]::IsNullOrWhiteSpace($Metadata)) {
        throw 'Metadata may not be explicitly empty.'
    }
} else {
    $Metadata = Join-Path $PSScriptRoot 'build\native-page-host-alpha\native-page-host-alpha.json'
}

$authorizedSerial = 'SN078C10015092'
$authorizedModel = 'Supernote Nomad'
$authorizedSdk = '30'
$authorizedUser = '0'
$authorizedFingerprint = 'Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys'
$packageName = 'com.techrebbe.supernote.nativepagehost'
$versionCode = 2
$versionName = '0.0.2-native-page-visual-only'
$reviewedCheckpoint = '2eeadd701d25dfeaf978108c358326e8edfaf87d'
$reviewedUnsignedApkSha256 = '670c755fabb00df87c6b6714c3dc8b878aa22e3190d95585b24adce295756178'
$reviewedUnsignedAuthoritySha256 = '94783276471ad4797b9a4ebf2200ae7adfd1ce1fe6ad888e2b5df09b403cb647'
$reviewedDexSha256 = '15d24cef8f4c70cf167ab6e93ac817fc2e85af4bfca6bb392e2535dc04863ab6'
$reviewedSignerCertSha256 = 'd3f9ce76640125df1037e4536b680e29684da5ae7c171147f3206e26c7e568b4'
$reviewedSignedApkSha256 = '3798c204360db82941db7516e774517b273a51e025cce4848a642a5de61c6a03'
$javaSha256 = '9da06bd6c880c0c8d1a63e3716f8ef7996f146c41e6d339e4eafc93df28392f9'
$apksignerJarSha256 = '00ef9948f843fe395d2440ae3ef41405b8040a6d5d46493bd1902ac0ee6deae7'
$aaptSha256 = 'db0ba2050b8f6b37185d2ba458d6e25b565aefa3f3b96040adf0a82c3469ce3c'
$adbSha256 = 'b4a6b455702684652cccf7b46258b29e653538904359a58fd4931cf3ef286b3f'
$buildTools = Join-Path $AndroidSdk 'build-tools\35.0.0'
$aapt = Join-Path $buildTools 'aapt.exe'
$apksignerJar = Join-Path $buildTools 'lib\apksigner.jar'
$java = Join-Path $Jdk 'bin\java.exe'
$adb = Join-Path $AndroidSdk 'platform-tools\adb.exe'
$fixedLockPath = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) (
    'SupernoteAlpha\NativePageHostLocks\' + $authorizedSerial + '\session.lock')

function Get-Sha256([string]$LiteralPath) {
    return (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-RegularFile([string]$LiteralPath, [string]$Label) {
    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
        throw "$Label is missing: $LiteralPath"
    }
    $item = Get-Item -LiteralPath $LiteralPath -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label may not be a reparse point: $LiteralPath"
    }
}

function Assert-PinnedFile([string]$LiteralPath, [string]$ExpectedSha256, [string]$Label) {
    Assert-RegularFile $LiteralPath $Label
    if ((Get-Sha256 $LiteralPath) -cne $ExpectedSha256) {
        throw "$Label differs from its fixed SHA-256 authority."
    }
}

function Assert-NoReparseComponents([string]$LiteralPath, [string]$Label) {
    $full = [IO.Path]::GetFullPath($LiteralPath)
    $root = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "$Label is not an absolute local path."
    }
    $current = $root
    if (Test-Path -LiteralPath $current) {
        $rootItem = Get-Item -LiteralPath $current -Force
        if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label has a reparse-point path root."
        }
    }
    $relative = $full.Substring($root.Length)
    foreach ($component in @($relative -split '[\\/]' | Where-Object { $_.Length -gt 0 })) {
        $current = Join-Path $current $component
        if (-not (Test-Path -LiteralPath $current)) {
            break
        }
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label contains a reparse point: $current"
        }
    }
    return $full
}

function Invoke-WithoutJavaInjection([scriptblock]$Action) {
    $removed = @{}
    $names = @(
        'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS',
        'JDK_JAVAC_OPTIONS', 'JAVA_OPTIONS', 'CLASSPATH'
    )
    foreach ($entry in [Environment]::GetEnvironmentVariables('Process').GetEnumerator()) {
        $name = [string]$entry.Key
        if ($names -ccontains $name.ToUpperInvariant()) {
            $removed[$name] = [string]$entry.Value
            Remove-Item -LiteralPath ('Env:\' + $name)
        }
    }
    try {
        return & $Action
    } finally {
        foreach ($name in $removed.Keys) {
            [Environment]::SetEnvironmentVariable($name, $removed[$name], 'Process')
        }
    }
}

function Get-ApkSignerSha256([string]$ApkPath) {
    $verification = @(Invoke-WithoutJavaInjection {
        $lines = @(& $java -jar $apksignerJar verify --verbose --print-certs $ApkPath 2>&1 |
            ForEach-Object { [string]$_ })
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            throw "APK signature verification failed with exit code $exitCode."
        }
        return $lines
    })
    $count = @($verification | Where-Object { $_ -ceq 'Number of signers: 1' }).Count
    $matches = @($verification | ForEach-Object {
        if ($_ -cmatch '^Signer #1 certificate SHA-256 digest: ([0-9a-f]{64})$') {
            $Matches[1]
        }
    })
    if ($count -ne 1 -or $matches.Count -ne 1) {
        throw 'APK does not have exactly one canonical signer.'
    }
    return $matches[0]
}

function Get-ClassesDexSha256([string]$ApkPath) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($ApkPath)
    try {
        $entries = @($archive.Entries | Where-Object { $_.FullName -ceq 'classes.dex' })
        if ($entries.Count -ne 1) {
            throw 'APK must contain exactly one classes.dex.'
        }
        $stream = $entries[0].Open()
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
        } finally {
            $sha.Dispose()
            $stream.Dispose()
        }
    } finally {
        $archive.Dispose()
    }
}

function Get-ApkIdentity([string]$ApkPath) {
    $badging = @(& $aapt dump badging $ApkPath 2>&1 | ForEach-Object { [string]$_ })
    $badgingExitCode = $LASTEXITCODE
    if ($badgingExitCode -ne 0) {
        throw "APK badging inspection failed with exit code $badgingExitCode."
    }
    $matches = @($badging | ForEach-Object {
        if ($_ -cmatch "^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']+)'(?: |$)") {
            [PSCustomObject]@{
                Package = $Matches[1]
                Code = [int]$Matches[2]
                Name = $Matches[3]
            }
        }
    })
    if ($matches.Count -ne 1) {
        throw 'APK package identity is ambiguous.'
    }
    return $matches[0]
}

function Invoke-Adb([string[]]$Arguments, [string]$Label) {
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        # ADB writes successful transfer progress (for example, `adb pull`)
        # to stderr.  Windows PowerShell represents that text as ErrorRecord
        # objects, so capture it without letting the script-wide Stop policy
        # terminate before the real process exit code is checked below.
        $ErrorActionPreference = 'Continue'
        $output = @(& $adb @Arguments 2>&1 | ForEach-Object { [string]$_ })
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
    if ($exitCode -ne 0) {
        throw "$Label failed with exit code $exitCode."
    }
    return $output
}

function Get-SingleAdbValue([string[]]$Arguments, [string]$Label) {
    $output = @(Invoke-Adb $Arguments $Label)
    if ($output.Count -ne 1) {
        throw "$Label did not return exactly one line."
    }
    return $output[0].Trim()
}

function Assert-SessionLock() {
    if ($null -eq $SessionLock -or -not $SessionLock.CanRead -or -not $SessionLock.CanWrite -or
            $SessionLock.SafeFileHandle.IsClosed -or $SessionLock.SafeFileHandle.IsInvalid) {
        throw 'A live read/write alpha session lock is required.'
    }
    $expected = [IO.Path]::GetFullPath($fixedLockPath)
    $actual = [IO.Path]::GetFullPath($SessionLock.Name)
    if (-not $actual.Equals($expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Alpha session lock path differs from the fixed per-device lock.'
    }
    Assert-NoReparseComponents $actual 'Alpha session lock path' | Out-Null
    Assert-RegularFile $actual 'Alpha session lock file'
    $second = $null
    try {
        $second = [IO.File]::Open(
            $actual, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
    } catch [IO.IOException] {
        return
    } finally {
        if ($null -ne $second) {
            $second.Dispose()
        }
    }
    throw 'Alpha session lock is not held exclusively.'
}

function Resolve-InstalledBasePathResult([int]$ExitCode, [string[]]$Output) {
    $lines = @($Output)
    if ($ExitCode -eq 1) {
        if ($lines.Count -eq 0) {
            return
        }
        throw 'Absent-package lookup returned output instead of the exact empty result.'
    }
    if ($ExitCode -ne 0) {
        throw "Installed-package lookup failed with exit code $ExitCode."
    }
    if ($lines.Count -ne 1) {
        throw 'Successful installed-package lookup did not return exactly one path line.'
    }
    if ($lines[0] -cnotmatch '\Apackage:(/(?:[A-Za-z0-9._=+~-]+/)+base[.]apk)\z') {
        throw 'Successful installed-package lookup returned a malformed package path.'
    }
    $path = $Matches[1]
    $components = @($path.Split(
            [char[]]@('/'), [StringSplitOptions]::RemoveEmptyEntries))
    if (@($components | Where-Object { $_ -in @('.', '..') }).Count -ne 0) {
        throw 'Successful installed-package lookup returned a traversal component.'
    }
    return $path
}

function Get-InstalledBasePath() {
    $output = @(& $adb -s $Serial shell pm path $packageName 2>&1 |
        ForEach-Object { [string]$_ })
    $exitCode = $LASTEXITCODE
    return Resolve-InstalledBasePathResult -ExitCode $exitCode -Output $output
}

function Read-InstalledApk([string]$RemotePath) {
    $temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) ('native-page-host-alpha-install-' + [Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($temporaryDirectory) | Out-Null
    $localApk = Join-Path $temporaryDirectory 'base.apk'
    try {
        Invoke-Adb @('-s', $Serial, 'pull', $RemotePath, $localApk) 'Installed base APK readback' | Out-Null
        Assert-RegularFile $localApk 'Installed base APK readback'
        return [PSCustomObject]@{
            Sha256 = Get-Sha256 $localApk
            SignerSha256 = Get-ApkSignerSha256 $localApk
            Identity = Get-ApkIdentity $localApk
        }
    } finally {
        if (Test-Path -LiteralPath $localApk -PathType Leaf) {
            Remove-Item -LiteralPath $localApk -Force
        }
        if (Test-Path -LiteralPath $temporaryDirectory -PathType Container) {
            Remove-Item -LiteralPath $temporaryDirectory -Force
        }
    }
}

function Assert-HostQuiescent() {
    $pidOutput = @(& $adb -s $Serial shell pidof $packageName 2>&1 | ForEach-Object { [string]$_ })
    $pidExitCode = $LASTEXITCODE
    if ($pidExitCode -eq 0 -and @($pidOutput | Where-Object { $_ -match '[0-9]' }).Count -gt 0) {
        throw 'Native page host process is running; refusing package replacement.'
    }
    if ($pidExitCode -notin @(0, 1)) {
        throw "Native page host process check failed with exit code $pidExitCode."
    }

    $activities = Invoke-Adb @('-s', $Serial, 'shell', 'dumpsys', 'activity', 'activities') 'Host task check'
    if (@($activities | Where-Object { $_.Contains($packageName) }).Count -gt 0) {
        throw 'Native page host task still exists; refusing package replacement.'
    }
    $displays = Invoke-Adb @('-s', $Serial, 'shell', 'dumpsys', 'display') 'Host display check'
    if (@($displays | Where-Object { $_.Contains($packageName) }).Count -gt 0) {
        throw 'Native page host still owns or names a display; refusing package replacement.'
    }
}

if ($Serial -cne $authorizedSerial) {
    throw 'Only the exact authorized Nomad serial is admitted.'
}
Assert-SessionLock
foreach ($required in @($Apk, $Metadata, $aapt, $apksignerJar, $java, $adb)) {
    Assert-RegularFile $required 'Required alpha install input/tool'
}
Assert-PinnedFile $java $javaSha256 'Pinned java.exe'
Assert-PinnedFile $apksignerJar $apksignerJarSha256 'Pinned apksigner.jar'
Assert-PinnedFile $aapt $aaptSha256 'Pinned aapt.exe'
Assert-PinnedFile $adb $adbSha256 'Pinned adb.exe'

try {
    $record = [IO.File]::ReadAllText($Metadata) | ConvertFrom-Json
} catch {
    throw 'Alpha APK metadata is not valid JSON.'
}
$expectedMetadataFields = @(
    'schema', 'package', 'versionCode', 'versionName', 'signedApkPath',
    'signedApkSha256', 'signerCertSha256', 'reviewedUnsignedApkSha256',
    'reviewedUnsignedAuthoritySha256', 'dexSha256', 'checkpoint',
    'diagnosticOnly', 'reproducibleUnsignedAuthorityPreserved',
    'formalReleaseArtifact'
)
$metadataFields = @($record.PSObject.Properties.Name)
if ($metadataFields.Count -ne $expectedMetadataFields.Count -or
        @($metadataFields | Where-Object { $expectedMetadataFields -cnotcontains $_ }).Count -ne 0) {
    throw 'Alpha APK metadata field topology changed.'
}
$apkFull = [IO.Path]::GetFullPath($Apk)
$metadataFull = [IO.Path]::GetFullPath($Metadata)
$apkParent = Split-Path -Parent $apkFull
$metadataParent = Split-Path -Parent $metadataFull
if (-not $apkParent.Equals($metadataParent, [StringComparison]::OrdinalIgnoreCase) -or
        (Split-Path -Leaf $apkFull) -cne 'native-page-host-alpha.apk' -or
        (Split-Path -Leaf $metadataFull) -cne 'native-page-host-alpha.json') {
    throw 'Alpha APK and metadata must use their fixed adjacent publication paths.'
}
$apkSha256 = Get-Sha256 $Apk
$signerSha256 = Get-ApkSignerSha256 $Apk
$dexSha256 = Get-ClassesDexSha256 $Apk
$identity = Get-ApkIdentity $Apk
if ($record.schema -cne 'native-page-host-local-alpha-apk-v1' -or
        $record.package -cne $packageName -or
        $identity.Package -cne $packageName -or
        $identity.Code -ne $versionCode -or
        $identity.Name -cne $versionName -or
        [int]$record.versionCode -ne $versionCode -or
        $record.versionName -cne $versionName -or
        $record.signedApkPath -cne 'native-page-host-alpha.apk' -or
        $apkSha256 -cne $reviewedSignedApkSha256 -or
        $record.signedApkSha256 -cne $reviewedSignedApkSha256 -or
        $signerSha256 -cne $reviewedSignerCertSha256 -or
        $record.signerCertSha256 -cne $reviewedSignerCertSha256 -or
        $record.reviewedUnsignedApkSha256 -cne $reviewedUnsignedApkSha256 -or
        $record.reviewedUnsignedAuthoritySha256 -cne $reviewedUnsignedAuthoritySha256 -or
        $dexSha256 -cne $reviewedDexSha256 -or
        $record.dexSha256 -cne $reviewedDexSha256 -or
        $record.checkpoint -cne $reviewedCheckpoint -or
        $record.diagnosticOnly -ne $true -or
        $record.reproducibleUnsignedAuthorityPreserved -ne $true -or
        $record.formalReleaseArtifact -ne $false) {
    throw 'Alpha APK or metadata differs from the independently fixed local alpha authority.'
}

$state = Get-SingleAdbValue @('-s', $authorizedSerial, 'get-state') 'Explicit ADB target check'
if ($state -cne 'device') {
    throw 'The explicitly selected ADB target is not in device state.'
}
$reportedSerial = Get-SingleAdbValue @('-s', $authorizedSerial, 'get-serialno') 'ADB serial identity check'
$model = Get-SingleAdbValue @('-s', $authorizedSerial, 'shell', 'getprop', 'ro.product.model') 'Nomad model check'
$sdk = Get-SingleAdbValue @('-s', $authorizedSerial, 'shell', 'getprop', 'ro.build.version.sdk') 'Nomad SDK check'
$fingerprint = Get-SingleAdbValue @('-s', $authorizedSerial, 'shell', 'getprop', 'ro.build.fingerprint') 'Nomad firmware check'
$currentUser = Get-SingleAdbValue @('-s', $authorizedSerial, 'shell', 'am', 'get-current-user') 'Nomad user check'
if ($reportedSerial -cne $authorizedSerial -or $model -cne $authorizedModel -or
        $sdk -cne $authorizedSdk -or $fingerprint -cne $authorizedFingerprint -or
        $currentUser -cne $authorizedUser) {
    throw 'ADB target differs from the exact authorized Nomad model/firmware identity.'
}
Assert-HostQuiescent

$priorPackageState = 'absent'
$rollbackState = 'uninstall-required'
$existingPath = Get-InstalledBasePath
if ($null -ne $existingPath) {
    $existing = Read-InstalledApk $existingPath
    if ($existing.Identity.Package -cne $packageName) {
        throw 'Installed base APK package identity is inconsistent.'
    }
    if ($existing.SignerSha256 -cne $signerSha256) {
        throw 'Installed alpha uses a different signer; refusing to uninstall or replace it.'
    }
    if ($existing.Identity.Code -gt $identity.Code) {
        throw 'Installed alpha has a newer version code; refusing a downgrade.'
    }
    if ($existing.Sha256 -ceq $apkSha256) {
        $priorPackageState = 'same'
        $rollbackState = 'unchanged'
    } elseif (-not $AllowPersistentUpgrade) {
        throw 'A compatible but different alpha is installed. Pass -AllowPersistentUpgrade to authorize a non-reversible package/data upgrade.'
    } else {
        $priorPackageState = 'upgraded'
        $rollbackState = 'not-exact'
    }
}

if ($priorPackageState -cne 'same') {
    $installOutput = Invoke-Adb @('-s', $Serial, 'install', '-r', $Apk) 'Upgrade-compatible alpha install'
    if (@($installOutput | Where-Object { $_.Trim() -ceq 'Success' }).Count -ne 1) {
        throw 'ADB install did not report exactly one Success result.'
    }
}

$installedPath = Get-InstalledBasePath
if ($null -eq $installedPath) {
    throw 'Installed alpha package was not found after install admission.'
}
$installed = Read-InstalledApk $installedPath
if ($installed.Sha256 -cne $apkSha256 -or
        $installed.SignerSha256 -cne $signerSha256 -or
        $installed.Identity.Package -cne $packageName -or
        $installed.Identity.Code -ne $identity.Code -or
        $installed.Identity.Name -cne $identity.Name) {
    throw 'Installed alpha readback differs from the exact verified local APK.'
}

Write-Output (
    'NATIVE_PAGE_HOST_ALPHA_INSTALLED serial=' + $Serial +
    ' package=' + $packageName +
    ' versionCode=' + $identity.Code +
    ' apkSha256=' + $apkSha256 +
    ' signerSha256=' + $signerSha256 +
    ' priorPackage=' + $priorPackageState +
    ' packageRollback=' + $rollbackState)
