# Creates an ignored, short-lived test key. Never reads the user's debug key.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$UnsignedApk,
    [string]$Jdk = $env:JAVA_HOME,
    [string]$AndroidSdk = $(if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT }
        else { $env:ANDROID_HOME })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Jdk) -or
        [string]::IsNullOrWhiteSpace($AndroidSdk)) {
    throw 'Pass -Jdk/-AndroidSdk or set JAVA_HOME/ANDROID_SDK_ROOT.'
}
$root = $PSScriptRoot
. (Join-Path $root 'path-guard.ps1')
$buildRoot = [IO.Path]::GetFullPath((Join-Path $root 'build'))
$source = [IO.Path]::GetFullPath($UnsignedApk)
if (-not $source.StartsWith($buildRoot + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($source) -cne 'disposable-no-child-trial-unsigned.apk' -or
        -not (Test-Path -LiteralPath $source -PathType Leaf)) {
    throw "Only this host's ignored, generated unsigned APK may be signed."
}
$null = Assert-IgnoredBuildPath $source $root
$keytool = Join-Path $Jdk 'bin\keytool.exe'
$apksigner = Join-Path $AndroidSdk 'build-tools\35.0.0\apksigner.bat'
$aapt = Join-Path $AndroidSdk 'build-tools\35.0.0\aapt.exe'
foreach ($tool in @($keytool, $apksigner, $aapt)) {
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) {
        throw "Missing local signing tool: $tool"
    }
}
$badging = @(& $aapt dump badging $source)
if ($LASTEXITCODE -ne 0 -or
        -not ($badging -match "package: name='com.techrebbe.supernote.leasetrial'")) {
    throw 'Unsigned APK is not the isolated trial package.'
}
$generation = New-IgnoredBuildGeneration $root 'sign-'
$null = Assert-IgnoredBuildPath $source $root
$null = Assert-IgnoredBuildPath $generation $root
$keystore = Join-Path $generation 'ephemeral-emulator-only.p12'
$signed = Join-Path $generation 'disposable-no-child-trial-signed.apk'
# Disposable random password; it is never printed, checked in, or reused.
$password = [Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')
try {
    $null = Assert-IgnoredBuildPath $keystore $root
    & $keytool -genkeypair -noprompt -alias lease-trial -keyalg RSA -keysize 3072 `
        -validity 7 -storetype PKCS12 -keystore $keystore -storepass $password `
        -keypass $password -dname 'CN=Disposable Emulator Lease Trial,O=Local Test,C=US'
    if ($LASTEXITCODE -ne 0) { throw 'Ephemeral test-key creation failed.' }
    $null = Assert-IgnoredBuildPath $keystore $root
    $null = Assert-IgnoredBuildPath $source $root
    $null = Assert-IgnoredBuildPath $signed $root
    & $apksigner sign --ks $keystore --ks-key-alias lease-trial `
        --ks-pass "pass:$password" --key-pass "pass:$password" `
        --out $signed $source
    if ($LASTEXITCODE -ne 0) { throw 'Disposable APK signing failed.' }
    $null = Assert-IgnoredBuildPath $generation $root
    $null = Assert-IgnoredBuildPath $keystore $root
    $null = Assert-IgnoredBuildPath $source $root
    $null = Assert-IgnoredBuildPath $signed $root
} finally {
    $password = $null
}
$verify = @(& $apksigner verify --verbose --print-certs $signed)
if ($LASTEXITCODE -ne 0) { throw 'Signed APK verification failed.' }
$certs = @($verify | Where-Object {
    $_ -cmatch '^Signer #1 certificate SHA-256 digest: ([a-fA-F0-9]{64})$'
})
if ($certs.Count -ne 1 -or
        $certs[0] -cnotmatch '^Signer #1 certificate SHA-256 digest: ([a-fA-F0-9]{64})$') {
    throw 'Exactly one test signer certificate was not verified.'
}
$certHash = $Matches[1].ToLowerInvariant()
$apkHash = (Get-FileHash -LiteralPath $signed -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Output "SIGNED_APK=$signed"
Write-Output "SIGNED_APK_SHA256=$apkHash"
Write-Output "CERT_SHA256=$certHash"
Write-Output "EPHEMERAL_KEYSTORE=$keystore"
Write-Output 'EMULATOR_ONLY=true'
