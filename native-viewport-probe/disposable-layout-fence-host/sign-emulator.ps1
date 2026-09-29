# Sign only a freshly built, ignored APK for the disposable layout-fence app.
# The key is emulator-only and is never read from the user's Android debug key.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$UnsignedApk,
    [Parameter(Mandatory = $true)][string]$ExpectedUnsignedSha256,
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
$hostRoot = $PSScriptRoot
. (Join-Path $hostRoot 'path-guard.ps1')
$buildRoot = [IO.Path]::GetFullPath((Join-Path $hostRoot 'build'))
$source = [IO.Path]::GetFullPath($UnsignedApk)
if (-not $source.StartsWith($buildRoot + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($source) -cne 'disposable-layout-fence-unsigned.apk' -or
        -not (Test-Path -LiteralPath $source -PathType Leaf)) {
    throw "Only this host's ignored, generated unsigned APK may be signed."
}
$null = Assert-IgnoredBuildPath $source $hostRoot
if ($ExpectedUnsignedSha256 -cnotmatch '^[a-f0-9]{64}$' -or
        (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $ExpectedUnsignedSha256) {
    throw 'Unsigned APK does not match the reviewed build hash.'
}
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
        @($badging | Where-Object {
            $_ -cmatch "^package: name='com\.techrebbe\.supernote\.layoutfencetrial' versionCode='1' "
        }).Count -ne 1) {
    throw 'Unsigned APK is not the isolated layout-fence trial package.'
}
$generation = New-IgnoredBuildGeneration $hostRoot 'sign-'
$null = Assert-IgnoredBuildPath $generation $hostRoot
$keystore = Join-Path $generation 'ephemeral-layout-emulator-only.p12'
$signed = Join-Path $generation 'disposable-layout-fence-signed.apk'
$env:LAYOUT_TRIAL_PASSWORD = [Guid]::NewGuid().ToString('N') +
    [Guid]::NewGuid().ToString('N')
try {
    $null = Assert-IgnoredBuildPath $keystore $hostRoot
    & $keytool -genkeypair -noprompt -alias layout-trial -keyalg RSA -keysize 3072 `
        -validity 7 -storetype PKCS12 -keystore $keystore `
        -storepass:env LAYOUT_TRIAL_PASSWORD -keypass:env LAYOUT_TRIAL_PASSWORD `
        -dname 'CN=Disposable Emulator Layout Trial,O=Local Test,C=US'
    if ($LASTEXITCODE -ne 0) { throw 'Ephemeral test-key creation failed.' }
    $null = Assert-IgnoredBuildPath $keystore $hostRoot
    $null = Assert-IgnoredBuildPath $source $hostRoot
    $null = Assert-IgnoredBuildPath $signed $hostRoot
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne
            $ExpectedUnsignedSha256) {
        throw 'Unsigned APK changed before signing.'
    }
    & $apksigner sign --ks $keystore --ks-key-alias layout-trial `
        --ks-pass env:LAYOUT_TRIAL_PASSWORD --key-pass env:LAYOUT_TRIAL_PASSWORD `
        --out $signed $source
    if ($LASTEXITCODE -ne 0) { throw 'Disposable APK signing failed.' }
} finally {
    Remove-Item Env:LAYOUT_TRIAL_PASSWORD -ErrorAction SilentlyContinue
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
$signerCounts = @($verify | Where-Object { $_ -ceq 'Number of signers: 1' })
if ($signerCounts.Count -ne 1) { throw 'Unexpected signer count.' }
$certMatch = [regex]::Match($certs[0],
    '^Signer #1 certificate SHA-256 digest: ([a-fA-F0-9]{64})$')
if (-not $certMatch.Success) { throw 'Signer digest is missing.' }
$certHash = $certMatch.Groups[1].Value.ToLowerInvariant()
$signedBadging = @(& $aapt dump badging $signed)
if ($LASTEXITCODE -ne 0 -or
        @($signedBadging | Where-Object {
            $_ -cmatch "^package: name='com\.techrebbe\.supernote\.layoutfencetrial' versionCode='1' "
        }).Count -ne 1) {
    throw 'Signed APK package identity changed.'
}
$apkHash = (Get-FileHash -LiteralPath $signed -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Output "SIGNED_APK=$signed"
Write-Output "SIGNED_APK_SHA256=$apkHash"
Write-Output "CERT_SHA256=$certHash"
Write-Output 'EMULATOR_ONLY=true'
