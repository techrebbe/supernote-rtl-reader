param(
    [string]$AndroidSdk = $(
        if ($env:ANDROID_SDK_ROOT) {
            $env:ANDROID_SDK_ROOT
        } elseif ($env:ANDROID_HOME) {
            $env:ANDROID_HOME
        } else {
            Join-Path $env:LOCALAPPDATA 'Android\Sdk'
        }
    ),
    [string]$DebugKeystore = $(
        Join-Path $env:USERPROFILE '.android\debug.keystore'
    ),
    [Parameter(Mandatory = $true)]
    [string]$ExpectedSignerSha256
)

$ErrorActionPreference = 'Stop'

function Get-NormalizedTextSha256 {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath
    )

    $text = [System.IO.File]::ReadAllText(
        $LiteralPath,
        [System.Text.Encoding]::UTF8
    )
    $normalized = $text.Replace("`r`n", "`n").Replace("`r", "`n")
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($normalized)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [System.BitConverter]::ToString(
            $sha256.ComputeHash($bytes)
        ).Replace('-', '')
    } finally {
        $sha256.Dispose()
    }
}

$projectRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$repositoryRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $projectRoot '..')
)
$workspaceRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $projectRoot '..\..\..\..')
)
$buildRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $projectRoot 'build')
)

$traceHelperTest = Join-Path `
    $repositoryRoot `
    'scripts\test_trace_helper_fail_closed.ps1'
$traceHelperScript = Join-Path $projectRoot 'trace.ps1'
$verifiedTraceSources = @(
    @(
        $traceHelperScript,
        'ADEAD52DF5ACE68EE59949501AE764AEFE338DC6FEAC1AACD0259F05DA8C9E06'
    ),
    @(
        $traceHelperTest,
        'A6C3C249D3239EE4FEC9DD465B01182E6A493965FC82F0230B78963D8611CA3D'
    )
)
foreach ($verifiedTraceSource in $verifiedTraceSources) {
    $actualTraceSourceSha256 = Get-NormalizedTextSha256 `
        -LiteralPath $verifiedTraceSource[0]
    if ($actualTraceSourceSha256 -ne $verifiedTraceSource[1]) {
        throw (
            "Trace safety source digest mismatch for $($verifiedTraceSource[0]): " +
            "expected $($verifiedTraceSource[1]), got $actualTraceSourceSha256"
        )
    }
}
$windowsPowerShell = Join-Path $PSHOME 'powershell.exe'
& $windowsPowerShell `
    -NoProfile `
    -ExecutionPolicy Bypass `
    -File $traceHelperTest `
    -RepositoryRoot $repositoryRoot
if ($LASTEXITCODE -ne 0) {
    throw "Trace-helper tests failed with exit code $LASTEXITCODE"
}

$manifestPath = Join-Path $projectRoot 'AndroidManifest.xml'
[xml]$manifestXml = Get-Content -LiteralPath $manifestPath
$androidNamespace = 'http://schemas.android.com/apk/res/android'
$versionCode = $manifestXml.manifest.GetAttribute(
    'versionCode',
    $androidNamespace
)
$versionName = $manifestXml.manifest.GetAttribute(
    'versionName',
    $androidNamespace
)
if (-not $versionCode -or -not $versionName) {
    throw 'AndroidManifest.xml is missing versionCode or versionName'
}

if (-not $buildRoot.StartsWith($projectRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to clean build directory outside project: $buildRoot"
}

if (Test-Path -LiteralPath $buildRoot) {
    Remove-Item -LiteralPath $buildRoot -Recurse -Force
}

$classesDir = Join-Path $buildRoot 'classes'
$dexDir = Join-Path $buildRoot 'dex'
$artifactDir = Join-Path $buildRoot 'artifact'
New-Item -ItemType Directory -Force -Path `
    $classesDir, $dexDir, $artifactDir | Out-Null

$androidJar = Join-Path $AndroidSdk 'platforms\android-35\android.jar'
$buildTools = Join-Path $AndroidSdk 'build-tools\35.0.0'
$aapt2 = Join-Path $buildTools 'aapt2.exe'
$d8 = Join-Path $buildTools 'd8.bat'
$zipalign = Join-Path $buildTools 'zipalign.exe'
$apksigner = Join-Path $buildTools 'apksigner.bat'
foreach ($required in @(
    $androidJar,
    $aapt2,
    $d8,
    $zipalign,
    $apksigner,
    $DebugKeystore
)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Missing build dependency: $required"
    }
}

$legacySource = [System.IO.Path]::GetFullPath((Join-Path `
    $projectRoot `
    'src\com\techrebbe\supernote\spreadprobe\SpreadProbe.java'
))
$javaSources = @(
    Get-ChildItem -LiteralPath (Join-Path $projectRoot 'src') -Recurse -Filter '*.java' -File
    Get-ChildItem -LiteralPath (Join-Path $projectRoot 'stubs') -Recurse -Filter '*.java' -File
) | ForEach-Object FullName | Where-Object {
    -not [System.IO.Path]::GetFullPath($_).Equals(
        $legacySource,
        [System.StringComparison]::OrdinalIgnoreCase
    )
}

& javac `
    -source 8 `
    -target 8 `
    -encoding UTF-8 `
    -cp $androidJar `
    -d $classesDir `
    $javaSources

if ($LASTEXITCODE -ne 0) {
    throw "javac failed with exit code $LASTEXITCODE"
}

# Native Reader v2 is an exclusive Java-hook engine. Preserve the legacy
# source for forensic comparison, but exclude it from compilation entirely.
# The post-compile assertion also prevents a future indirect build input from
# silently reintroducing its executable entry point.
$legacyClassRoot = Join-Path `
    $classesDir `
    'com\techrebbe\supernote\spreadprobe'
if (-not $legacyClassRoot.StartsWith(
    $classesDir,
    [System.StringComparison]::OrdinalIgnoreCase
)) {
    throw "Refusing to filter classes outside build output: $legacyClassRoot"
}
if (Get-ChildItem -LiteralPath $legacyClassRoot -Filter 'SpreadProbe*.class' -File) {
    throw 'Legacy SpreadProbe executable classes entered the v2 build.'
}

$moduleJar = Join-Path $buildRoot 'spread-probe.jar'
Push-Location $classesDir
try {
    & jar cf $moduleJar com\techrebbe\supernote\spreadprobe
} finally {
    Pop-Location
}
if ($LASTEXITCODE -ne 0) {
    throw "jar class packaging failed with exit code $LASTEXITCODE"
}
if (-not (Test-Path -LiteralPath $moduleJar -PathType Leaf)) {
    throw "jar class packaging did not create $moduleJar"
}

& $d8 `
    --lib $androidJar `
    --min-api 27 `
    --output $dexDir `
    $moduleJar

if ($LASTEXITCODE -ne 0) {
    throw "d8 failed with exit code $LASTEXITCODE"
}

$unsignedApk = Join-Path $buildRoot 'spread-probe-unsigned.apk'
& $aapt2 link `
    -I $androidJar `
    --manifest $manifestPath `
    -A (Join-Path $projectRoot 'assets') `
    --min-sdk-version 27 `
    --target-sdk-version 28 `
    --version-code $versionCode `
    --version-name $versionName `
    -o $unsignedApk

if ($LASTEXITCODE -ne 0) {
    throw "aapt2 link failed with exit code $LASTEXITCODE"
}

& jar uf $unsignedApk `
    -C $dexDir classes.dex `
    -C (Join-Path $projectRoot 'meta') META-INF
if ($LASTEXITCODE -ne 0) {
    throw "jar dex/metadata update failed with exit code $LASTEXITCODE"
}

$alignedApk = Join-Path $buildRoot 'spread-probe-aligned.apk'
& $zipalign -f -p 4 $unsignedApk $alignedApk

if ($LASTEXITCODE -ne 0) {
    throw "zipalign failed with exit code $LASTEXITCODE"
}

$outputApk = Join-Path $artifactDir `
    "SupernoteNativeSpreadProbe-v$versionName.apk"
& $apksigner sign `
    --ks $DebugKeystore `
    --ks-key-alias androiddebugkey `
    --ks-pass pass:android `
    --key-pass pass:android `
    --out $outputApk `
    $alignedApk

if ($LASTEXITCODE -ne 0) {
    throw "apksigner failed with exit code $LASTEXITCODE"
}

$verificationOutput = @(
    & $apksigner verify --verbose --print-certs $outputApk 2>&1
)
$verificationOutput | ForEach-Object { Write-Host $_ }
if ($LASTEXITCODE -ne 0) {
    throw "apksigner verification failed with exit code $LASTEXITCODE"
}
$normalizedExpectedSigner = $ExpectedSignerSha256.Trim().ToLowerInvariant()
if ($normalizedExpectedSigner -notmatch '^[0-9a-f]{64}$') {
    throw 'Expected signer SHA-256 is not canonical lowercase hexadecimal.'
}
$signerLine = "Signer #1 certificate SHA-256 digest: $normalizedExpectedSigner"
if (-not ($verificationOutput -contains 'Number of signers: 1') -or
    -not ($verificationOutput -contains $signerLine)) {
    throw (
        'APK signer does not match the exact established upgrade identity: ' +
        $normalizedExpectedSigner
    )
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$apkArchive = [IO.Compression.ZipFile]::OpenRead($outputApk)
try {
    $requiredEntries = @(
        'AndroidManifest.xml',
        'assets/xposed_init',
        'classes.dex',
        'META-INF/xposed/scope.list'
    )
    $entriesByName = @{}
    foreach ($entry in $apkArchive.Entries) {
        if ($entriesByName.ContainsKey($entry.FullName)) {
            throw "APK contains duplicate entry: $($entry.FullName)"
        }
        $entriesByName[$entry.FullName] = $entry
    }
    foreach ($requiredEntry in $requiredEntries) {
        if (-not $entriesByName.ContainsKey($requiredEntry)) {
            throw "APK is missing required entry: $requiredEntry"
        }
        if ($entriesByName[$requiredEntry].Length -le 0) {
            throw "APK required entry is empty: $requiredEntry"
        }
    }
    foreach ($forbiddenEntry in @(
        'assets/native_init',
        'lib/arm64-v8a/libspreadprobe.so'
    )) {
        if ($entriesByName.ContainsKey($forbiddenEntry)) {
            throw "v2 APK contains forbidden legacy payload: $forbiddenEntry"
        }
    }
} finally {
    $apkArchive.Dispose()
}

& $aapt2 dump badging $outputApk | Select-Object -First 12
Get-FileHash -Algorithm SHA256 -LiteralPath $outputApk
