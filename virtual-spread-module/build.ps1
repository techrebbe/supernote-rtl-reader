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
        Join-Path `
            ([Environment]::GetFolderPath('UserProfile')) `
            '.android/debug.keystore'
    ),
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$ExpectedSignerSha256 = '',
    [switch]$SkipTests,
    [switch]$AlignedOnly
)

$ErrorActionPreference = 'Stop'

if ($SkipTests -and -not $AlignedOnly) {
    throw '-SkipTests is permitted only for the no-signature aligned build'
}
if ($AlignedOnly -and $ExpectedSignerSha256) {
    throw '-ExpectedSignerSha256 is incompatible with -AlignedOnly'
}

$projectRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$buildRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $projectRoot 'build')
)
$stubRoot = [System.IO.Path]::GetFullPath(
    (Join-Path (Split-Path -Parent $projectRoot) 'native-spread-module/stubs')
)
$windowsHost = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT

if (-not $buildRoot.StartsWith(
        $projectRoot,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
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

$androidJar = Join-Path $AndroidSdk 'platforms/android-35/android.jar'
$buildTools = Join-Path $AndroidSdk 'build-tools/35.0.0'
$aapt2 = Join-Path $buildTools $(if ($windowsHost) {'aapt2.exe'} else {'aapt2'})
$d8 = Join-Path $buildTools $(if ($windowsHost) {'d8.bat'} else {'d8'})
$zipalign = Join-Path $buildTools $(if ($windowsHost) {'zipalign.exe'} else {'zipalign'})
$apksigner = Join-Path $buildTools $(if ($windowsHost) {'apksigner.bat'} else {'apksigner'})
foreach ($required in @(
    $androidJar,
    $aapt2,
    $d8,
    $zipalign,
    $stubRoot
)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Missing build dependency: $required"
    }
}
if (-not $AlignedOnly) {
    foreach ($required in @($apksigner, $DebugKeystore)) {
        if (-not (Test-Path -LiteralPath $required)) {
            throw "Missing signing dependency: $required"
        }
    }
}

if (-not $SkipTests) {
    & (Join-Path $projectRoot 'test.ps1')
    if ($LASTEXITCODE -ne 0) {
        throw "tests failed with exit code $LASTEXITCODE"
    }
}

$javaSources = @(
    Get-ChildItem -LiteralPath (Join-Path $projectRoot 'src') `
        -Recurse -Filter '*.java' -File
    Get-ChildItem -LiteralPath $stubRoot `
        -Recurse -Filter '*.java' -File
) | ForEach-Object FullName

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

$moduleJar = Join-Path $buildRoot 'virtual-spread-navigation.jar'
& jar cf $moduleJar -C $classesDir 'com/techrebbe/supernote/virtualspread'
if ($LASTEXITCODE -ne 0) {
    throw "module jar creation failed with exit code $LASTEXITCODE"
}

& $d8 `
    --lib $androidJar `
    --min-api 27 `
    --output $dexDir `
    $moduleJar
if ($LASTEXITCODE -ne 0) {
    throw "d8 failed with exit code $LASTEXITCODE"
}

$unsignedApk = Join-Path $buildRoot 'virtual-spread-unsigned.apk'
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
    throw "APK payload injection failed with exit code $LASTEXITCODE"
}

$archiveEntries = @(& jar tf $unsignedApk)
if ($LASTEXITCODE -ne 0) {
    throw "APK payload listing failed with exit code $LASTEXITCODE"
}
foreach ($requiredEntry in @(
    'classes.dex',
    'assets/xposed_init',
    'META-INF/xposed/scope.list'
)) {
    if ($archiveEntries -notcontains $requiredEntry) {
        throw "APK payload is missing required entry: $requiredEntry"
    }
}

$alignedApk = Join-Path $buildRoot 'virtual-spread-aligned.apk'
& $zipalign -f -p 4 $unsignedApk $alignedApk
if ($LASTEXITCODE -ne 0) {
    throw "zipalign failed with exit code $LASTEXITCODE"
}
if ($AlignedOnly) {
    Get-FileHash -Algorithm SHA256 -LiteralPath $alignedApk
    return
}

$outputApk = Join-Path $artifactDir `
    "SupernoteVirtualSpreadNavigation-v$versionName.apk"
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

$verification = @(
    & $apksigner verify --verbose --print-certs $outputApk 2>&1
)
$verificationExitCode = $LASTEXITCODE
$verification | ForEach-Object { Write-Host $_ }
if ($verificationExitCode -ne 0) {
    throw "apksigner verification failed with exit code $verificationExitCode"
}
if ($ExpectedSignerSha256) {
    $signerMatches = @(
        $verification |
            Select-String -Pattern `
                '^Signer #[0-9]+ certificate SHA-256 digest: ([0-9A-Fa-f:]+)$'
    )
    if ($signerMatches.Count -ne 1) {
        throw "Expected exactly one APK signer certificate"
    }
    $actualSignerSha256 = `
        $signerMatches[0].Matches[0].Groups[1].Value.Replace(':', '')
    if (-not $actualSignerSha256.Equals(
            $ExpectedSignerSha256,
            [System.StringComparison]::OrdinalIgnoreCase
        )) {
        throw "APK signer certificate does not match the expected release signer"
    }
}
& $aapt2 dump badging $outputApk | Select-Object -First 12
Get-FileHash -Algorithm SHA256 -LiteralPath $outputApk
