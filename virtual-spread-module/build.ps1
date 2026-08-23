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
    )
)

$ErrorActionPreference = 'Stop'

$projectRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$buildRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $projectRoot 'build')
)
$stubRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $projectRoot '..\native-spread-module\stubs')
)

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
    $DebugKeystore,
    $stubRoot
)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Missing build dependency: $required"
    }
}

& (Join-Path $projectRoot 'test.ps1')
if ($LASTEXITCODE -ne 0) {
    throw "tests failed with exit code $LASTEXITCODE"
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
Push-Location $classesDir
try {
    & jar cf $moduleJar com\techrebbe\supernote\virtualspread
} finally {
    Pop-Location
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

$alignedApk = Join-Path $buildRoot 'virtual-spread-aligned.apk'
& $zipalign -f -p 4 $unsignedApk $alignedApk
if ($LASTEXITCODE -ne 0) {
    throw "zipalign failed with exit code $LASTEXITCODE"
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

& $apksigner verify --verbose --print-certs $outputApk
if ($LASTEXITCODE -ne 0) {
    throw "apksigner verification failed with exit code $LASTEXITCODE"
}
& $aapt2 dump badging $outputApk | Select-Object -First 12
Get-FileHash -Algorithm SHA256 -LiteralPath $outputApk
