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
    [string]$AndroidNdk = $env:ANDROID_NDK_HOME,
    [string]$DebugKeystore = $(
        Join-Path $env:USERPROFILE '.android\debug.keystore'
    )
)

$ErrorActionPreference = 'Stop'

$projectRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$workspaceRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $projectRoot '..\..\..\..')
)
$buildRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $projectRoot 'build')
)

if (-not $AndroidNdk) {
    $AndroidNdk = Join-Path $AndroidSdk 'ndk\27.0.12077973'
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
$nativeLibRoot = Join-Path $buildRoot 'native'
$arm64LibDir = Join-Path $nativeLibRoot 'lib\arm64-v8a'
New-Item -ItemType Directory -Force -Path `
    $classesDir, $dexDir, $artifactDir, $arm64LibDir | Out-Null

$androidJar = Join-Path $AndroidSdk 'platforms\android-35\android.jar'
$buildTools = Join-Path $AndroidSdk 'build-tools\35.0.0'
$aapt2 = Join-Path $buildTools 'aapt2.exe'
$d8 = Join-Path $buildTools 'd8.bat'
$zipalign = Join-Path $buildTools 'zipalign.exe'
$apksigner = Join-Path $buildTools 'apksigner.bat'
$clang = Join-Path $AndroidNdk `
    'toolchains\llvm\prebuilt\windows-x86_64\bin\aarch64-linux-android27-clang++.cmd'

foreach ($required in @(
    $androidJar,
    $aapt2,
    $d8,
    $zipalign,
    $apksigner,
    $clang,
    $DebugKeystore
)) {
    if (-not (Test-Path -LiteralPath $required)) {
        throw "Missing build dependency: $required"
    }
}

$nativeOutput = Join-Path $arm64LibDir 'libspreadprobe.so'
& $clang `
    -shared `
    -fPIC `
    -std=c++17 `
    -O2 `
    -fvisibility=hidden `
    '-Wl,--build-id=sha1' `
    -llog `
    -ldl `
    -o $nativeOutput `
    (Join-Path $projectRoot 'native\spread_probe_native.cpp')

if ($LASTEXITCODE -ne 0) {
    throw "NDK compilation failed with exit code $LASTEXITCODE"
}

$javaSources = @(
    Get-ChildItem -LiteralPath (Join-Path $projectRoot 'src') -Recurse -Filter '*.java' -File
    Get-ChildItem -LiteralPath (Join-Path $projectRoot 'stubs') -Recurse -Filter '*.java' -File
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

$moduleJar = Join-Path $buildRoot 'spread-probe.jar'
Push-Location $classesDir
try {
    & jar cf $moduleJar com\techrebbe\supernote\spreadprobe
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

# LSPosed's module class loader maps native libraries directly from the APK.
# Keep the arm64 library uncompressed so Android's linker can mmap it.
& jar u0f $unsignedApk `
    -C $nativeLibRoot lib

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

& $apksigner verify --verbose --print-certs $outputApk
if ($LASTEXITCODE -ne 0) {
    throw "apksigner verification failed with exit code $LASTEXITCODE"
}

& $aapt2 dump badging $outputApk | Select-Object -First 12
Get-FileHash -Algorithm SHA256 -LiteralPath $outputApk
