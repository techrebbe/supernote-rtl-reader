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
        '1D75E574776B3E90DC04AE42AB6685623324734DAE4DAD16AC10888005229D6A'
    ),
    @(
        $traceHelperTest,
        '224BA08B5D9A8252ED67F785448E65F3D7EFD1C86527A4E0F109BC241172D358'
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

$nativeSource = Join-Path $projectRoot 'native\spread_probe_native.cpp'
$expectedNativeSourceSha256 =
    '715183119972CC32599842C07CBC999334D0EF74E9CC587E9FCFE2ADEAC47CD5'
$nativeSourceSha256 = Get-NormalizedTextSha256 -LiteralPath $nativeSource
if ($nativeSourceSha256 -ne $expectedNativeSourceSha256) {
    throw (
        'Frozen native eraser source digest mismatch: expected ' +
        "$expectedNativeSourceSha256, got $nativeSourceSha256"
    )
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
    $nativeSource

if ($LASTEXITCODE -ne 0) {
    throw "NDK compilation failed with exit code $LASTEXITCODE"
}
$compiledNativeSha256 = (
    Get-FileHash -Algorithm SHA256 -LiteralPath $nativeOutput
).Hash

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

# LSPosed's module class loader maps native libraries directly from the APK.
# Keep the arm64 library uncompressed so Android's linker can mmap it.
if (
    (Get-NormalizedTextSha256 -LiteralPath $nativeSource) -ne
        $expectedNativeSourceSha256 -or
    (Get-FileHash -Algorithm SHA256 -LiteralPath $nativeOutput).Hash -ne
        $compiledNativeSha256
) {
    throw 'Native eraser source or compiled library changed before packaging.'
}
& jar u0f $unsignedApk `
    -C $nativeLibRoot lib
if ($LASTEXITCODE -ne 0) {
    throw "jar native-library update failed with exit code $LASTEXITCODE"
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

& $apksigner verify --verbose --print-certs $outputApk
if ($LASTEXITCODE -ne 0) {
    throw "apksigner verification failed with exit code $LASTEXITCODE"
}

Add-Type -AssemblyName System.IO.Compression.FileSystem
$apkArchive = [IO.Compression.ZipFile]::OpenRead($outputApk)
try {
    $requiredEntries = @(
        'AndroidManifest.xml',
        'assets/native_init',
        'assets/xposed_init',
        'classes.dex',
        'META-INF/xposed/scope.list',
        'lib/arm64-v8a/libspreadprobe.so'
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
    $nativeEntry = $entriesByName['lib/arm64-v8a/libspreadprobe.so']
    if ($nativeEntry.CompressedLength -ne $nativeEntry.Length) {
        throw 'APK native library is compressed and cannot be mmap-loaded.'
    }
    $nativeEntryStream = $nativeEntry.Open()
    try {
        $apkNativeSha256 = [BitConverter]::ToString(
            [Security.Cryptography.SHA256]::Create().ComputeHash(
                $nativeEntryStream
            )
        ).Replace('-', '')
    } finally {
        $nativeEntryStream.Dispose()
    }
    if ($apkNativeSha256 -ne $compiledNativeSha256) {
        throw 'APK native library does not match the verified compiler output.'
    }
} finally {
    $apkArchive.Dispose()
}

& $aapt2 dump badging $outputApk | Select-Object -First 12
Get-FileHash -Algorithm SHA256 -LiteralPath $outputApk
