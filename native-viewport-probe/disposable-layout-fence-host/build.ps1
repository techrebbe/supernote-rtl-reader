[CmdletBinding()]
param(
    [string]$Jdk = $env:JAVA_HOME,
    [string]$AndroidSdk = $(if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT }
        else { $env:ANDROID_HOME })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Jdk)) { throw 'Pass -Jdk or set JAVA_HOME.' }
if ([string]::IsNullOrWhiteSpace($AndroidSdk)) {
    throw 'Pass -AndroidSdk or set ANDROID_SDK_ROOT/ANDROID_HOME.'
}
$hostRoot = $PSScriptRoot
. (Join-Path $hostRoot 'path-guard.ps1')
$javac = Join-Path $Jdk 'bin\javac.exe'
$jar = Join-Path $Jdk 'bin\jar.exe'
$tools = Join-Path $AndroidSdk 'build-tools\35.0.0'
$aapt = Join-Path $tools 'aapt.exe'
$d8 = Join-Path $tools 'd8.bat'
$zipalign = Join-Path $tools 'zipalign.exe'
$androidJar = Join-Path $AndroidSdk 'platforms\android-30\android.jar'
foreach ($path in @($javac, $jar, $aapt, $d8, $zipalign, $androidJar)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing build tool: $path" }
}
& (Join-Path $hostRoot 'test-host.ps1') -Jdk $Jdk
if ($LASTEXITCODE -ne 0) { throw 'Host proof tests failed.' }

$generation = New-IgnoredBuildGeneration $hostRoot 'apk-'
$classes = Join-Path $generation 'classes'
$dex = Join-Path $generation 'dex'
New-Item -ItemType Directory -Path $classes -ErrorAction Stop | Out-Null
New-Item -ItemType Directory -Path $dex -ErrorAction Stop | Out-Null
$null = Assert-IgnoredBuildPath $classes $hostRoot
$null = Assert-IgnoredBuildPath $dex $hostRoot
$sources = @(Get-ChildItem -LiteralPath (Join-Path $hostRoot 'src') -Recurse -File -Filter '*.java' |
    Sort-Object FullName | ForEach-Object { $_.FullName })
if ($sources.Count -ne 9) { throw "Unexpected synthetic source count: $($sources.Count)" }
& $javac -encoding UTF-8 --release 8 -classpath $androidJar -d $classes @sources
if ($LASTEXITCODE -ne 0) { throw 'Android synthetic compilation failed.' }
$classesJar = Join-Path $generation 'classes.jar'
& $jar --create --file $classesJar -C $classes .
if ($LASTEXITCODE -ne 0) { throw 'Class archiving failed.' }
& $d8 --min-api 30 --lib $androidJar --output $dex $classesJar
if ($LASTEXITCODE -ne 0) { throw 'Dex compilation failed.' }
if (-not (Test-Path -LiteralPath (Join-Path $dex 'classes.dex') -PathType Leaf)) {
    throw 'No compiled classes.dex.'
}
$baseApk = Join-Path $generation 'base.apk'
& $aapt package -f -M (Join-Path $hostRoot 'AndroidManifest.xml') -I $androidJar -F $baseApk
if ($LASTEXITCODE -ne 0) { throw 'Manifest packaging failed.' }
Push-Location -LiteralPath $dex
try {
    & $aapt add $baseApk 'classes.dex'
    if ($LASTEXITCODE -ne 0) { throw 'Dex packaging failed.' }
} finally { Pop-Location }
$apk = Join-Path $generation 'disposable-layout-fence-unsigned.apk'
& $zipalign -f -p 4 $baseApk $apk
if ($LASTEXITCODE -ne 0) { throw 'APK alignment failed.' }
& $zipalign -c 4 $apk
if ($LASTEXITCODE -ne 0) { throw 'APK alignment verification failed.' }
$null = Assert-IgnoredBuildPath $apk $hostRoot
$badging = @(& $aapt dump badging $apk)
if ($LASTEXITCODE -ne 0 -or
        -not ($badging -match "package: name='com.techrebbe.supernote.layoutfencetrial'")) {
    throw 'Unexpected APK package identity.'
}
$digest = (Get-FileHash -LiteralPath $apk -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Output "APK=$apk"
Write-Output "APK_SHA256=$digest"
Write-Output 'APK_IS_UNSIGNED=true'
