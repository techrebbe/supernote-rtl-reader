[CmdletBinding()]
param(
    [string]$Jdk = $env:JAVA_HOME,
    [string]$AndroidSdk = $(if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT }
        else { $env:ANDROID_HOME })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Jdk) -or [string]::IsNullOrWhiteSpace($AndroidSdk)) {
    throw 'Pass -Jdk and -AndroidSdk for an offline unsigned build.'
}
$root = $PSScriptRoot
$java = Join-Path $Jdk 'bin\java.exe'
$javac = Join-Path $Jdk 'bin\javac.exe'
$jar = Join-Path $Jdk 'bin\jar.exe'
$tools = Join-Path $AndroidSdk 'build-tools\35.0.0'
$aapt = Join-Path $tools 'aapt.exe'
$d8 = Join-Path $tools 'd8.bat'
$zipalign = Join-Path $tools 'zipalign.exe'
$androidJar = Join-Path $AndroidSdk 'platforms\android-30\android.jar'
foreach ($path in @($java, $javac, $jar, $aapt, $d8, $zipalign, $androidJar)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing build tool: $path"
    }
}
& (Join-Path $root 'test-host.ps1') -Jdk $Jdk
if ($LASTEXITCODE -ne 0) { throw 'Tile trial host tests failed.' }

# A fresh, ignored generation prevents accidental reuse of an older APK.
$generation = Join-Path $root ('build\apk-' + [Guid]::NewGuid().ToString('N'))
$classes = Join-Path $generation 'classes'
$dex = Join-Path $generation 'dex'
New-Item -ItemType Directory -Path $classes -ErrorAction Stop | Out-Null
New-Item -ItemType Directory -Path $dex -ErrorAction Stop | Out-Null
$sources = @(Get-ChildItem -LiteralPath (Join-Path $root 'src') -Recurse -File `
    -Filter '*.java' | Sort-Object FullName | ForEach-Object { $_.FullName })
if ($sources.Count -ne 4) { throw 'Unexpected tile host Java source inventory.' }
& $javac -encoding UTF-8 --release 8 -classpath $androidJar -d $classes @sources
if ($LASTEXITCODE -ne 0) { throw 'Tile Android compilation failed.' }
$classesJar = Join-Path $generation 'classes.jar'
& $jar --create --file $classesJar -C $classes .
if ($LASTEXITCODE -ne 0) { throw 'Tile class archiving failed.' }
& $d8 --min-api 30 --lib $androidJar --output $dex $classesJar
if ($LASTEXITCODE -ne 0) { throw 'Tile Dex compilation failed.' }
$dexFile = Join-Path $dex 'classes.dex'
if (-not (Test-Path -LiteralPath $dexFile -PathType Leaf)) { throw 'No classes.dex.' }
$baseApk = Join-Path $generation 'base.apk'
& $aapt package -f -M (Join-Path $root 'AndroidManifest.xml') -I $androidJar -F $baseApk
if ($LASTEXITCODE -ne 0) { throw 'Tile manifest packaging failed.' }
Push-Location -LiteralPath $dex
try {
    & $aapt add $baseApk 'classes.dex'
    if ($LASTEXITCODE -ne 0) { throw 'Tile Dex packaging failed.' }
} finally { Pop-Location }
$apk = Join-Path $generation 'disposable-lease-tile-trial-unsigned.apk'
& $zipalign -f -p 4 $baseApk $apk
if ($LASTEXITCODE -ne 0) { throw 'Tile APK alignment failed.' }
& $zipalign -c 4 $apk
if ($LASTEXITCODE -ne 0) { throw 'Tile APK alignment verification failed.' }
$badging = @(& $aapt dump badging $apk)
if ($LASTEXITCODE -ne 0 -or
        -not ($badging -match "package: name='com.techrebbe.supernote.leasetiletrial'")) {
    throw 'Unexpected tile APK package identity.'
}
$digest = (Get-FileHash -LiteralPath $apk -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Output "APK=$apk"
Write-Output "APK_SHA256=$digest"
Write-Output 'APK_IS_UNSIGNED=true'
