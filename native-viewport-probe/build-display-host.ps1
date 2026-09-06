param(
    [Parameter(Mandatory=$true)][string]$Jdk,
    [Parameter(Mandatory=$true)][string]$AndroidSdk,
    [Parameter(Mandatory=$true)][string]$Python
)
$ErrorActionPreference='Stop'
$probeRoot=$PSScriptRoot
$androidJar=Join-Path $AndroidSdk 'platforms/android-35/android.jar'
$buildTools=Join-Path $AndroidSdk 'build-tools/35.0.0'
& (Join-Path $probeRoot 'check.ps1') -Jdk $Jdk -AndroidJar $androidJar -Python $Python
if ($LASTEXITCODE -ne 0) {throw 'Probe checks failed'}
# A fresh generation for every build; never delete previous results/evidence.
$out=Join-Path $probeRoot ('build/d-' + [guid]::NewGuid().ToString('N'))
$classes=Join-Path $out 'classes'
$dex=Join-Path $out 'dex'
New-Item -ItemType Directory -Path $classes,$dex | Out-Null
$sources=@(Get-ChildItem -LiteralPath (Join-Path $probeRoot 'display-host/src') -Recurse -Filter '*.java' | ForEach-Object FullName)
$sources+=Join-Path $probeRoot 'java/com/techrebbe/supernote/viewportprobe/DisplayProbeLayout.java'
$sources+=Join-Path $probeRoot 'java/com/techrebbe/supernote/viewportprobe/DisplayProbeLifecycle.java'
& (Join-Path $Jdk 'bin/javac.exe') -encoding UTF-8 --release 8 -classpath $androidJar -d $classes @sources
if ($LASTEXITCODE -ne 0) {throw 'Display host compilation failed'}
$classJar=Join-Path $out 'host-classes.jar'
& (Join-Path $Jdk 'bin/jar.exe') --create --file $classJar -C $classes .
if ($LASTEXITCODE -ne 0) {throw 'Display host class packaging failed'}
# d8 uses JAVA_HOME; retain the caller's environment and restore in all cases.
$priorJavaHome=$env:JAVA_HOME
try {
    $env:JAVA_HOME=$Jdk
    & (Join-Path $buildTools 'd8.bat') --min-api 30 --lib $androidJar --output $dex $classJar
    if ($LASTEXITCODE -ne 0) {throw 'Display host DEX compilation failed'}
} finally { $env:JAVA_HOME=$priorJavaHome }
$raw=Join-Path $out 'viewport-raw.apk'
& (Join-Path $buildTools 'aapt.exe') package -f -M (Join-Path $probeRoot 'display-host/AndroidManifest.xml') -I $androidJar -F $raw
if ($LASTEXITCODE -ne 0) {throw 'Display host manifest packaging failed'}
& (Join-Path $Jdk 'bin/jar.exe') --update --file $raw -C $dex classes.dex
if ($LASTEXITCODE -ne 0) {throw 'Display host DEX packaging failed'}
$aligned=Join-Path $out 'viewport-unsigned.apk'
& (Join-Path $buildTools 'zipalign.exe') -p 4 $raw $aligned
if ($LASTEXITCODE -ne 0) {throw 'Display host alignment failed'}
& (Join-Path $buildTools 'zipalign.exe') -c 4 $aligned
if ($LASTEXITCODE -ne 0) {throw 'Display host alignment verification failed'}
& (Join-Path $buildTools 'aapt.exe') dump badging $aligned
if ($LASTEXITCODE -ne 0) {throw 'Display host package inspection failed'}
Get-FileHash -LiteralPath $aligned -Algorithm SHA256
Write-Output 'UNSIGNED DISPLAY-ONLY APK. Not installable, not a reader/pen gate. Independent review required.'
Write-Output $aligned
