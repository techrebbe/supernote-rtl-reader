param(
    [Parameter(Mandatory=$true)][string]$Jdk,
    [Parameter(Mandatory=$true)][string]$AndroidSdk,
    [Parameter(Mandatory=$true)][string]$JsonJar,
    [Parameter(Mandatory=$true)][string]$Python,
    [Parameter(Mandatory=$true)][string]$PythonPath
)
$ErrorActionPreference='Stop'
$probeRoot=$PSScriptRoot
$androidJar=Join-Path $AndroidSdk 'platforms/android-35/android.jar'
$buildTools=Join-Path $AndroidSdk 'build-tools/35.0.0'
& (Join-Path $probeRoot 'check.ps1') -Jdk $Jdk -AndroidJar $androidJar -JsonJar $JsonJar `
    -Python $Python -PythonPath $PythonPath
if ($LASTEXITCODE -ne 0) {throw 'Probe checks failed'}
# A fresh generation for every build; never delete previous results/evidence.
$out=Join-Path $probeRoot ('build/d-' + [guid]::NewGuid().ToString('N'))
$classes=Join-Path $out 'classes'
$dex=Join-Path $out 'dex'
New-Item -ItemType Directory -Path $classes,$dex | Out-Null
$hostSourceRoot=Join-Path $probeRoot 'display-host/src'
$sources=@(
    (Join-Path $hostSourceRoot 'com/techrebbe/supernote/viewportdisplayprobe/CalibrationActivity.java'),
    (Join-Path $hostSourceRoot 'com/techrebbe/supernote/viewportdisplayprobe/DisplayProbeActivity.java')
)
$discoveredSources=@(Get-ChildItem -LiteralPath $hostSourceRoot -Recurse -File -Filter '*.java' |
    ForEach-Object FullName)
$sourceDifference=@(Compare-Object ($sources | Sort-Object) ($discoveredSources | Sort-Object))
if ($sourceDifference.Count -ne 0) {
    throw 'Display-host Java source inventory differs from the exact two-file allowlist'
}
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
$permissionPath=Join-Path $out 'permissions.txt'
$xmltreePath=Join-Path $out 'manifest-xmltree.txt'
$authorityPath=Join-Path $out 'packaged-scope-authority.json'
$authenticatedLauncher=Join-Path $probeRoot 'invoke-authenticated-production.ps1'
$inspectArguments=@(
    '--aapt', (Join-Path $buildTools 'aapt.exe'),
    '--apk', $aligned,
    '--permissions-out', $permissionPath,
    '--xmltree-out', $xmltreePath,
    '--authority-out', $authorityPath
)
& $authenticatedLauncher -Python $Python `
    -Mode display-inspect -CommandArguments $inspectArguments
$inspectExit=$LASTEXITCODE
if ($inspectExit -eq 2) {exit 2}
if ($inspectExit -eq 126) {exit $inspectExit}
if ($inspectExit -ne 0) {exit 126}
$verifyArguments=@(
    '--apk', $aligned,
    '--permissions-out', $permissionPath,
    '--xmltree-out', $xmltreePath,
    '--authority-out', $authorityPath
)
& $authenticatedLauncher -Python $Python `
    -Mode display-verify -CommandArguments $verifyArguments
$verifyExit=$LASTEXITCODE
if ($verifyExit -eq 2) {exit 2}
if ($verifyExit -eq 126) {exit $verifyExit}
if ($verifyExit -ne 0) {exit 126}
Write-Output 'UNSIGNED DISPLAY-ONLY APK. Not installable, not a reader/pen gate. Independent review required.'
Write-Output $aligned
