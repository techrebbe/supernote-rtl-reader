param(
    [Parameter(Mandatory=$true)][string]$Jdk,
    [Parameter(Mandatory=$true)][string]$AndroidJar,
    [Parameter(Mandatory=$true)][string]$Python,
    [string]$Node='node'
)
$ErrorActionPreference='Stop'
$probeRoot=$PSScriptRoot
$repoRoot=Split-Path $probeRoot -Parent
$buildPath=Join-Path $probeRoot 'build/classes'
New-Item -ItemType Directory -Force -Path $buildPath | Out-Null
$javac=Join-Path $Jdk 'bin/javac.exe'
$java=Join-Path $Jdk 'bin/java.exe'
$sourceRoot=Join-Path $repoRoot 'native-spread-module/src/com/techrebbe/supernote/spreadprobe/v2'
$sources=@('Affine2D.java','PointD.java','RectD.java') | ForEach-Object { Join-Path $sourceRoot $_ }
$sources+=Join-Path $probeRoot 'java/com/techrebbe/supernote/viewportprobe/ViewportFrame.java'
$sources+=Join-Path $probeRoot 'test/ViewportFrameTest.java'
$sources+=Join-Path $probeRoot 'java/com/techrebbe/supernote/viewportprobe/DisplayProbeLayout.java'
$sources+=Join-Path $probeRoot 'java/com/techrebbe/supernote/viewportprobe/DisplayProbeLifecycle.java'
$sources+=Join-Path $probeRoot 'test/DisplayProbeLayoutTest.java'
& $javac -encoding UTF-8 --release 8 -d $buildPath @sources
if ($LASTEXITCODE -ne 0) {throw 'Viewport contract compilation failed'}
& $java -cp $buildPath ViewportFrameTest
if ($LASTEXITCODE -ne 0) {throw 'Viewport contract tests failed'}
& $java -cp $buildPath DisplayProbeLayoutTest
if ($LASTEXITCODE -ne 0) {throw 'Display surface layout tests failed'}
& $javac -encoding UTF-8 --release 8 -classpath $AndroidJar -d $buildPath (Join-Path $probeRoot 'java/com/techrebbe/supernote/viewportprobe/SavedInkReader.java')
if ($LASTEXITCODE -ne 0) {throw 'Saved-ink diagnostic compilation failed'}
$hostSources=@(Get-ChildItem -LiteralPath (Join-Path $probeRoot 'display-host/src') -Recurse -Filter '*.java' | ForEach-Object FullName)
& $javac -encoding UTF-8 --release 8 -classpath "$AndroidJar;$buildPath" -d $buildPath @hostSources
if ($LASTEXITCODE -ne 0) {throw 'Display-only Android host compilation failed'}
& $Python -m unittest discover -s $probeRoot -p 'test_*.py' -v
if ($LASTEXITCODE -ne 0) {throw 'Evidence validation tests failed'}
& $Node (Join-Path $probeRoot 'test_pen_boundary_snapshot.js')
if ($LASTEXITCODE -ne 0) {throw 'Pen-boundary observation tests failed'}
Write-Output 'HOST CHECKS PASS. Not a hardware/collector/viewport readiness claim.'
