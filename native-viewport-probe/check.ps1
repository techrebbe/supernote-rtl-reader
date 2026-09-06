param(
    [Parameter(Mandatory=$true)][string]$Jdk,
    [Parameter(Mandatory=$true)][string]$AndroidJar,
    [Parameter(Mandatory=$true)][string]$Python
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
& $javac --release 8 -d $buildPath @sources
if ($LASTEXITCODE -ne 0) {throw 'Viewport contract compilation failed'}
& $java -cp $buildPath ViewportFrameTest
if ($LASTEXITCODE -ne 0) {throw 'Viewport contract tests failed'}
& $javac --release 8 -classpath $AndroidJar -d $buildPath (Join-Path $probeRoot 'java/com/techrebbe/supernote/viewportprobe/SavedInkReader.java')
if ($LASTEXITCODE -ne 0) {throw 'Saved-ink diagnostic compilation failed'}
& $Python -m unittest discover -s $probeRoot -p 'test_*.py' -v
if ($LASTEXITCODE -ne 0) {throw 'Evidence validation tests failed'}
Write-Output 'HOST CHECKS PASS. Not a hardware/collector/viewport readiness claim.'
