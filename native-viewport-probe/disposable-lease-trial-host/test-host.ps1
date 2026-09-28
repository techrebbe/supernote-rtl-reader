[CmdletBinding()]
param([string]$Jdk = $env:JAVA_HOME)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Jdk)) { throw 'Pass -Jdk or set JAVA_HOME.' }
$javac = Join-Path $Jdk 'bin\javac.exe'
$java = Join-Path $Jdk 'bin\java.exe'
foreach ($path in @($javac, $java)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing JDK tool: $path" }
}
$root = $PSScriptRoot
. (Join-Path $root 'path-guard.ps1')
$source = Join-Path $root 'src\com\techrebbe\supernote\leasetrial'
$generation = New-IgnoredBuildGeneration $root 'host-test-'
$classes = Join-Path $generation 'classes'
New-Item -ItemType Directory -Path $classes -ErrorAction Stop | Out-Null
$null = Assert-IgnoredBuildPath $classes $root
$sources = @(
    (Join-Path $source 'LeaseTrialContract.java'),
    (Join-Path $source 'TrialEvidence.java'),
    (Join-Path $source 'TrialSessionGuard.java'),
    (Join-Path $root 'tests\TrialEvidenceTest.java'),
    (Join-Path $root 'tests\TrialSessionGuardTest.java')
)
& $javac -encoding UTF-8 --release 8 -d $classes @sources
if ($LASTEXITCODE -ne 0) { throw 'Pure-Java trial proof compilation failed.' }
$null = Assert-IgnoredBuildPath $classes $root
& $java -cp $classes com.techrebbe.supernote.leasetrial.TrialEvidenceTest
if ($LASTEXITCODE -ne 0) { throw 'No-child trial proof tests failed.' }
& $java -cp $classes com.techrebbe.supernote.leasetrial.TrialSessionGuardTest
if ($LASTEXITCODE -ne 0) { throw 'Session-taint tests failed.' }
& (Join-Path $root 'test-path-guard.ps1')
if ($LASTEXITCODE -ne 0) { throw 'Ignored build path tests failed.' }
$manifest = Get-Content -LiteralPath (Join-Path $root 'AndroidManifest.xml') -Raw
if ($manifest -notmatch 'package="com\.techrebbe\.supernote\.leasetrial"' -or
        $manifest -notmatch 'android:authorities="com\.techrebbe\.supernote\.leasetrial\.probe"' -or
        $manifest -match '<uses-permission\b' -or
        $manifest -match 'com\.techrebbe\.supernote\.disposableleasehost') {
    throw 'Trial manifest isolation/permission guard failed.'
}
Write-Output 'PASS isolated manifest guard'
$activity = Get-Content -LiteralPath (Join-Path $source 'LeaseTrialActivity.java') -Raw
if ($activity -notmatch 'onNewIntent\(Intent intent\)[\s\S]*?taint\("ACTIVITY_REUSED"\)' -or
        $activity -notmatch 'onPause\(\)[\s\S]*?taint\("ACTIVITY_PAUSED"\)' -or
        $activity -notmatch 'onWindowFocusChanged\(boolean hasFocus\)[\s\S]*?taint\("WINDOW_FOCUS_LOST"\)' -or
        $activity -notmatch 'claimInitialFocusPaint\(admitted, hasFocus, trial == null\)\)[\s\S]*?firstFocusPaintFloorRevision = root\.startedPaintRevision;[\s\S]*?root\.invalidate\(\);' -or
        $activity -notmatch 'state\.put\("firstFocusPaintFloorRevision", firstFocusPaintFloorRevision\);' -or
        $activity -notmatch 'baseline\.startedPaintRevision <= firstFocusPaintFloorRevision' -or
        $activity -notmatch 'return JSONObject\.NULL;' -or
        $activity -notmatch 'sessionGuard\.currentlyValid\(') {
    throw 'Lifecycle/null-cut Activity contract guard failed.'
}
Write-Output 'PASS lifecycle and null-cut source contract guard'
& (Join-Path $root 'emulator-gate.ps1') -ParserSelfTest
if ($LASTEXITCODE -ne 0) { throw 'No-child runner parser tests failed.' }
