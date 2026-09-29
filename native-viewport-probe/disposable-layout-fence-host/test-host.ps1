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
$hostRoot = $PSScriptRoot
. (Join-Path $hostRoot 'path-guard.ps1')
$source = Join-Path $hostRoot 'src\com\techrebbe\supernote\layoutfencetrial'
$generation = New-IgnoredBuildGeneration $hostRoot 'host-test-'
$classes = Join-Path $generation 'classes'
New-Item -ItemType Directory -Path $classes -ErrorAction Stop | Out-Null
$null = Assert-IgnoredBuildPath $classes $hostRoot
$sources = @(
    (Join-Path $source 'TrialContract.java'),
    (Join-Path $source 'TrialSessionGuard.java'),
    (Join-Path $source 'TrialEvidence.java'),
    (Join-Path $source 'ArmProtocol.java'),
    (Join-Path $hostRoot 'tests\TrialEvidenceTest.java'),
    (Join-Path $hostRoot 'tests\TrialSessionGuardTest.java'),
    (Join-Path $hostRoot 'tests\ArmProtocolTest.java')
)
& $javac -encoding UTF-8 --release 8 -d $classes @sources
if ($LASTEXITCODE -ne 0) { throw 'Pure-Java trial compilation failed.' }
& $java -cp $classes com.techrebbe.supernote.layoutfencetrial.TrialEvidenceTest
if ($LASTEXITCODE -ne 0) { throw 'Layout-fence evidence tests failed.' }
& $java -cp $classes com.techrebbe.supernote.layoutfencetrial.TrialSessionGuardTest
if ($LASTEXITCODE -ne 0) { throw 'One-shot session tests failed.' }
& $java -cp $classes com.techrebbe.supernote.layoutfencetrial.ArmProtocolTest
if ($LASTEXITCODE -ne 0) { throw 'Process prearm/sentinel tests failed.' }

$manifest = Get-Content -LiteralPath (Join-Path $hostRoot 'AndroidManifest.xml') -Raw
if ($manifest -notmatch 'package="com\.techrebbe\.supernote\.layoutfencetrial"' -or
        $manifest -notmatch 'android:authorities="com\.techrebbe\.supernote\.layoutfencetrial\.probe"' -or
        $manifest -notmatch 'android:minSdkVersion="30"' -or
        $manifest -match '<uses-permission\b' -or
        $manifest -match 'com\.techrebbe\.supernote\.disposableleasehost') {
    throw 'Synthetic manifest isolation guard failed.'
}
$activity = Get-Content -LiteralPath (Join-Path $source 'TrialActivity.java') -Raw
$root = Get-Content -LiteralPath (Join-Path $source 'TrialRoot.java') -Raw
$parent = Get-Content -LiteralPath (Join-Path $source 'TrialParent.java') -Raw
$process = Get-Content -LiteralPath (Join-Path $source 'TrialProcess.java') -Raw
if ($activity -notmatch 'if \(before == TrialEvidence\.State\.WAIT_FIRST_PAINT\s*&& trial\.state\(\) == TrialEvidence\.State\.WAIT_RESTORE_CALL\) \{\s*(?://[^\r\n]*\r?\n\s*)*requestRestore\(\);\s*\} else if' -or
        $activity -notmatch 'else if \(cleanupPending && before == TrialEvidence\.State\.WAIT_RESTORE_CALL\) \{\s*unknownAndRestore\("EXTRA_PAINT_BEFORE_RESTORE"\);') {
    throw 'Changed-frame restore must be requested synchronously and extra paints fail closed.'
}
$restoreMethod = [regex]::Match($activity,
    '(?s)private void requestRestore\(\) \{(.*?)\r?\n    \}\s*private void unknownAndRestore')
if (-not $restoreMethod.Success -or
        $restoreMethod.Groups[1].Value -notmatch 'parent\.requestLayout\(\);\s*if \(trial\.state\(\) == TrialEvidence\.State\.UNKNOWN\) \{\s*(?://[^\r\n]*\r?\n\s*)*root\.invalidate\(\);\s*\}' -or
        [regex]::Matches($restoreMethod.Groups[1].Value, 'root\.invalidate\(\);').Count -ne 1 -or
        $activity -notmatch 'if \(!cleanupVerified\.get\(\) && !cleanupPending\) requestRestore\(\);') {
    throw 'Normal restore must use parent layout only; UNKNOWN cleanup keeps explicit redraw.'
}
$afterParentMethod = [regex]::Match($activity,
    '(?s)@Override public void afterParentRootLayout\(\) \{(.*?)\r?\n    \}\s*@Override public void onParentAnomaly')
if (-not $afterParentMethod.Success -or
        $afterParentMethod.Groups[1].Value -notmatch '(?s)TrialEvidence\.Cut after = root\.captureLive\(\);\s*trial\.onParentLayoutAfter\(after, SystemClock\.elapsedRealtime\(\)\);\s*if \(trial\.state\(\) == TrialEvidence\.State\.UNKNOWN\) unknownAndRestore\(trial\.reason\(\)\);\s*else \{.*?if \(trial\.shouldRequestRestorePaint\(after\)\) root\.invalidate\(\);.*?if \(trial\.claimUnchangedFirstPaintRequest\(after\)\) root\.invalidate\(\);' -or
        [regex]::Matches($afterParentMethod.Groups[1].Value, 'root\.invalidate\(\);').Count -ne 2) {
    throw 'Only verified direct-offset restore and unchanged first-return cuts may request their missing paints.'
}
if ($activity -notmatch 'final TrialEvidence\.Cut scheduledAnchor = trial\.secondPaintAnchor\(\);' -or
        $activity -notmatch 'if \(trial\.secondPaintAnchor\(\) != scheduledAnchor\) return;' -or
        $activity -notmatch 'proof\.put\("paintOrderProofVersion", 2\);' -or
        $activity -notmatch 'proof\.put\("interveningRestoredFrame", cutJson\(' -or
        $activity -notmatch 'proof\.put\("secondPaintRequestElapsedMs", trial == null \? 0' -or
        $activity -notmatch 'proof\.put\("secondPaintStartRevisionFloor", trial == null \? 0') {
    throw 'Intervening paint must rebase only the pending timer and expose bounded proof.'
}
if ($activity -notmatch 'proof\.put\("abaAway", cutJson\(trial == null \? null : trial\.abaAway\(\)\)\);' -or
        $activity -notmatch 'if \(cut == null\) return JSONObject\.NULL;') {
    throw 'ABA proof JSON key and null serialization contract failed.'
}
if ($activity -notmatch 'new TrialRoot\(this, TrialContract\.rootToken\(' -or
        $activity -notmatch 'public TrialRoot getTrialRoot\(' -or
        $activity -notmatch 'Process\.killProcess\(Process\.myPid\(\)\)' -or
        $activity -notmatch 'watchdog\.start\(\)' -or
        $activity -notmatch 'cleanupVerified\.set\(true\)' -or
        $activity -notmatch 'trialWatchdogStarted\(' -or
        $process -notmatch 'activity != null \|\| everRegistered' -or
        $process -notmatch 'layout-fence-prearm-watchdog' -or
        $process -notmatch 'if \(!armFinished\.get\(\)\) Process\.killProcess\(exactPid\)' -or
        $root -notmatch 'public long getParentPreCallRevision\(' -or
        $root -notmatch 'drawChild\(Canvas canvas, View child' -or
        $root -notmatch 'onDetachedFromWindow\(' -or
        $parent -notmatch 'onDetachedFromWindow\(' -or
        $parent -notmatch 'root\.layout\(target\.left, target\.top') {
    throw 'Pre-call/paint/watchdog source contract guard failed.'
}
$allJava = @(Get-ChildItem -LiteralPath $source -Filter '*.java' -File |
    ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
if ($allJava -match 'android\.permission\.' -or
        $allJava -match 'https?://' -or
        $allJava -match 'Java\.use\(|supernote\.app|\.pdf\b|pen input') {
    throw 'Synthetic no-reader/no-network source guard failed.'
}
Write-Output 'PASS synthetic manifest/source isolation guard'
