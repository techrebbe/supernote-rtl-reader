# NO-CHILD gate only. This script never installs, writes a document, or targets Nomad.
[CmdletBinding()]
param(
    [string]$Serial = 'emulator-5554',
    [string]$SignedApk,
    [string]$ExpectedApkSha256,
    [string]$ExpectedCertSha256,
    [string]$Jdk = $env:JAVA_HOME,
    [string]$AndroidSdk = $(if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT }
        else { $env:ANDROID_HOME }),
    [switch]$ParserSelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'path-guard.ps1')
$script:Package = 'com.techrebbe.supernote.leasetrial'
$script:Authority = 'content://com.techrebbe.supernote.leasetrial.probe'
$script:Component = 'com.techrebbe.supernote.leasetrial/.LeaseTrialActivity'
$script:RunDir = $null
$script:EvidenceNumber = 0
$script:Summary = [ordered]@{
    schema = 'disposable-no-child-emulator-gate-v1'
    serial = $Serial
    startedUtc = [DateTime]::UtcNow.ToString('o')
    outcome = 'UNKNOWN'
    package = $script:Package
}

function Fail([string]$Message) { throw "FAIL: $Message" }
function Unknown([string]$Message) { throw "UNKNOWN: $Message" }
function Lines([string]$Value) {
    return @($Value -split '(?:\r+\n|\n|\r+)' | Where-Object { $_.Length -gt 0 })
}

function Parse-State([string]$Text, [string]$Label) {
    $rows = @(Lines $Text)
    if ($rows.Count -ne 1 -or $rows[0] -cnotmatch '^Row: 0 json=(\{.*\})$') {
        Unknown "$Label is not exactly one JSON state row"
    }
    try { $state = ConvertFrom-Json -InputObject $Matches[1] -ErrorAction Stop }
    catch { Unknown "$Label contains invalid JSON" }
    if ($state.schema -cne 'lease-trial-no-child-state-v1') {
        Unknown "$Label has an unexpected schema"
    }
    return $state
}

function Assert-Cut($Cut, [string]$Label) {
    if ($null -eq $Cut -or $Cut.exactNinePainted -cne $true -or
            $Cut.startedPaintRevision -ne $Cut.completedPaintRevision -or
            $Cut.startedPaintRevision -lt 1 -or
            @($Cut.children).Count -ne 9 -or
            @($Cut.effectivePaintOrder).Count -ne 9) {
        Unknown "$Label lacks a completed actual nine-child paint"
    }
    for ($i = 0; $i -lt 9; $i++) {
        $child = $Cut.children[$i]
        if ($child.index -ne $i -or $child.identityHash -eq 0 -or
                $child.matchesOriginal -cne $true -or
                $child.parentIsRoot -cne $true -or
                [string]::IsNullOrEmpty($child.evidence) -or
                $Cut.effectivePaintOrder[$i] -ne $child.identityHash) {
            Unknown "$Label child/paint position $i is not the original"
        }
    }
}

function Assert-SameNine($Before, $After, [string]$Label) {
    if ($Before.rootIdentityHash -ne $After.rootIdentityHash -or
            $Before.scene -cne $After.scene -or
            $Before.mutationRevision -ne $After.mutationRevision) {
        Unknown "$Label changed root, scene, or evidence revision"
    }
    for ($i = 0; $i -lt 9; $i++) {
        if ($Before.children[$i].identityHash -ne $After.children[$i].identityHash -or
                $Before.children[$i].evidence -cne $After.children[$i].evidence -or
                $Before.effectivePaintOrder[$i] -ne $After.effectivePaintOrder[$i]) {
            Unknown "$Label changed original $i or its actual paint order"
        }
    }
}

function Assert-SameCut($Before, $After, [string]$Label) {
    Assert-Cut $Before "$Label.before"
    Assert-Cut $After "$Label.after"
    Assert-SameNine $Before $After $Label
    if ($Before.startedPaintRevision -ne $After.startedPaintRevision -or
            $Before.completedPaintRevision -ne $After.completedPaintRevision -or
            $Before.completedPaintElapsedMs -ne $After.completedPaintElapsedMs) {
        Unknown "$Label changed its completed paint witness"
    }
}

function Assert-SameSession($State, $Anchor, [string]$Label) {
    if ($State.process.pid -ne $Anchor.process.pid -or
            $State.process.incarnation -cne $Anchor.process.incarnation -or
            $State.activitySerial -ne $Anchor.activitySerial -or
            $State.firstFocusPaintFloorRevision -ne
                $Anchor.firstFocusPaintFloorRevision -or
            $State.current.rootIdentityHash -ne $Anchor.current.rootIdentityHash) {
        Unknown "$Label changed process, Activity, or root incarnation"
    }
}

function Has-PostFocusCompletedPaint($State) {
    if (-not ($State.PSObject.Properties.Name -ccontains
            'firstFocusPaintFloorRevision')) {
        Unknown 'state lacks first-focus paint revision'
    }
    $floor = $State.firstFocusPaintFloorRevision
    if (($floor -isnot [int] -and $floor -isnot [long]) -or $floor -lt -1) {
        Unknown 'state has invalid first-focus paint revision'
    }
    if ($floor -lt 0 -or $null -eq $State.lastCompletedPaint) { return $false }
    $paint = $State.lastCompletedPaint
    return ($paint.exactNinePainted -ceq $true -and
        $paint.startedPaintRevision -eq $paint.completedPaintRevision -and
        $paint.completedPaintRevision -gt $floor)
}

function Parse-Command([string]$Text) {
    $rows = @(Lines $Text)
    if ($rows.Count -ne 1 -or
            $rows[0] -cnotmatch '^Result: Bundle\[\{(.*)\}\]$') {
        Unknown 'command response is not one Bundle'
    }
    $body = $Matches[1]
    $fields = New-Object System.Collections.ArrayList
    $depth = 0
    $quoted = $false
    $escaped = $false
    $start = 0
    for ($i = 0; $i -lt $body.Length; $i++) {
        $character = $body[$i]
        if ($quoted) {
            if ($escaped) { $escaped = $false }
            elseif ($character -eq '\') { $escaped = $true }
            elseif ($character -eq '"') { $quoted = $false }
        } elseif ($character -eq '"') { $quoted = $true }
        elseif ($character -eq '{' -or $character -eq '[') { $depth++ }
        elseif ($character -eq '}' -or $character -eq ']') {
            $depth--
            if ($depth -lt 0) { Unknown 'malformed command Bundle nesting' }
        } elseif ($character -eq ',' -and $depth -eq 0) {
            $null = $fields.Add($body.Substring($start, $i - $start).Trim())
            $start = $i + 1
        }
    }
    if ($quoted -or $depth -ne 0) { Unknown 'malformed command Bundle' }
    $null = $fields.Add($body.Substring($start).Trim())
    $parsed = @{}
    foreach ($field in $fields) {
        if ($field -cnotmatch '^([a-z]+)=(.*)$' -or
                $parsed.ContainsKey($Matches[1])) {
            Unknown 'duplicate or malformed command Bundle field'
        }
        $parsed.Add($Matches[1], $Matches[2])
    }
    if ($parsed.Count -ne 3 -or $parsed.ok -cne 'true' -or
            $parsed.command -cne 'preflight-noop-layout' -or
            $parsed.json -cnotmatch '^\{.*\}$') {
        Unknown 'no-child command was not explicitly accepted'
    }
    $embedded = ConvertFrom-Json -InputObject $parsed.json -ErrorAction Stop
    if ($embedded.schema -cne 'lease-trial-no-child-state-v1' -or
            $embedded.trial.token -ne 1) {
        Unknown 'accepted command returned an unexpected state'
    }
}

function Invoke-Adb([string[]]$Arguments, [string]$Label, [int]$TimeoutMs = 10000) {
    $all = @('-s', $Serial) + $Arguments
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $script:Adb
    $start.Arguments = ($all -join ' ')
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    if (-not $process.Start()) { Unknown "$Label ADB did not start" }
    $outTask = $process.StandardOutput.ReadToEndAsync()
    $errTask = $process.StandardError.ReadToEndAsync()
    $timedOut = -not $process.WaitForExit($TimeoutMs)
    if ($timedOut) {
        try { $process.Kill() } catch { }
        $null = $process.WaitForExit(2000)
    }
    $outDone = $outTask.Wait(2000)
    $errDone = $errTask.Wait(2000)
    $stdout = if ($outDone) { $outTask.GetAwaiter().GetResult() } else { '<incomplete>' }
    $stderr = if ($errDone) { $errTask.GetAwaiter().GetResult() } else { '<incomplete>' }
    $code = if ($timedOut) { -1 } else { $process.ExitCode }
    $script:EvidenceNumber++
    $record = [ordered]@{
        utc = [DateTime]::UtcNow.ToString('o')
        label = $Label
        argv = $all
        exitCode = $code
        timedOut = $timedOut
        stdout = $stdout
        stderr = $stderr
    }
    $file = Join-Path $script:RunDir ('{0:d3}-{1}.json' -f
        $script:EvidenceNumber, ($Label -replace '[^A-Za-z0-9_-]', '_'))
    $null = Assert-IgnoredBuildPath $file $PSScriptRoot
    [IO.File]::WriteAllText($file, ($record | ConvertTo-Json -Depth 8),
        [Text.UTF8Encoding]::new($false))
    $null = Assert-IgnoredBuildPath $file $PSScriptRoot
    $process.Dispose()
    if ($timedOut -or -not $outDone -or -not $errDone -or $code -ne 0 -or
            $stderr.Trim().Length -gt 0) {
        Unknown "$Label ADB failed or timed out; inspect evidence, do not retry blindly"
    }
    return $stdout
}

function Read-State([string]$Label) {
    $raw = Invoke-Adb @('shell', 'content', 'query', '--uri',
        "$script:Authority/state") $Label
    return Parse-State $raw $Label
}

function Check-Events([long]$After, $Anchor) {
    $raw = Invoke-Adb @('shell', 'content', 'query', '--uri',
        "$script:Authority/events?after=$After") 'events'
    $rows = @(Lines $raw)
    if ($rows.Count -ne 5) { Unknown 'event witness has missing or extra rows' }
    $last = $After
    $names = @()
    foreach ($row in $rows) {
        if ($row -cnotmatch '^Row: \d+ pid=(\d+), incarnation=([^,]+), firstRetained=(\d+), lastSequence=(\d+), sequence=(\d+), elapsedMs=(\d+), name=([A-Z0-9_]+), detail=(.*)$') {
            Unknown 'malformed event row'
        }
        if ([int]$Matches[1] -ne $Anchor.process.pid -or
                $Matches[2] -cne $Anchor.process.incarnation -or
                [long]$Matches[3] -gt ($After + 1) -or
                [long]$Matches[5] -ne ($last + 1)) {
            Unknown 'event gap or process identity mismatch'
        }
        $last = [long]$Matches[5]
        $names += $Matches[7]
    }
    $required = @('TRIAL_BEGIN', 'NOOP_LAYOUT_ENTERED', 'PAINT_COMPLETE',
        'POST_LAYOUT_PAINT', 'NO_CHILD_PREFLIGHT_PASS')
    for ($i = 0; $i -lt $required.Count; $i++) {
        if ($names[$i] -cne $required[$i]) {
            Unknown "unexpected event at trial position $i"
        }
    }
    return $last
}

if ($ParserSelfTest) {
    $root = New-Object Object
    $children = @(1..9 | ForEach-Object { [pscustomobject]@{
        index = $_ - 1; identityHash = $_; matchesOriginal = $true;
        parentIsRoot = $true; evidence = "child-$_"
    } })
    $cut = [pscustomobject]@{
        rootIdentityHash = 7; scene = 'fixed'; mutationRevision = 3;
        startedPaintRevision = 2; completedPaintRevision = 2;
        completedPaintElapsedMs = 42;
        exactNinePainted = $true; children = $children;
        effectivePaintOrder = @(1..9)
    }
    Assert-Cut $cut 'self-test'
    Assert-SameNine $cut $cut 'self-test'
    Assert-SameCut $cut $cut 'self-test'
    $focusState = [pscustomobject]@{
        firstFocusPaintFloorRevision = 2; lastCompletedPaint = $cut
    }
    if (Has-PostFocusCompletedPaint $focusState) {
        Fail 'pre-focus paint accepted as post-focus paint'
    }
    $cut.startedPaintRevision = 3
    $cut.completedPaintRevision = 3
    if (-not (Has-PostFocusCompletedPaint $focusState)) {
        Fail 'completed post-focus paint was rejected'
    }
    $focusState.firstFocusPaintFloorRevision = -1
    if (Has-PostFocusCompletedPaint $focusState) {
        Fail 'unfocused state accepted as post-focus paint'
    }
    $prepaint = Parse-State 'Row: 0 json={"schema":"lease-trial-no-child-state-v1","lastCompletedPaint":null,"trial":{"baseline":null,"layoutEntry":null,"postPaint":null,"secondSample":null}}' 'prepaint self-test'
    if (-not ($prepaint.PSObject.Properties.Name -ccontains 'lastCompletedPaint') -or
            $null -ne $prepaint.lastCompletedPaint) {
        Fail 'prepaint null-cut parser contract failed'
    }
    foreach ($cutName in @('baseline', 'layoutEntry', 'postPaint', 'secondSample')) {
        if (-not ($prepaint.trial.PSObject.Properties.Name -ccontains $cutName) -or
                $null -ne $prepaint.trial.$cutName) {
            Fail "prepaint $cutName null-cut parser contract failed"
        }
    }
    Parse-Command 'Result: Bundle[{ok=true, json={"schema":"lease-trial-no-child-state-v1","trial":{"token":1}}, command=preflight-noop-layout}]'
    Write-Output 'PASS no-child runner parser self-test (no ADB)'
    exit 0
}

if ($Serial -cne 'emulator-5554') { Fail 'this gate is pinned to emulator-5554' }
if ($ExpectedApkSha256 -cnotmatch '^[a-fA-F0-9]{64}$' -or
        $ExpectedCertSha256 -cnotmatch '^[a-fA-F0-9]{64}$' -or
        -not (Test-Path -LiteralPath $SignedApk -PathType Leaf)) {
    Fail 'signed emulator APK and exact package/certificate hashes are required'
}
if ([string]::IsNullOrWhiteSpace($AndroidSdk) -or
        [string]::IsNullOrWhiteSpace($Jdk)) { Fail 'Android SDK/JDK required' }
$script:Adb = Join-Path $AndroidSdk 'platform-tools\adb.exe'
$apksigner = Join-Path $AndroidSdk 'build-tools\35.0.0\lib\apksigner.jar'
$java = Join-Path $Jdk 'bin\java.exe'
foreach ($path in @($script:Adb, $apksigner, $java)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Fail "missing tool: $path" }
}
$hostHash = (Get-FileHash -LiteralPath $SignedApk -Algorithm SHA256).Hash.ToLowerInvariant()
if ($hostHash -cne $ExpectedApkSha256.ToLowerInvariant()) {
    Fail 'local signed APK hash differs from reviewed hash'
}
$certLines = @(& $java -jar $apksigner verify --print-certs $SignedApk 2>&1)
if ($LASTEXITCODE -ne 0) { Fail 'local APK signature verification failed' }
$cert = @($certLines | Where-Object {
    $_ -cmatch '^Signer #1 certificate SHA-256 digest: ([a-fA-F0-9]{64})$'
})
if ($cert.Count -ne 1 -or
        $cert[0] -cnotmatch '^Signer #1 certificate SHA-256 digest: ([a-fA-F0-9]{64})$' -or
        $Matches[1].ToLowerInvariant() -cne $ExpectedCertSha256.ToLowerInvariant()) {
    Fail 'local APK certificate differs from reviewed certificate'
}
$script:RunDir = New-IgnoredBuildGeneration $PSScriptRoot 'emulator-nochild-'

try {
    $avd = @(Lines (Invoke-Adb @('emu', 'avd', 'name') 'avd_name'))
    if ($avd.Count -ne 2 -or $avd[0].Trim() -cne 'RTL_Lease_API30' -or
            $avd[1].Trim() -cne 'OK') { Fail 'not the dedicated RTL_Lease_API30 AVD' }
    $sdk = (Invoke-Adb @('shell', 'getprop', 'ro.build.version.sdk') 'api_level').Trim()
    $qemu = (Invoke-Adb @('shell', 'getprop', 'ro.kernel.qemu') 'qemu').Trim()
    if ($sdk -cne '30' -or $qemu -cne '1') { Fail 'target is not API-30 emulator' }
    $pm = (Invoke-Adb @('shell', 'pm', 'path', $script:Package) 'package_path').Trim()
    if ($pm -cnotmatch '^package:(/data/app/[^\s]+/base\.apk)$') {
        Fail 'unique trial package is not installed as one base APK'
    }
    $installedPath = $Matches[1]
    $remoteHash = (Invoke-Adb @('shell', 'sha256sum', $installedPath) 'installed_hash').Trim()
    if ($remoteHash -cnotmatch '^([a-fA-F0-9]{64})\s+/data/app/[^\s]+/base\.apk$' -or
            $Matches[1].ToLowerInvariant() -cne $hostHash) {
        Fail 'installed APK bytes differ from the reviewed signed APK'
    }
    $null = Invoke-Adb @('shell', 'am', 'start', '-n', $script:Component) 'activity_launch'
    $until = [DateTime]::UtcNow.AddSeconds(8)
    $baseline = $null
    do {
        $candidate = Read-State 'baseline_state'
        if ($candidate.activityPresent -eq $true -and $candidate.lifecycle -ceq 'RESUMED' -and
                $candidate.tainted -eq $false -and
                $candidate.rootAttached -eq $true -and $candidate.rootHasFocus -eq $true -and
                $candidate.rootLayoutRequested -eq $false -and
                $candidate.originalsExact -eq $true -and
                $candidate.trial.state -ceq 'IDLE' -and
                (Has-PostFocusCompletedPaint $candidate) -and
                $candidate.current.startedPaintRevision -eq
                    $candidate.current.completedPaintRevision) {
            $baseline = $candidate
            break
        }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $until)
    if ($null -eq $baseline) { Unknown 'fresh initial nine-child scene did not appear' }
    Assert-Cut $baseline.lastCompletedPaint 'baseline paint'
    Assert-Cut $baseline.current 'baseline live'
    Assert-SameNine $baseline.lastCompletedPaint $baseline.current 'baseline'
    $afterEvent = [long]$baseline.process.eventLastSequence
    Parse-Command (Invoke-Adb @('shell', 'content', 'call', '--uri',
        $script:Authority, '--method', 'command', '--arg',
        'preflight-noop-layout') 'trial_command')
    $until = [DateTime]::UtcNow.AddSeconds(8)
    $final = $null
    do {
        $candidate = Read-State 'trial_state'
        Assert-SameSession $candidate $baseline 'trial'
        if ($candidate.trial.state -ceq 'UNKNOWN') {
            Unknown "trial failed closed: $($candidate.trial.reason)"
        }
        if ($candidate.trial.state -ceq 'PASS') { $final = $candidate; break }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $until)
    if ($null -eq $final) { Unknown 'bounded no-child trial did not finish' }
    if ($final.tainted -cne $false -or
            $final.trial.token -ne 1 -or $final.trial.layoutCalls -ne 1 -or
            $final.trial.rollbackVerified -cne $true -or
            $final.trial.currentlyValid -cne $true -or
            $final.rootLayoutCalls -ne ($baseline.rootLayoutCalls + 1) -or
            $final.rootControlledNoopCalls -ne ($baseline.rootControlledNoopCalls + 1) -or
            $final.originalsExact -cne $true -or
            $final.lifecycle -cne 'RESUMED' -or $final.rootAttached -cne $true -or
            $final.rootLayoutRequested -cne $false) {
        Unknown 'trial result or layout count is not exact'
    }
    foreach ($name in @('baseline', 'layoutEntry', 'postPaint', 'secondSample')) {
        Assert-Cut $final.trial.$name "trial.$name"
        Assert-SameNine $baseline.current $final.trial.$name "trial.$name"
    }
    Assert-Cut $final.current 'final live'
    Assert-SameNine $baseline.current $final.current 'final rollback'
    Assert-SameNine $final.trial.secondSample $final.current 'final post-PASS fence'
    if ($final.trial.postPaint.startedPaintRevision -le
            $final.trial.baseline.startedPaintRevision -or
            $final.current.startedPaintRevision -ne
                $final.trial.secondSample.startedPaintRevision -or
            $final.current.completedPaintRevision -ne
                $final.trial.secondSample.completedPaintRevision -or
            $final.current.completedPaintElapsedMs -ne
                $final.trial.secondSample.completedPaintElapsedMs) {
        Unknown 'no later completed paint or unstable final paint'
    }
    $lastEvent = Check-Events $afterEvent $baseline
    $sealed = Read-State 'final_after_events'
    Assert-SameSession $sealed $baseline 'final after events'
    if ($sealed.process.eventLastSequence -ne $lastEvent -or
            $sealed.tainted -cne $false -or
            $sealed.trial.state -cne 'PASS' -or
            $sealed.trial.currentlyValid -cne $true -or
            $sealed.trial.token -ne $final.trial.token -or
            $sealed.trial.rollbackVerified -cne $true -or
            $sealed.lifecycle -cne 'RESUMED' -or
            $sealed.rootAttached -cne $true -or
            $sealed.rootHasFocus -cne $true -or
            $sealed.rootLayoutRequested -cne $false -or
            $sealed.originalsExact -cne $true -or
            $sealed.rootLayoutCalls -ne $final.rootLayoutCalls -or
            $sealed.rootControlledNoopCalls -ne $final.rootControlledNoopCalls) {
        Unknown 'post-event live state or event tail changed'
    }
    Assert-SameCut $final.current $sealed.current 'sealed final live'
    Assert-SameCut $final.lastCompletedPaint $sealed.lastCompletedPaint 'sealed completed paint'
    Assert-SameCut $final.trial.secondSample $sealed.trial.secondSample 'sealed proof sample'
    Assert-SameCut $sealed.trial.secondSample $sealed.current 'sealed rollback'
    $script:Summary.outcome = 'PASS'
    $script:Summary.pid = $final.process.pid
    $script:Summary.incarnation = $final.process.incarnation
    $script:Summary.activitySerial = $final.activitySerial
    $script:Summary.rootIdentityHash = $final.current.rootIdentityHash
    $script:Summary.baselinePaintRevision =
        $final.trial.baseline.startedPaintRevision
    $script:Summary.postPaintRevision =
        $final.trial.postPaint.startedPaintRevision
    $script:Summary.mutationRevision = $final.current.mutationRevision
    Write-Output 'PASS real no-child layout, later nine-child paint, and two-sample rollback'
} catch {
    $script:Summary.outcome = if ($_.Exception.Message.StartsWith('FAIL:')) {
        'FAIL'
    } else { 'UNKNOWN' }
    $script:Summary.error = $_.Exception.Message
    throw
} finally {
    $script:Summary.finishedUtc = [DateTime]::UtcNow.ToString('o')
    if ($null -ne $script:RunDir) {
        $summaryPath = Join-Path $script:RunDir 'summary.json'
        $null = Assert-IgnoredBuildPath $summaryPath $PSScriptRoot
        [IO.File]::WriteAllText($summaryPath,
            ($script:Summary | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))
        $null = Assert-IgnoredBuildPath $summaryPath $PSScriptRoot
    }
}
