# Disposable API-30 host only. This script never installs an APK or addresses Nomad.
[CmdletBinding()]
param(
    [string]$Serial = 'emulator-5554',
    [switch]$ParserSelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Serial -cne 'emulator-5554') {
    throw 'FAIL: this disposable gate is pinned to emulator-5554'
}

$script:Authority = 'content://com.techrebbe.supernote.disposableleasehost.probe'
$script:Component = 'com.techrebbe.supernote.disposableleasehost/.ProbeActivity'
$script:Package = 'com.techrebbe.supernote.disposableleasehost'
$script:ExpectedApkSha256 = '728420a7db5018e18e83ea5d64f03282f00446604e19e9a14fc9bb2436877152'
$script:ExpectedCertSha256 = '94d4246035b9bed00164f7dc89aec8b9164d7fac769189729df74fb77b2446f3'
$script:SignedApk = Join-Path $PSScriptRoot 'build\apk-814cdcc59a944282a0a0e2fb77445cb9\disposable-lease-host-emulator-signed.apk'
$script:ApksignerJar = Join-Path $env:LOCALAPPDATA 'Android\Sdk\build-tools\35.0.0\lib\apksigner.jar'
$script:Java = 'C:\Program Files\Java\jdk-17\bin\java.exe'
$script:Adb = Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe'
$script:RunDir = $null
$script:EvidenceNumber = 0
$script:Summary = [ordered]@{
    schema = 'disposable-lease-emulator-gate-v1'
    serial = $Serial
    startedUtc = [DateTime]::UtcNow.ToString('o')
    outcome = 'UNKNOWN'
    trials = @()
}

function Fail([string]$Message) { throw "FAIL: $Message" }
function Unknown([string]$Message) { throw "UNKNOWN: $Message" }

function Assert-ExactKeys($Value, [string[]]$Expected, [string]$Label) {
    if ($null -eq $Value -or $Value -isnot [pscustomobject]) {
        Fail "$Label must be a JSON object"
    }
    $actual = @($Value.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object -CaseSensitive)
    $wanted = @($Expected | Sort-Object -CaseSensitive)
    if (($actual -join [char]0) -cne ($wanted -join [char]0)) {
        Fail "$Label keys differ from the pinned schema: $($actual -join ',')"
    }
}

function Assert-Integer($Value, [string]$Label, [long]$Minimum = 0) {
    if (($Value -isnot [int]) -and ($Value -isnot [long]) -and
            ($Value -isnot [uint32]) -and ($Value -isnot [uint64])) {
        Fail "$Label must be an integer"
    }
    if ($Value -lt $Minimum) { Fail "$Label is below $Minimum" }
}

function Assert-Boolean($Value, [string]$Label) {
    if ($Value -isnot [bool]) { Fail "$Label must be a Boolean" }
}

function Get-AdbLines([string]$Output) {
    # Windows PTYs can turn an Android CRLF into CRCRLF. Normalize only
    # line delimiters; preserve all non-delimiter bytes for strict parsers.
    return @($Output -split '(?:\r+\n|\n|\r+)' |
        Where-Object { $_.Length -gt 0 })
}

function Parse-OneJsonRow([string]$Output, [string]$Label) {
    $lines = @(Get-AdbLines $Output)
    if ($lines.Count -ne 1 -or $lines[0] -cnotmatch '^Row: 0 json=(\{.*\})$') {
        Fail "$Label must contain exactly one Row: 0 json={...} record"
    }
    Assert-NoDuplicateJsonKeys $Matches[1] $Label
    try { $value = ConvertFrom-Json -InputObject $Matches[1] -ErrorAction Stop }
    catch { Fail "$Label contains invalid JSON: $($_.Exception.Message)" }
    if ($value -isnot [pscustomobject]) { Fail "$Label JSON root must be an object" }
    return $value
}

function Assert-AvdName([string]$Output) {
    $lines = @(Get-AdbLines $Output | ForEach-Object { $_.Trim() })
    if ($lines.Count -ne 2 -or $lines[0] -cne 'RTL_Lease_API30' -or
            $lines[1] -cne 'OK') {
        Fail 'target is not the pinned RTL_Lease_API30 AVD'
    }
}

function Assert-NoDuplicateJsonKeys([string]$Json, [string]$Label) {
    # ConvertFrom-Json accepts duplicate keys. Tokenize structural punctuation
    # outside JSON strings, then reject repeated names in each object scope.
    $tokens = [regex]::Matches($Json, '"(?:\\.|[^"\\])*"|[{}\[\]:]')
    $stack = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $tokens.Count; $i++) {
        $token = $tokens[$i].Value
        if ($token -ceq '{') {
            $null = $stack.Add((New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)))
        } elseif ($token -ceq '[') {
            $null = $stack.Add($null)
        } elseif ($token -ceq '}' -or $token -ceq ']') {
            if ($stack.Count -eq 0) { Fail "$Label malformed JSON nesting" }
            $stack.RemoveAt($stack.Count - 1)
        } elseif ($token.StartsWith('"') -and $stack.Count -gt 0 -and
                $i + 1 -lt $tokens.Count -and $tokens[$i + 1].Value -ceq ':') {
            $scope = $stack[$stack.Count - 1]
            if ($null -eq $scope) { Fail "$Label has an object key in an array scope" }
            $key = ConvertFrom-Json -InputObject $token -ErrorAction Stop
            if (-not $scope.Add([string]$key)) {
                Fail "$Label contains duplicate JSON key $key"
            }
        }
    }
}

function Assert-Identity($Id, [string]$Label) {
    Assert-ExactKeys $Id @(
        'pid','incarnation','initializationElapsedRealtimeMs','initializationWallMs',
        'currentElapsedRealtimeMs','eventFirstRetainedSequence','eventLastSequence',
        'eventCapacity','leaseSlotOccupied','leaseSlotOwnerIdentityHash',
        'leaseSlotOwnerClass','leaseSlotClaimCount','activityLiveCount','activitySerial',
        'activityRootIdentityHash','activityAdmissionCollisions','coverState',
        'coverGeneration'
    ) $Label
    Assert-Integer $Id.pid "$Label.pid" 1
    $guid = [Guid]::Empty
    if ($Id.incarnation -isnot [string] -or
            -not [Guid]::TryParse($Id.incarnation, [ref]$guid)) {
        Fail "$Label.incarnation is not a UUID"
    }
    foreach ($key in @('initializationElapsedRealtimeMs','initializationWallMs',
            'currentElapsedRealtimeMs','eventFirstRetainedSequence','eventLastSequence',
            'eventCapacity','leaseSlotClaimCount','activityLiveCount','activitySerial',
            'activityAdmissionCollisions','coverGeneration')) {
        Assert-Integer $Id.$key "$Label.$key"
    }
    if ($Id.eventCapacity -ne 256 -or $Id.eventLastSequence -lt
            $Id.eventFirstRetainedSequence - 1) {
        Fail "$Label event window is invalid"
    }
    Assert-Boolean $Id.leaseSlotOccupied "$Label.leaseSlotOccupied"
    if ($Id.leaseSlotOccupied) { Fail "$Label has an unexpected occupied lease slot" }
    if ($Id.coverState -cnotin @('IDLE','REQUESTED','ACTIVE','FINISH_REQUESTED')) {
        Fail "$Label.coverState is unknown"
    }
}

function Assert-State($State, [string]$Label, [switch]$AllowAbsent) {
    if ($AllowAbsent -and $State.PSObject.Properties.Name -contains 'activityPresent') {
        Assert-ExactKeys $State @('schema','process','activityPresent') $Label
        if ($State.schema -cne 'disposable-lease-host-state-v1' -or
                $State.activityPresent -cne $false) { Fail "$Label absent state is invalid" }
        Assert-Identity $State.process "$Label.process"
        return
    }
    Assert-ExactKeys $State @(
        'schema','process','sampleElapsedRealtimeMs','activitySerial',
        'activityIdentityHash','lifecycle','taskId','displayId','orientation',
        'rootIdentityHash','rootAttached','rootWidth','rootHeight',
        'rootPaddingLeft','rootPaddingTop','baselineCaptured','actualLayoutPasses',
        'page','uri','renderEpoch','renderIdentityHash','layoutEpoch','childCount',
        'customDrawingOrderEnabled','lastPaintOrder','lastPaintElapsedRealtimeMs',
        'lastPaintLayoutPass','paintOrderMatchesOriginals','paintFreshForLayout',
        'requiredPaintRevision','lastPaintRevision','paintFreshForRevision',
        'children','originals','originalsPresent','originalRelativeOrder',
        'originalsAtExactIndices','originalGeometryAndParams',
        'exactNineBaseline','liveNineBaselineCandidate','fieldBindings'
    ) $Label
    if ($State.schema -cne 'disposable-lease-host-state-v1') {
        Fail "$Label has an unexpected schema"
    }
    Assert-Identity $State.process "$Label.process"
    foreach ($key in @('sampleElapsedRealtimeMs','activitySerial','actualLayoutPasses',
            'renderEpoch','layoutEpoch','lastPaintElapsedRealtimeMs',
            'lastPaintLayoutPass','requiredPaintRevision','lastPaintRevision')) {
        Assert-Integer $State.$key "$Label.$key"
    }
    foreach ($key in @('rootAttached','baselineCaptured','customDrawingOrderEnabled',
            'paintOrderMatchesOriginals','paintFreshForLayout','paintFreshForRevision',
            'originalsPresent','originalRelativeOrder','originalsAtExactIndices',
            'originalGeometryAndParams','exactNineBaseline','liveNineBaselineCandidate')) {
        Assert-Boolean $State.$key "$Label.$key"
    }
    if ($State.lifecycle -cnotin @('CREATED','STARTED','RESUMED','PAUSED',
            'STOPPED','DESTROYED') -or $State.uri -cnotin @(
            'probe://disposable-host/source-a','probe://disposable-host/source-b')) {
        Fail "$Label has an unknown lifecycle or synthetic URI"
    }
    if ($State.orientation -notin @(1,2) -or $State.page -notin @(1,2)) {
        Fail "$Label has invalid orientation or synthetic page"
    }
    if ($State.childCount -ne 9 -or @($State.children).Count -ne 9 -or
            @($State.originals).Count -ne 9) {
        Fail "$Label no longer has exactly nine original children"
    }
    Assert-ExactKeys $State.fieldBindings @(
        'pdfOriginal','digestOriginal','inkOriginal','pdfIdentityHash',
        'digestIdentityHash','inkIdentityHash') "$Label.fieldBindings"
    foreach ($key in @('pdfOriginal','digestOriginal','inkOriginal')) {
        if ($State.fieldBindings.$key -cne $true) { Fail "$Label.$key binding changed" }
    }
    for ($i = 0; $i -lt 9; $i++) {
        $child = $State.children[$i]
        $original = $State.originals[$i]
        $baseKeys = @('index','originalIndex','name','identityHash','class','id',
            'parentIsRoot','parentIdentityHash','visibility','left','top',
            'right','bottom','screenLeft','screenTop','screenRight',
            'screenBottom','elevation','translationZ','z','alpha',
            'rawDrawingPosition','layout')
        Assert-ExactKeys $child $baseKeys "$Label.children[$i]"
        Assert-ExactKeys $original ($baseKeys + @('present','baselineSignatureMatches')) "$Label.originals[$i]"
        if ($child.index -ne $i -or $child.originalIndex -ne $i -or
                $child.id -ne (0x71000100 + $i) -or
                $child.parentIsRoot -cne $true -or
                $original.identityHash -ne $child.identityHash -or
                $original.present -cne $true) {
            Fail "$Label original child $i changed identity, position, or parent"
        }
        Assert-ExactKeys $child.layout @('class','width','height','gravity',
            'leftMargin','topMargin','rightMargin','bottomMargin') "$Label.children[$i].layout"
    }
    foreach ($entry in @($State.lastPaintOrder)) {
        Assert-ExactKeys $entry @('paintPosition','childIndexAtPaint',
            'currentChildIndex','originalIndex','identityHash',
            'referenceStillLive') "$Label.lastPaintOrder"
    }
}

function Assert-Nine([pscustomobject]$State, [string]$Label,
        [switch]$RequireLivePaint, [switch]$RequireExactBaseline) {
    if (-not $State.baselineCaptured -or -not $State.originalsPresent -or
            -not $State.originalRelativeOrder -or
            -not $State.originalsAtExactIndices -or
            $State.customDrawingOrderEnabled) {
        Fail "$Label lost the nine-child structural baseline"
    }
    if ($RequireLivePaint -and ($State.lifecycle -cne 'RESUMED' -or
            -not $State.rootAttached -or -not $State.paintOrderMatchesOriginals -or
            -not $State.paintFreshForLayout -or
            -not $State.paintFreshForRevision -or
            @($State.lastPaintOrder).Count -ne 9)) {
        Fail "$Label lacks a fresh actual nine-child paint witness"
    }
    if ($RequireLivePaint) {
        for ($i = 0; $i -lt 9; $i++) {
            $paint = $State.lastPaintOrder[$i]
            $child = $State.children[$i]
            $original = $State.originals[$i]
            if ($paint.paintPosition -ne $i -or
                    $paint.childIndexAtPaint -ne $i -or
                    $paint.currentChildIndex -ne $i -or
                    $paint.originalIndex -ne $i -or
                    $paint.identityHash -ne $child.identityHash -or
                    $paint.identityHash -ne $original.identityHash -or
                    $paint.referenceStillLive -cne $true -or
                    $child.id -ne (0x71000100 + $i) -or
                    $child.parentIdentityHash -ne $State.rootIdentityHash -or
                    $original.parentIdentityHash -ne $State.rootIdentityHash -or
                    $child.rawDrawingPosition -ne $i) {
                Fail "$Label paint position $i differs from its original child"
            }
        }
        if ($State.lastPaintRevision -ne $State.requiredPaintRevision -or
                $State.lastPaintElapsedRealtimeMs -gt $State.sampleElapsedRealtimeMs -or
                ($State.sampleElapsedRealtimeMs - $State.lastPaintElapsedRealtimeMs) -gt 60000) {
            Fail "$Label paint is stale or older than the bounded 60-second baseline"
        }
    }
    if ($RequireExactBaseline -and -not $State.exactNineBaseline) {
        Fail "$Label does not match the original geometry baseline"
    }
}

function Has-FreshPaint($State) {
    return $State.lifecycle -ceq 'RESUMED' -and
        $State.rootAttached -and $State.paintOrderMatchesOriginals -and
        $State.paintFreshForLayout -and $State.paintFreshForRevision -and
        @($State.lastPaintOrder).Count -eq 9 -and
        ($State.sampleElapsedRealtimeMs - $State.lastPaintElapsedRealtimeMs) -ge 0 -and
        ($State.sampleElapsedRealtimeMs - $State.lastPaintElapsedRealtimeMs) -le 60000
}

function Invoke-Adb([string[]]$Arguments, [string]$Label,
        [int]$TimeoutMs = 10000) {
    if ($Serial -cne 'emulator-5554') { Fail 'ADB target changed' }
    foreach ($arg in $Arguments) {
        if ($arg -match '[\s"\x00]') { Fail "unsafe ADB argument for $Label" }
    }
    $all = @('-s','emulator-5554') + $Arguments
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $script:Adb
    $info.Arguments = ($all -join ' ')
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::Start($info)
    if ($null -eq $process) { Unknown "$Label did not start" }
    $outTask = $process.StandardOutput.ReadToEndAsync()
    $errTask = $process.StandardError.ReadToEndAsync()
    $timedOut = -not $process.WaitForExit($TimeoutMs)
    if ($timedOut) {
        try { $process.Kill() } catch { }
        $null = $process.WaitForExit(2000)
    }
    # A dead or detached ADB client can retain a pipe. Never await it without
    # a second bound after killing the process.
    $outDone = $outTask.Wait(2000)
    $errDone = $errTask.Wait(2000)
    $stdout = if ($outDone) { $outTask.GetAwaiter().GetResult() } else { '<stdout-incomplete>' }
    $stderr = if ($errDone) { $errTask.GetAwaiter().GetResult() } else { '<stderr-incomplete>' }
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
    if ($null -ne $script:RunDir) {
        $file = Join-Path $script:RunDir ('{0:d3}-{1}.json' -f
            $script:EvidenceNumber, ($Label -replace '[^A-Za-z0-9_-]','_'))
        [IO.File]::WriteAllText($file, ($record | ConvertTo-Json -Depth 8),
            [Text.UTF8Encoding]::new($false))
    }
    $process.Dispose()
    if ($timedOut -or -not $outDone -or -not $errDone) {
        Unknown "$Label timed out or left an incomplete stream; outcome must be inspected, not retried"
    }
    if ($code -ne 0) { Unknown "$Label ADB exit $code; outcome must be inspected" }
    if ($stderr.Trim().Length -gt 0) {
        Unknown "$Label emitted unexpected stderr; inspect recorded evidence"
    }
    return $stdout
}

function Assert-EmulatorPackage {
    $avd = Invoke-Adb @('emu','avd','name') 'preflight_avd_name'
    Assert-AvdName $avd
    $sdk = (Invoke-Adb @('shell','getprop','ro.build.version.sdk') 'preflight_sdk').Trim()
    if ($sdk -cne '30') { Fail 'target is not Android API 30' }
    if (-not (Test-Path -LiteralPath $script:SignedApk -PathType Leaf)) {
        Fail 'pinned signed emulator-only APK is missing'
    }
    $hostHash = (Get-FileHash -LiteralPath $script:SignedApk -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hostHash -cne $script:ExpectedApkSha256) { Fail 'signed host APK hash mismatch' }
    if (-not (Test-Path -LiteralPath $script:Java -PathType Leaf) -or
            -not (Test-Path -LiteralPath $script:ApksignerJar -PathType Leaf)) {
        Fail 'local apksigner verifier is unavailable'
    }
    $certLines = @(& $script:Java -jar $script:ApksignerJar verify --print-certs $script:SignedApk 2>&1)
    if ($LASTEXITCODE -ne 0) { Fail 'signed host APK failed apksigner verification' }
    $fingerprints = @($certLines | Where-Object {
        $_ -cmatch '^Signer #1 certificate SHA-256 digest: ([a-fA-F0-9]{64})$'
    })
    if ($fingerprints.Count -ne 1 -or
            $fingerprints[0] -cnotmatch '^Signer #1 certificate SHA-256 digest: ([a-fA-F0-9]{64})$' -or
            $Matches[1].ToLowerInvariant() -cne $script:ExpectedCertSha256) {
        Fail 'signed host APK certificate fingerprint mismatch'
    }
    $pm = (Invoke-Adb @('shell','pm','path',$script:Package) 'preflight_package_path').Trim()
    if ($pm -cnotmatch '^package:(/data/app/[^\s]+/base\.apk)$') {
        Fail 'expected disposable package is not installed as one base APK'
    }
    $installedPath = $Matches[1]
    $shaOutput = (Invoke-Adb @('shell','sha256sum',$installedPath) 'preflight_installed_apk_sha256').Trim()
    if ($shaOutput -cnotmatch '^([a-fA-F0-9]{64})\s+/data/app/[^\s]+/base\.apk$' -or
            $Matches[1].ToLowerInvariant() -cne $script:ExpectedApkSha256) {
        Fail 'installed APK bytes differ from the pinned signed emulator artifact'
    }
    $script:Summary.package = $script:Package
    $script:Summary.installedApkSha256 = $script:ExpectedApkSha256
    # Installed byte equality binds the just-verified local signing block.
    $script:Summary.signerCertSha256 = $script:ExpectedCertSha256
    Write-Summary
}

function Read-Identity([string]$Label) {
    $text = Invoke-Adb @('shell','content','query','--uri',
        "$script:Authority/identity") $Label
    $id = Parse-OneJsonRow $text $Label
    Assert-Identity $id $Label
    return $id
}

function Read-State([string]$Label, [switch]$AllowAbsent) {
    $text = Invoke-Adb @('shell','content','query','--uri',
        "$script:Authority/state") $Label
    $state = Parse-OneJsonRow $text $Label
    Assert-State $state $Label -AllowAbsent:$AllowAbsent
    return $state
}

function Assert-SameProcess($State, $Anchor, [string]$Label) {
    $reference = if ($Anchor.PSObject.Properties.Name -contains 'process') {
        $Anchor.process
    } else { $Anchor }
    if ($State.process.pid -ne $reference.pid -or
            $State.process.incarnation -cne $reference.incarnation -or
            $State.process.initializationElapsedRealtimeMs -ne
                $reference.initializationElapsedRealtimeMs) {
        Unknown "$Label observed a different process; provider queries can restart one"
    }
}

function Assert-SameActivity($State, $Anchor, [string]$Label) {
    Assert-SameProcess $State $Anchor $Label
    if ($State.activitySerial -ne $Anchor.activitySerial -or
            $State.rootIdentityHash -ne $Anchor.rootIdentityHash -or
            $State.activityIdentityHash -ne $Anchor.activityIdentityHash) {
        Unknown "$Label switched activity/root during an ordinary scene trial"
    }
}

function Wait-State([string]$Label, $Anchor, [scriptblock]$Accept,
        [switch]$AllowAbsent) {
    $until = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $state = Read-State $Label -AllowAbsent:$AllowAbsent
        Assert-SameProcess $state $Anchor $Label
        if (& $Accept $state) { return $state }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $until)
    Unknown "$Label did not reach the expected state within ten seconds"
}

function Parse-EventRows([string]$Text, [string]$Label, [long]$After, $Anchor) {
    $lines = @(Get-AdbLines $Text)
    if ($lines.Count -eq 0) { Fail "$Label returned no event rows" }
    $events = @()
    $last = $After
    $row = 0
    $windowFirst = -1L
    $windowLast = -1L
    foreach ($line in $lines) {
        if ($line -cnotmatch '^Row: (\d+) pid=(\d+), incarnation=([^,]+), windowFirstSequence=(\d+), windowLastSequence=(\d+), sequence=(\d+), elapsedRealtimeMs=(\d+), name=([A-Z0-9_]+), detail=(.*)$') {
            Fail "$Label has malformed event-row output"
        }
        $m = $Matches
        if ($row -eq 0) {
            $windowFirst = [long]$m[4]
            $windowLast = [long]$m[5]
        }
        if ([int]$m[1] -ne $row -or [int]$m[2] -ne $Anchor.pid -or
                $m[3] -cne $Anchor.incarnation -or
                [long]$m[4] -ne $windowFirst -or
                [long]$m[5] -ne $windowLast -or
                $windowFirst -gt ($After + 1) -or
                [long]$m[6] -ne ($last + 1) -or
                [long]$m[6] -gt $windowLast) {
            Fail "$Label event sequence/window or process identity is inconsistent"
        }
        $last = [long]$m[6]
        $events += [pscustomobject]@{ sequence = $last; name = $m[8]; detail = $m[9] }
        $row++
    }
    if ($last -ne $windowLast) { Fail "$Label omitted the end of the reported event window" }
    return ,$events
}

function Read-Events([string]$Label, [long]$After, $Anchor) {
    $text = Invoke-Adb @('shell','content','query','--uri',
        "$script:Authority/events?after=$After") $Label
    return ,(Parse-EventRows $text $Label $After $Anchor)
}

function Assert-Events($Events, [string[]]$Names, [string]$Label,
        [string[]]$Details = @()) {
    $seen = @($Events | ForEach-Object { $_.name })
    $lastPosition = -1
    for ($i = 0; $i -lt $Names.Count; $i++) {
        $position = -1
        for ($j = $lastPosition + 1; $j -lt $Events.Count; $j++) {
            if ($Events[$j].name -ceq $Names[$i]) { $position = $j; break }
        }
        if ($position -lt 0) { Fail "$Label lacks ordered event witness $($Names[$i])" }
        if ($i -lt $Details.Count -and $Details[$i] -ne '' -and
                $Events[$position].detail -cne $Details[$i]) {
            Fail "$Label event $($Names[$i]) has unexpected detail"
        }
        $lastPosition = $position
    }
    foreach ($bad in @('MAIN_DISPATCH_TIMEOUT','ACTIVITY_ADMISSION_COLLISION',
            'COVER_COLLISION','COVER_DESTROY_MISMATCH','COVER_LAUNCH_FAILED')) {
        if ($bad -cin $seen) { Unknown "$Label reported $bad" }
    }
}

function Toggle-Detail($State) {
    return "page=$($State.page) uri=$($State.uri) render=$($State.renderEpoch) layout=$($State.layoutEpoch)"
}

function Assert-ToggleTransition([string]$Name, $Before, $Observed,
        [switch]$Restored) {
    $page = $Before.page
    $uri = $Before.uri
    $render = $Before.renderEpoch
    $layout = $Before.layoutEpoch
    if ($Restored) {
        if ($Name -eq 'render') { $render += 2 }
        if ($Name -eq 'layout') { $layout += 2 }
    } else {
        switch ($Name) {
            'page' { $page = 3 - $page }
            'uri' {
                $uri = if ($uri -ceq 'probe://disposable-host/source-a') {
                    'probe://disposable-host/source-b'
                } else { 'probe://disposable-host/source-a' }
            }
            'render' { $render++ }
            'layout' { $layout++ }
            default { Fail "unknown synthetic toggle $Name" }
        }
    }
    if ($Observed.page -ne $page -or $Observed.uri -cne $uri -or
            $Observed.renderEpoch -ne $render -or
            $Observed.layoutEpoch -ne $layout -or
            $Observed.orientation -ne $Before.orientation) {
        Fail "$Name changed an unrelated dimension or failed its inverse"
    }
    if (-not $Restored -and $Name -eq 'layout') {
        if ($Before.rootPaddingLeft -ne 0 -or $Before.rootPaddingTop -ne 0 -or
                $Observed.rootPaddingLeft -le 0 -or
                $Observed.rootPaddingTop -ne $Observed.rootPaddingLeft -or
                $Observed.originalGeometryAndParams -cne $false -or
                $Observed.exactNineBaseline -cne $false) {
            Fail 'layout did not produce symmetric nonzero inset and altered geometry'
        }
    } elseif ($Observed.rootPaddingLeft -ne $Before.rootPaddingLeft -or
            $Observed.rootPaddingTop -ne $Before.rootPaddingTop -or
            $Observed.originalGeometryAndParams -cne $Before.originalGeometryAndParams -or
            $Observed.exactNineBaseline -cne $Before.exactNineBaseline) {
        Fail "$Name failed presentation geometry parity"
    }
    if (-not $Restored -and $Name -eq 'render' -and
            $Observed.renderIdentityHash -eq $Before.renderIdentityHash) {
        Fail 'render token did not change identity'
    }
}

function Assert-LayoutChildGeometry($Before, $Observed, [switch]$Restored) {
    $shift = if ($Restored) { 0 } else {
        $Observed.rootPaddingLeft - $Before.rootPaddingLeft
    }
    if ($shift -lt 0 -or ($Restored -and $shift -ne 0) -or
            (-not $Restored -and $shift -le 0) -or
            $Observed.rootWidth -ne $Before.rootWidth -or
            $Observed.rootHeight -ne $Before.rootHeight -or
            @($Before.children).Count -ne 9 -or
            @($Observed.children).Count -ne 9) {
        Fail 'layout child-geometry premise changed'
    }
    for ($i = 0; $i -lt 9; $i++) {
        $beforeChild = $Before.children[$i]
        $observedChild = $Observed.children[$i]
        foreach ($key in @('identityHash','id','class','name','index',
                'originalIndex','parentIsRoot','parentIdentityHash','visibility',
                'alpha','elevation','translationZ','z','rawDrawingPosition')) {
            if ($observedChild.$key -cne $beforeChild.$key) {
                Fail "layout child $i changed metadata $key"
            }
        }
        foreach ($key in @('class','width','height','gravity','leftMargin',
                'topMargin','rightMargin','bottomMargin')) {
            if ($observedChild.layout.$key -cne $beforeChild.layout.$key) {
                Fail "layout child $i changed layout parameter $key"
            }
        }
        foreach ($key in @('left','top','right','bottom','screenLeft',
                'screenTop','screenRight','screenBottom')) {
            if ($observedChild.$key -ne ($beforeChild.$key + $shift)) {
                Fail "layout child $i did not shift $key by exactly $shift"
            }
        }
    }
}

function Assert-CoverRestore($Before, $Restored) {
    if ($Restored.page -ne $Before.page -or $Restored.uri -cne $Before.uri -or
            $Restored.renderEpoch -ne $Before.renderEpoch -or
            $Restored.layoutEpoch -ne $Before.layoutEpoch -or
            $Restored.orientation -ne $Before.orientation -or
            $Restored.rootPaddingLeft -ne $Before.rootPaddingLeft -or
            $Restored.rootPaddingTop -ne $Before.rootPaddingTop -or
            $Restored.originalGeometryAndParams -cne $true -or
            $Restored.exactNineBaseline -cne $true) {
        Fail 'cover/uncover did not restore the exact nine-child scene'
    }
}

function Parse-CommandBundle([string]$Text, [string]$Command,
        [string]$Label) {
    $lines = @(Get-AdbLines $Text)
    if ($lines.Count -ne 1 -or $lines[0] -cnotmatch '^Result: Bundle\[\{(.*)\}\]$') {
        Unknown "$Label command response is not exactly one Bundle"
    }
    $body = $Matches[1]
    $fields = New-Object System.Collections.ArrayList
    $depth = 0
    $quoted = $false
    $escaped = $false
    $start = 0
    for ($i = 0; $i -lt $body.Length; $i++) {
        $c = $body[$i]
        if ($quoted) {
            if ($escaped) { $escaped = $false }
            elseif ($c -eq '\') { $escaped = $true }
            elseif ($c -eq '"') { $quoted = $false }
        } elseif ($c -eq '"') { $quoted = $true }
        elseif ($c -eq '{' -or $c -eq '[') { $depth++ }
        elseif ($c -eq '}' -or $c -eq ']') {
            $depth--
            if ($depth -lt 0) { Unknown "$Label malformed Bundle nesting" }
        } elseif ($c -eq ',' -and $depth -eq 0) {
            $null = $fields.Add($body.Substring($start, $i - $start).Trim())
            $start = $i + 1
        }
    }
    if ($quoted -or $depth -ne 0) { Unknown "$Label malformed Bundle payload" }
    $null = $fields.Add($body.Substring($start).Trim())
    $parsed = @{}
    foreach ($field in $fields) {
        if ($field -cnotmatch '^([a-z]+)=(.*)$' -or
                $parsed.ContainsKey($Matches[1])) {
            Unknown "$Label has duplicate or malformed Bundle fields"
        }
        $parsed.Add($Matches[1], $Matches[2])
    }
    if ($fields.Count -ne 3 -or $parsed.Count -ne 3 -or
            $parsed.ok -cne 'true' -or $parsed.command -cne $Command -or
            $parsed.json -cnotmatch '^\{.*\}$') {
        Unknown "$Label Bundle did not explicitly accept exactly $Command"
    }
    Assert-NoDuplicateJsonKeys $parsed.json "$Label.json"
    try { $embedded = ConvertFrom-Json -InputObject $parsed.json -ErrorAction Stop }
    catch { Unknown "$Label has invalid embedded state JSON" }
    Assert-State $embedded "$Label.json" -AllowAbsent
    return $embedded
}

function Send-CommandOnce([string]$Command, [string]$Label) {
    if ($Command -cnotin @('page','uri','render','layout','orientation',
            'cover','uncover','finish')) { Fail "unsupported command $Command" }
    $text = Invoke-Adb @('shell','content','call','--uri',$script:Authority,
        '--method','command','--arg',$Command) $Label
    return Parse-CommandBundle $text $Command $Label
}

function Record-Trial([string]$Name, $Before, $After, $Restored,
        $Events, $RollbackEvents) {
    $script:Summary.trials += [ordered]@{
        name = $Name
        outcome = 'PASS'
        beforePage = $Before.page
        afterPage = $After.page
        restoredPage = $Restored.page
        beforeUri = $Before.uri
        afterUri = $After.uri
        restoredUri = $Restored.uri
        beforeLayoutEpoch = $Before.layoutEpoch
        afterLayoutEpoch = $After.layoutEpoch
        restoredLayoutEpoch = $Restored.layoutEpoch
        beforeRenderEpoch = $Before.renderEpoch
        afterRenderEpoch = $After.renderEpoch
        restoredRenderEpoch = $Restored.renderEpoch
        eventSequences = @($Events | ForEach-Object { $_.sequence })
        eventNames = @($Events | ForEach-Object { $_.name })
        rollbackEventNames = @($RollbackEvents | ForEach-Object { $_.name })
    }
    Write-Summary
}

function Write-Summary {
    if ($null -ne $script:RunDir) {
        $path = Join-Path $script:RunDir 'summary.json'
        [IO.File]::WriteAllText($path, ($script:Summary | ConvertTo-Json -Depth 10),
            [Text.UTF8Encoding]::new($false))
    }
}

function Test-Parser {
    $crcrlf = "`r`r`n"
    Assert-AvdName "RTL_Lease_API30${crcrlf}OK${crcrlf}"
    foreach ($badAvd in @(
            "RTL_Lease_API30X${crcrlf}OK${crcrlf}",
            "RTL_Lease_API30${crcrlf}OK${crcrlf}EXTRA${crcrlf}")) {
        $rejected = $false
        try { Assert-AvdName $badAvd }
        catch { $rejected = $true }
        if (-not $rejected) { Fail 'wrong AVD identity passed CRCRLF self-test' }
    }
    $good = Parse-OneJsonRow 'Row: 0 json={"schema":"x"}' 'self-test'
    $goodCrcrlf = Parse-OneJsonRow "Row: 0 json={`"schema`":`"x`"}${crcrlf}" 'self-test-crcrlf'
    if ($goodCrcrlf.schema -cne 'x') { Fail 'CRCRLF JSON row failed self-test' }
    Assert-ExactKeys $good @('schema') 'self-test'
    if ($good.schema -cne 'x') { Fail 'valid parser self-test failed' }
    foreach ($bad in @(
            'Row: 1 json={"schema":"x"}',
            "Row: 0 json={`"schema`":`"x`"}`nRow: 1 json={}",
            'Row: 0 json=[]',
            'Row: 0 json={"schema":"x","schema":"y"}')) {
        $rejected = $false
        try { $null = Parse-OneJsonRow $bad 'self-test' }
        catch { $rejected = $true }
        if (-not $rejected) { Fail 'malformed row passed parser self-test' }
    }
    $identity = [ordered]@{
        pid=123; incarnation='11111111-2222-3333-4444-555555555555'
        initializationElapsedRealtimeMs=1; initializationWallMs=1
        currentElapsedRealtimeMs=2; eventFirstRetainedSequence=1
        eventLastSequence=1; eventCapacity=256; leaseSlotOccupied=$false
        leaseSlotOwnerIdentityHash=0; leaseSlotOwnerClass=$null
        leaseSlotClaimCount=0; activityLiveCount=0; activitySerial=0
        activityRootIdentityHash=0; activityAdmissionCollisions=0
        coverState='IDLE'; coverGeneration=0
    }
    Assert-Identity ([pscustomobject]$identity) 'self-test-identity'
    $identity.pid = '123'
    $rejected = $false
    try { Assert-Identity ([pscustomobject]$identity) 'self-test-wrong-type' }
    catch { $rejected = $true }
    if (-not $rejected) { Fail 'wrong numeric JSON type passed self-test' }
    $identity.pid = 123
    $stateAnchor = [pscustomobject]@{ process = [pscustomobject]$identity }
    Assert-SameProcess $stateAnchor $stateAnchor 'self-test-state-anchor'
    Assert-SameProcess $stateAnchor ([pscustomobject]$identity) 'self-test-identity-anchor'
    $absent = [ordered]@{
        schema='disposable-lease-host-state-v1'; process=$identity
        activityPresent=$false
    } | ConvertTo-Json -Compress -Depth 8
    $accepted = Parse-CommandBundle "Result: Bundle[{ok=true, json=$absent, command=page}]" 'page' 'self-test-bundle'
    $acceptedCrcrlf = Parse-CommandBundle "Result: Bundle[{ok=true, json=$absent, command=page}]${crcrlf}" 'page' 'self-test-bundle-crcrlf'
    if ($acceptedCrcrlf.activityPresent -cne $false) { Fail 'CRCRLF Bundle failed self-test' }
    if ($accepted.activityPresent -cne $false) { Fail 'exact Bundle parser rejected a valid command' }
    foreach ($bad in @(
            "Result: Bundle[{ok=true, json=$absent, command=page, ok=true}]",
            "Result: Bundle[{ok=false, json=$absent, command=page}]",
            "Result: Bundle[{ok=true, json=$absent, command=uri}]")) {
        $rejected = $false
        try { $null = Parse-CommandBundle $bad 'page' 'self-test-bad-bundle' }
        catch { $rejected = $true }
        if (-not $rejected) { Fail 'ambiguous Bundle passed self-test' }
    }
    $anchor = [pscustomobject]@{
        pid=123; incarnation='11111111-2222-3333-4444-555555555555'
    }
    $row2 = 'Row: 0 pid=123, incarnation=11111111-2222-3333-4444-555555555555, windowFirstSequence=1, windowLastSequence=3, sequence=2, elapsedRealtimeMs=3, name=TOGGLE_PAGE, detail=page=2'
    $row3 = 'Row: 1 pid=123, incarnation=11111111-2222-3333-4444-555555555555, windowFirstSequence=1, windowLastSequence=3, sequence=3, elapsedRealtimeMs=4, name=LAYOUT_PASS, detail=2'
    $parsed = Parse-EventRows "$row2`n$row3" 'self-test-events' 1 $anchor
    $parsedCrcrlf = Parse-EventRows "$row2${crcrlf}$row3${crcrlf}" 'self-test-events-crcrlf' 1 $anchor
    if (@($parsedCrcrlf).Count -ne 2) { Fail 'CRCRLF event rows failed self-test' }
    if (@($parsed).Count -ne 2) { Fail 'valid event window failed parser self-test' }
    foreach ($bad in @($row3, "$row2`n$($row3 -replace 'windowLastSequence=3','windowLastSequence=4')")) {
        $rejected = $false
        try { $null = Parse-EventRows $bad 'self-test-bad-events' 1 $anchor }
        catch { $rejected = $true }
        if (-not $rejected) { Fail 'gapped or inconsistent event window passed self-test' }
    }
    $baseScene = [pscustomobject]@{
        page=1; uri='probe://disposable-host/source-a'; renderEpoch=0
        layoutEpoch=0; renderIdentityHash=11; orientation=1
        originalGeometryAndParams=$true; exactNineBaseline=$true
        rootPaddingLeft=0; rootPaddingTop=0
    }
    foreach ($name in @('page','uri','render','layout')) {
        $changed = $baseScene | ConvertTo-Json -Compress | ConvertFrom-Json
        $restored = $baseScene | ConvertTo-Json -Compress | ConvertFrom-Json
        switch ($name) {
            'page' { $changed.page=2 }
            'uri' { $changed.uri='probe://disposable-host/source-b' }
            'render' { $changed.renderEpoch=1; $changed.renderIdentityHash=12
                       $restored.renderEpoch=2 }
            'layout' { $changed.layoutEpoch=1; $changed.rootPaddingLeft=12
                       $changed.rootPaddingTop=12
                       $changed.originalGeometryAndParams=$false
                       $changed.exactNineBaseline=$false
                       $restored.layoutEpoch=2 }
        }
        Assert-ToggleTransition $name $baseScene $changed
        Assert-ToggleTransition $name $baseScene $restored -Restored
        $changed.page=9
        $rejected = $false
        try { Assert-ToggleTransition $name $baseScene $changed }
        catch { $rejected = $true }
        if (-not $rejected) { Fail "incorrect $name scene passed matrix self-test" }
        if ($name -eq 'layout') {
            $changed.page=1; $changed.rootPaddingTop=0
            $rejected = $false
            try { Assert-ToggleTransition 'layout' $baseScene $changed }
            catch { $rejected = $true }
            if (-not $rejected) { Fail 'one-sided layout inset passed matrix self-test' }
            $changed.rootPaddingTop=12; $changed.originalGeometryAndParams=$true
            $rejected = $false
            try { Assert-ToggleTransition 'layout' $baseScene $changed }
            catch { $rejected = $true }
            if (-not $rejected) { Fail 'unchanged layout geometry passed matrix self-test' }
        } else {
            $changed.page = if ($name -eq 'page') { 2 } else { 1 }
            $changed.exactNineBaseline=$false
            $rejected = $false
            try { Assert-ToggleTransition $name $baseScene $changed }
            catch { $rejected = $true }
            if (-not $rejected) { Fail "$name geometry drift passed matrix self-test" }
        }
    }
    Assert-CoverRestore $baseScene $baseScene
    $badCover = $baseScene | ConvertTo-Json -Compress | ConvertFrom-Json
    $badCover.exactNineBaseline = $false
    $rejected = $false
    try { Assert-CoverRestore $baseScene $badCover }
    catch { $rejected = $true }
    if (-not $rejected) { Fail 'cover geometry drift passed matrix self-test' }
    $childFixture = @()
    for ($i = 0; $i -lt 9; $i++) {
        $childFixture += [pscustomobject]@{
            identityHash=100+$i; id=0x71000100+$i; class='android.view.View'
            name="original-$i"; index=$i; originalIndex=$i
            parentIsRoot=$true; parentIdentityHash=77; visibility=0
            alpha=1.0; elevation=0.0; translationZ=0.0; z=0.0
            rawDrawingPosition=$i; left=10+$i; top=20+$i
            right=30+$i; bottom=40+$i; screenLeft=50+$i
            screenTop=60+$i; screenRight=70+$i; screenBottom=80+$i
            layout=[pscustomobject]@{
                class='android.widget.FrameLayout$LayoutParams'; width=20
                height=20; gravity=51; leftMargin=10; topMargin=20
                rightMargin=0; bottomMargin=0
            }
        }
    }
    $layoutBefore = [pscustomobject]@{
        rootWidth=100; rootHeight=200; rootPaddingLeft=0
        children=$childFixture
    }
    $layoutChanged = $layoutBefore | ConvertTo-Json -Depth 6 -Compress | ConvertFrom-Json
    $layoutChanged.rootPaddingLeft=33
    foreach ($child in $layoutChanged.children) {
        foreach ($key in @('left','top','right','bottom','screenLeft',
                'screenTop','screenRight','screenBottom')) {
            $child.$key += 33
        }
    }
    Assert-LayoutChildGeometry $layoutBefore $layoutChanged
    Assert-LayoutChildGeometry $layoutBefore $layoutBefore -Restored
    $layoutChanged.children[4].left -= 33
    $rejected = $false
    try { Assert-LayoutChildGeometry $layoutBefore $layoutChanged }
    catch { $rejected = $true }
    if (-not $rejected) { Fail 'one unmoved child passed layout shift self-test' }
    $layoutChanged.children[4].left += 33
    $layoutChanged.children[4].layout.leftMargin++
    $rejected = $false
    try { Assert-LayoutChildGeometry $layoutBefore $layoutChanged }
    catch { $rejected = $true }
    if (-not $rejected) { Fail 'changed child layout params passed self-test' }
    $layoutChanged.children[4].layout.leftMargin--
    $rollbackBad = $layoutBefore | ConvertTo-Json -Depth 6 -Compress | ConvertFrom-Json
    $rollbackBad.children[4].top++
    $rejected = $false
    try { Assert-LayoutChildGeometry $layoutBefore $rollbackBad -Restored }
    catch { $rejected = $true }
    if (-not $rejected) { Fail 'misplaced rollback child passed self-test' }
    Write-Output 'Parser and scene-matrix self-tests PASS (host-only; no ADB)'
}

if ($ParserSelfTest) { Test-Parser; return }
if (-not (Test-Path -LiteralPath $script:Adb -PathType Leaf)) {
    Fail 'Android SDK adb.exe is unavailable'
}
$build = Join-Path $PSScriptRoot 'build'
if (-not (Test-Path -LiteralPath $build)) {
    $null = New-Item -ItemType Directory -Path $build
}
if ((Get-Item -LiteralPath $build).Attributes -band [IO.FileAttributes]::ReparsePoint) {
    Fail 'evidence build directory is a reparse point'
}
$stamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')
$script:RunDir = Join-Path $build "emulator-gate-$stamp"
$null = New-Item -ItemType Directory -Path $script:RunDir -ErrorAction Stop
Write-Summary
$lockPath = Join-Path $build 'emulator-gate.lock'
try {
    $script:RunLock = New-Object System.IO.FileStream($lockPath,
        [IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
} catch {
    Fail 'another emulator gate run owns the same-run lock'
}

try {
    Assert-EmulatorPackage
    # The disposable app must already be visibly active. Querying an inactive
    # provider may start a fresh process; that is not a valid baseline.
    $id = Read-Identity 'initial_identity'
    $first = Wait-State 'initial_state' $id {
        param($s)
        return $s.lifecycle -ceq 'RESUMED' -and
            $s.liveNineBaselineCandidate -and
            ($s.sampleElapsedRealtimeMs - $s.lastPaintElapsedRealtimeMs) -le 60000
    }
    Assert-SameProcess $first $id 'initial_state'
    if ($id.activityLiveCount -ne 1 -or $first.lifecycle -cne 'RESUMED' -or
            $id.coverState -cne 'IDLE' -or $id.leaseSlotClaimCount -ne 0) {
        Fail 'disposable activity is not an unleased active baseline'
    }
    Assert-Nine $first 'initial_state' -RequireLivePaint -RequireExactBaseline
    if ($first.page -ne 1 -or
            $first.uri -cne 'probe://disposable-host/source-a' -or
            $first.renderEpoch -ne 0 -or $first.layoutEpoch -ne 0 -or
            $first.orientation -ne 1 -or $first.rootPaddingLeft -ne 0 -or
            $first.rootPaddingTop -ne 0) {
        Fail 'fixed PAGE 1 / source A / zero-epoch / portrait scene is not present; reset manually'
    }
    Start-Sleep -Milliseconds 300
    $second = Read-State 'stable_baseline_state'
    Assert-SameActivity $second $first 'stable_baseline_state'
    Assert-Nine $second 'stable_baseline_state' -RequireLivePaint -RequireExactBaseline
    if ($second.sampleElapsedRealtimeMs -le $first.sampleElapsedRealtimeMs -or
            ($second.sampleElapsedRealtimeMs - $first.sampleElapsedRealtimeMs) -gt 2000 -or
            $second.requiredPaintRevision -ne $first.requiredPaintRevision -or
            $second.lastPaintRevision -ne $first.lastPaintRevision) {
        Fail 'two baseline samples lack a bounded stable paint interval'
    }
    if ($second.page -ne $first.page -or $second.uri -cne $first.uri -or
            $second.layoutEpoch -ne $first.layoutEpoch -or
            $second.renderEpoch -ne $first.renderEpoch -or
            $second.originals[0].identityHash -ne $first.originals[0].identityHash) {
        Fail 'two initial baseline samples are not stable'
    }
    $anchor = $first
    $script:Summary.trials += [ordered]@{ name='two_stable_baselines'; outcome='PASS' }
    Write-Summary

    # Each command changes exactly one synthetic dimension. Every command is
    # sent once. Polling is read-only and bounded; timeout is UNKNOWN.
    foreach ($trial in @(
            [pscustomobject]@{ name='page'; event='TOGGLE_PAGE' },
            [pscustomobject]@{ name='uri'; event='TOGGLE_URI' },
            [pscustomobject]@{ name='render'; event='TOGGLE_RENDER' },
            [pscustomobject]@{ name='layout'; event='TOGGLE_LAYOUT' })) {
        $before = Wait-State "$($trial.name)_before" $anchor {
            param($s)
            return Has-FreshPaint $s
        }
        Assert-SameActivity $before $anchor "$($trial.name)_before"
        Assert-Nine $before "$($trial.name)_before" -RequireLivePaint
        $cursor = [long]$before.process.eventLastSequence
        $null = Send-CommandOnce $trial.name "$($trial.name)_command"
        $after = Wait-State "$($trial.name)_after" $anchor {
            param($s)
            if ($s.activitySerial -ne $anchor.activitySerial -or
                    $s.rootIdentityHash -ne $anchor.rootIdentityHash) {
                Unknown 'activity/root changed during scene polling'
            }
            if (-not (Has-FreshPaint $s)) { return $false }
            switch ($trial.name) {
                'page' { return $s.page -ne $before.page }
                'uri' { return $s.uri -cne $before.uri }
                'render' { return $s.renderEpoch -eq ($before.renderEpoch + 1) }
                'layout' { return $s.layoutEpoch -eq ($before.layoutEpoch + 1) }
            }
            return $false
        }
        Assert-SameActivity $after $anchor "$($trial.name)_after"
        if ($trial.name -eq 'layout') {
            Assert-Nine $after "$($trial.name)_after" -RequireLivePaint
        } else {
            Assert-Nine $after "$($trial.name)_after" -RequireLivePaint -RequireExactBaseline
        }
        Assert-ToggleTransition $trial.name $before $after
        if ($trial.name -eq 'layout') {
            Assert-LayoutChildGeometry $before $after
        }
        $events = Read-Events "$($trial.name)_events" $cursor $id
        Assert-Events $events @($trial.event) $trial.name @((Toggle-Detail $after))

        # The same deterministic toggle is an inverse operation for page,
        # URI, and layout. Render epochs cannot decrement, but the second
        # toggle restores presentation parity with a fresh paint witness.
        $cursor = [long]$after.process.eventLastSequence
        $null = Send-CommandOnce $trial.name "$($trial.name)_rollback_command"
        $restored = Wait-State "$($trial.name)_restored" $anchor {
            param($s)
            if (-not (Has-FreshPaint $s)) { return $false }
            switch ($trial.name) {
                'page' { return $s.page -eq $before.page }
                'uri' { return $s.uri -ceq $before.uri }
                'render' { return $s.renderEpoch -eq ($before.renderEpoch + 2) }
                'layout' { return $s.layoutEpoch -eq ($before.layoutEpoch + 2) }
            }
            return $false
        }
        Assert-SameActivity $restored $anchor "$($trial.name)_restored"
        Assert-Nine $restored "$($trial.name)_restored" -RequireLivePaint -RequireExactBaseline
        Assert-ToggleTransition $trial.name $before $restored -Restored
        if ($trial.name -eq 'layout') {
            Assert-LayoutChildGeometry $before $restored -Restored
        }
        $rollbackEvents = Read-Events "$($trial.name)_rollback_events" $cursor $id
        Assert-Events $rollbackEvents @($trial.event) "$($trial.name)_rollback" @((Toggle-Detail $restored))
        Record-Trial $trial.name $before $after $restored $events $rollbackEvents
    }

    $before = Wait-State 'orientation_before' $anchor { param($s) Has-FreshPaint $s }
    Assert-SameActivity $before $anchor 'orientation_before'
    $cursor = [long]$before.process.eventLastSequence
    $null = Send-CommandOnce 'orientation' 'orientation_command'
    $after = Wait-State 'orientation_after' $anchor {
        param($s)
        return $s.orientation -ne $before.orientation -and
            $s.layoutEpoch -eq ($before.layoutEpoch + 1) -and
            (Has-FreshPaint $s)
    }
    Assert-SameActivity $after $anchor 'orientation_after'
    Assert-Nine $after 'orientation_after' -RequireLivePaint
    if ($after.page -ne $before.page -or $after.uri -cne $before.uri -or
            $after.renderEpoch -ne $before.renderEpoch) {
        Fail 'orientation changed a non-layout synthetic dimension'
    }
    $events = Read-Events 'orientation_events' $cursor $id
    Assert-Events $events @('ORIENTATION_REQUEST','CONFIGURATION_CHANGE') 'orientation' @('0',"orientation=$($after.orientation) layoutEpoch=$($after.layoutEpoch)")
    $cursor = [long]$after.process.eventLastSequence
    $null = Send-CommandOnce 'orientation' 'orientation_rollback_command'
    $restored = Wait-State 'orientation_restored' $anchor {
        param($s)
        return $s.orientation -eq $before.orientation -and
            $s.layoutEpoch -eq ($before.layoutEpoch + 2) -and
            (Has-FreshPaint $s)
    }
    Assert-SameActivity $restored $anchor 'orientation_restored'
    Assert-Nine $restored 'orientation_restored' -RequireLivePaint -RequireExactBaseline
    if ($restored.page -ne $before.page -or
            $restored.uri -cne $before.uri -or
            $restored.renderEpoch -ne $before.renderEpoch -or
            $restored.rootPaddingLeft -ne $before.rootPaddingLeft -or
            $restored.rootPaddingTop -ne $before.rootPaddingTop) {
        Fail 'orientation rollback changed other synthetic state'
    }
    $rollbackEvents = Read-Events 'orientation_rollback_events' $cursor $id
    Assert-Events $rollbackEvents @('ORIENTATION_REQUEST','CONFIGURATION_CHANGE') 'orientation_rollback' @('1',"orientation=$($restored.orientation) layoutEpoch=$($restored.layoutEpoch)")
    Record-Trial 'orientation' $before $after $restored $events $rollbackEvents

    $before = Wait-State 'cover_before' $anchor { param($s) Has-FreshPaint $s }
    Assert-SameActivity $before $anchor 'cover_before'
    $cursor = [long]$before.process.eventLastSequence
    $null = Send-CommandOnce 'cover' 'cover_command'
    $after = Wait-State 'cover_after' $anchor {
        param($s)
        return $s.process.coverState -ceq 'ACTIVE' -and
            $s.lifecycle -cin @('PAUSED','STOPPED')
    }
    Assert-SameActivity $after $anchor 'cover_after'
    Assert-Nine $after 'cover_after'
    $events = Read-Events 'cover_events' $cursor $id
    Assert-Events $events @('COVER_REQUEST','COVER_ACTIVATE') 'cover_activation' @(
        "generation=$($after.process.coverGeneration)",
        "generation=$($after.process.coverGeneration) result=ACTIVE")
    Assert-Events $events @('COVER_REQUEST','ACTIVITY_PAUSE') 'cover_pause' @(
        "generation=$($after.process.coverGeneration)","serial=$($before.activitySerial)")
    $coverBefore = $before
    $coverAfter = $after
    $coverEvents = $events

    $before = Read-State 'uncover_before'
    Assert-SameActivity $before $anchor 'uncover_before'
    $cursor = [long]$before.process.eventLastSequence
    $null = Send-CommandOnce 'uncover' 'uncover_command'
    $after = Wait-State 'uncover_after' $anchor {
        param($s)
        return $s.process.coverState -ceq 'IDLE' -and
            (Has-FreshPaint $s)
    }
    Assert-SameActivity $after $anchor 'uncover_after'
    Assert-Nine $after 'uncover_after' -RequireLivePaint -RequireExactBaseline
    $events = Read-Events 'uncover_events' $cursor $id
    Assert-Events $events @('UNCOVER_REQUEST','COVER_DESTROYED') 'uncover_destroy' @(
        'FINISH_ACTIVE',"generation=$($after.process.coverGeneration)")
    Assert-Events $events @('UNCOVER_REQUEST','ACTIVITY_RESUME') 'uncover_resume' @(
        'FINISH_ACTIVE',"serial=$($after.activitySerial)")
    Assert-SameActivity $after $anchor 'cover_rollback'
    Assert-CoverRestore $coverBefore $after
    Record-Trial 'cover' $coverBefore $coverAfter $after $coverEvents $events
    Record-Trial 'uncover' $coverAfter $after $after $events $events

    # A clean finish/relaunch is the only intentional activity/root switch.
    $before = Read-State 'finish_before'
    Assert-SameActivity $before $anchor 'finish_before'
    $cursor = [long]$before.process.eventLastSequence
    $null = Send-CommandOnce 'finish' 'finish_command'
    $absent = Wait-State 'finish_absent' $id {
        param($s)
        return $s.PSObject.Properties.Name -contains 'activityPresent' -and
            $s.activityPresent -cne $true -and
            $s.process.activityLiveCount -eq 0
    } -AllowAbsent
    $events = Read-Events 'finish_events' $cursor $id
    Assert-Events $events @('FINISH_REQUEST','ACTIVITY_DESTROY',
        'ACTIVITY_RELEASED') 'finish' @('',"serial=$($before.activitySerial)",'')
    $script:Summary.trials += [ordered]@{
        name='finish'; outcome='PASS'; eventNames=@($events | ForEach-Object { $_.name })
    }
    Write-Summary

    $cursor = [long]$absent.process.eventLastSequence
    $launch = Invoke-Adb @('shell','am','start','-n',$script:Component) 'relaunch_once'
    if ($launch -cnotmatch '(?m)^Starting: Intent ' -or
            $launch -cmatch '(?m)^(Error|Warning):') {
        Unknown 'relaunch acceptance is ambiguous; no automatic retry'
    }
    $fresh = Wait-State 'relaunch_after' $id {
        param($s)
        return $s.PSObject.Properties.Name -notcontains 'activityPresent' -and
            $s.lifecycle -ceq 'RESUMED' -and $s.baselineCaptured -and
            $s.liveNineBaselineCandidate
    } -AllowAbsent
    if ($fresh.activitySerial -le $anchor.activitySerial -or
            $fresh.rootIdentityHash -eq $anchor.rootIdentityHash -or
            $fresh.activityIdentityHash -eq $anchor.activityIdentityHash) {
        Fail 'relaunch did not establish a fresh activity/root identity'
    }
    Assert-Nine $fresh 'relaunch_after' -RequireLivePaint -RequireExactBaseline
    if ($fresh.page -ne 1 -or
            $fresh.uri -cne 'probe://disposable-host/source-a' -or
            $fresh.renderEpoch -ne 0 -or $fresh.layoutEpoch -ne 0) {
        Fail 'relaunch did not restore a fresh synthetic scene'
    }
    $events = Read-Events 'relaunch_events' $cursor $id
    Assert-Events $events @('ACTIVITY_ADMITTED','ACTIVITY_CREATE',
        'ACTIVITY_RESUME','BASELINE_CAPTURED') 'relaunch' @(
        "serial=$($fresh.activitySerial) root=$($fresh.rootIdentityHash)",
        "serial=$($fresh.activitySerial)","serial=$($fresh.activitySerial)",
        'nine laid-out originals')
    $script:Summary.trials += [ordered]@{
        name='relaunch_fresh_baseline'; outcome='PASS'
        eventNames=@($events | ForEach-Object { $_.name })
    }
    $script:Summary.outcome = 'PASS'
    $script:Summary.completedUtc = [DateTime]::UtcNow.ToString('o')
    Write-Summary
    Write-Output "PASS: disposable emulator gate; evidence: $script:RunDir"
} catch {
    $reason = $_.Exception.Message
    $script:Summary.outcome = if ($reason -clike 'FAIL:*') { 'FAIL' } else { 'UNKNOWN' }
    $script:Summary.reason = $reason
    $script:Summary.completedUtc = [DateTime]::UtcNow.ToString('o')
    Write-Summary
    throw "${reason}; evidence: $script:RunDir"
} finally {
    $script:RunLock.Dispose()
}
