param(
    [string]$RepositoryRoot = $(
        [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    )
)

$ErrorActionPreference = 'Stop'
$traceScript = Join-Path $RepositoryRoot 'native-spread-module\trace.ps1'
if (-not (Test-Path -LiteralPath $traceScript)) {
    throw "Native Spread trace helper was not found: $traceScript"
}

$testRoot = Join-Path (
    [System.IO.Path]::GetTempPath()
) ('sn-trace-helper-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$fakeAdb = Join-Path $testRoot 'fake-adb.ps1'
$validActiveSession = '20260811-120000-000-p1234-active.pdf'
$validOtherSession = '20260811-120001-000-p1234-other.pdf'
$validLastSession = '20260811-115959-000-p1234-older.pdf'

try {
    @'
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$AdbArguments
)

$global:LASTEXITCODE = 0
[System.IO.File]::AppendAllText(
    $env:SN_TRACE_FAKE_LOG,
    (($AdbArguments -join [char]31) + [Environment]::NewLine)
)

function Read-FakePointerState {
    param([string]$Name)

    if ($Name -eq 'active' -and $env:SN_TRACE_FAKE_ACTIVE_SEQUENCE) {
        $states = @($env:SN_TRACE_FAKE_ACTIVE_SEQUENCE -split [char]30)
        $counterPath = Join-Path $env:SN_TRACE_FAKE_STATE_DIR 'active-count.txt'
        $index = if (Test-Path -LiteralPath $counterPath) {
            [int](Get-Content -LiteralPath $counterPath -Raw)
        } else {
            0
        }
        Set-Content -LiteralPath $counterPath -Value ($index + 1) -NoNewline
        return [string]$states[[Math]::Min($index, $states.Count - 1)]
    }

    $dynamicPath = Join-Path $env:SN_TRACE_FAKE_STATE_DIR ($Name + '.txt')
    if (Test-Path -LiteralPath $dynamicPath) {
        return [string](Get-Content -LiteralPath $dynamicPath -Raw)
    }
    switch ($Name) {
        'publication-failed' { return $env:SN_TRACE_FAKE_PUBLICATION_FAILED }
        'incomplete' { return $env:SN_TRACE_FAKE_INCOMPLETE }
        'active' { return $env:SN_TRACE_FAKE_ACTIVE }
        'last' { return $env:SN_TRACE_FAKE_LAST }
    }
    return '__ABSENT__'
}

if ($AdbArguments.Count -eq 1 -and $AdbArguments[0] -eq 'get-state') {
    if ($env:SN_TRACE_FAKE_TRANSPORT_ERROR -eq 'true') {
        [Console]::Error.WriteLine('simulated adb transport failure')
        $global:LASTEXITCODE = 71
        return
    }
    Write-Output 'device'
    return
}

if (
    $AdbArguments.Count -ge 3 -and
    $AdbArguments[0] -eq 'shell' -and
    $AdbArguments[1] -eq 'am' -and
    $AdbArguments[2] -eq 'broadcast'
) {
    $commandIndex = [Array]::IndexOf($AdbArguments, 'command')
    if ($commandIndex -lt 0 -or $commandIndex + 1 -ge $AdbArguments.Count) {
        [Console]::Error.WriteLine('trace-control broadcast omitted command')
        $global:LASTEXITCODE = 97
        return
    }
    $command = $AdbArguments[$commandIndex + 1]
    if ($command -eq 'start') {
        Set-Content `
            -LiteralPath (Join-Path $env:SN_TRACE_FAKE_STATE_DIR 'active.txt') `
            -Value $env:SN_TRACE_FAKE_START_SESSION `
            -NoNewline
    } elseif ($command -notin @('checkpoint', 'stop')) {
        [Console]::Error.WriteLine("unexpected trace-control command: $command")
        $global:LASTEXITCODE = 97
        return
    }
    Write-Output 'Broadcast completed: result=0'
    return
}

if ($AdbArguments.Count -ge 2 -and $AdbArguments[0] -eq 'shell') {
    $command = $AdbArguments[1]
    if ($command.Contains('__SNTRACE_RECOVERY_PRESENT__')) {
        $recoveryState = Read-FakePointerState -Name 'recovery-lock'
        if ($recoveryState -eq '__ERROR__') {
            [Console]::Error.WriteLine(
                'simulated unreadable abandoned-pointer recovery guard'
            )
            $global:LASTEXITCODE = 73
            return
        }
        if ($recoveryState -eq '__ABSENT__') {
            Write-Output '__SNTRACE_RECOVERY_ABSENT__'
            return
        }
        Write-Output '__SNTRACE_RECOVERY_PRESENT__'
        return
    }
    if ($command.Contains('__SNTRACE_PRESENT__')) {
        foreach ($name in @(
            'publication-failed',
            'incomplete',
            'active',
            'last'
        )) {
            if (-not $command.Contains("/$name.txt")) {
                continue
            }
            $state = Read-FakePointerState -Name $name
            if ($state -eq '__ERROR__') {
                [Console]::Error.WriteLine(
                    "simulated unreadable $name pointer"
                )
                $global:LASTEXITCODE = 72
                return
            }
            if ($state -eq '__NOT_REGULAR__') {
                [Console]::Error.WriteLine(
                    "simulated non-regular $name pointer"
                )
                $global:LASTEXITCODE = 74
                return
            }
            if ($state -eq '__CHANGED__') {
                [Console]::Error.WriteLine(
                    "simulated changing $name pointer"
                )
                $global:LASTEXITCODE = 76
                return
            }
            if ($state -eq '__ABSENT__') {
                Write-Output '__SNTRACE_ABSENT__'
                return
            }
            Write-Output '__SNTRACE_PRESENT__'
            Write-Output $state
            return
        }
    }
    if ($command.Contains('/session.properties')) {
        if ($env:SN_TRACE_FAKE_METADATA -eq '__ERROR__') {
            [Console]::Error.WriteLine('simulated unreadable session metadata')
            $global:LASTEXITCODE = 77
            return
        }
        if ($env:SN_TRACE_FAKE_METADATA -eq '__MALFORMED__') {
            Write-Output 'not-a-pid'
            return
        }
        Write-Output '1234'
        return
    }
    if ($command.Contains('__SNTRACE_PID_LIST__')) {
        if ($env:SN_TRACE_FAKE_PID_STATE -eq '__ERROR__') {
            [Console]::Error.WriteLine('simulated pidof failure')
            $global:LASTEXITCODE = 80
            return
        }
        if ($env:SN_TRACE_FAKE_PID_STATE -eq '__ABSENT__') {
            Write-Output '__SNTRACE_NO_PROCESS__'
            return
        }
        Write-Output '__SNTRACE_PID_LIST__'
        Write-Output '1234'
        return
    }
    if ($command.Contains('__TRACE_ABANDONED_ARCHIVED__')) {
        $partialDirectory =
            "/storage/emulated/0/Download/SupernoteNativeSpreadTrace/" +
            $env:SN_TRACE_FAKE_ACTIVE
        if ($command.Contains($partialDirectory)) {
            [Console]::Error.WriteLine(
                'attempted to delete the abandoned trace partial directory'
            )
            $global:LASTEXITCODE = 83
            return
        }
        $remoteRoot =
            '/storage/emulated/0/Download/SupernoteNativeSpreadTrace'
        $requiredFragments = @(
            "mkdir '$remoteRoot/.active-recovery'",
            "stat -c '%d:%i:%s:%Y' '$remoteRoot/active.txt'",
            "mv '$remoteRoot/active.txt' " +
                "'$remoteRoot/.active-recovery/active.txt'",
            "mv '$remoteRoot/.active-recovery' " +
                "'$remoteRoot/.abandoned-$env:SN_TRACE_FAKE_ACTIVE'"
        )
        foreach ($fragment in $requiredFragments) {
            if (-not $command.Contains($fragment)) {
                [Console]::Error.WriteLine(
                    "abandoned-pointer protocol omitted: $fragment"
                )
                $global:LASTEXITCODE = 97
                return
            }
        }
        if ($command.Contains("stat -c '%d:%i:%s:%Y:%Z'")) {
            [Console]::Error.WriteLine(
                'abandoned-pointer identity incorrectly includes rename-changing ctime'
            )
            $global:LASTEXITCODE = 97
            return
        }
        if ($env:SN_TRACE_FAKE_RECOVERY_RESULT -eq '__FAIL__') {
            [Console]::Error.WriteLine('simulated abandoned-pointer recovery failure')
            $global:LASTEXITCODE = 82
            return
        }
        if ($env:SN_TRACE_FAKE_RECOVERY_RESULT -eq '__REPLACED__') {
            Set-Content `
                -LiteralPath (
                    Join-Path $env:SN_TRACE_FAKE_STATE_DIR 'active.txt'
                ) `
                -Value '__ABSENT__' `
                -NoNewline
            Set-Content `
                -LiteralPath (
                    Join-Path $env:SN_TRACE_FAKE_STATE_DIR 'recovery-lock.txt'
                ) `
                -Value $env:SN_TRACE_FAKE_REPLACEMENT `
                -NoNewline
            Write-Output '__TRACE_POINTER_REPLACEMENT_RETAINED__'
            return
        }
        Set-Content `
            -LiteralPath (Join-Path $env:SN_TRACE_FAKE_STATE_DIR 'active.txt') `
            -Value '__ABSENT__' `
            -NoNewline
        Write-Output '__TRACE_ABANDONED_ARCHIVED__'
        return
    }
    [Console]::Error.WriteLine("unexpected fake adb shell command: $command")
    $global:LASTEXITCODE = 98
    return
}
[Console]::Error.WriteLine(
    'unexpected fake adb arguments: ' + ($AdbArguments -join ' ')
)
$global:LASTEXITCODE = 99
'@ | Set-Content -LiteralPath $fakeAdb -Encoding utf8

    $powershell = (Get-Process -Id $PID).Path
    $failures = [System.Collections.Generic.List[string]]::new()

    $tokens = $null
    $parseErrors = $null
    $traceAst = [System.Management.Automation.Language.Parser]::ParseFile(
        $traceScript,
        [ref]$tokens,
        [ref]$parseErrors
    )
    if ($parseErrors.Count -ne 0) {
        throw 'trace.ps1 did not parse while importing Write-TraceSummary'
    }
    $summaryDefinition = $traceAst.Find(
        {
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -eq 'Write-TraceSummary'
        },
        $true
    )
    if ($null -eq $summaryDefinition) {
        throw 'Write-TraceSummary was not found in trace.ps1'
    }
    Invoke-Expression $summaryDefinition.Extent.Text

    $malformedSummary = Join-Path $testRoot 'summary-malformed'
    New-Item -ItemType Directory -Path $malformedSummary | Out-Null
    @('{"event":"pen_contact_started"}', '{not-json') |
        Set-Content -LiteralPath (Join-Path $malformedSummary 'events.jsonl')
    try {
        Write-TraceSummary -SessionDirectory $malformedSummary
        $failures.Add('malformed JSON summary unexpectedly succeeded')
    } catch {
        if (-not $_.Exception.Message.Contains('malformed JSON event')) {
            $failures.Add('malformed JSON summary reported the wrong failure')
        }
    }
    if (Test-Path -LiteralPath (Join-Path $malformedSummary 'summary.md')) {
        $failures.Add('malformed JSON summary published summary.md')
    }

    $emptySummary = Join-Path $testRoot 'summary-empty'
    New-Item -ItemType Directory -Path $emptySummary | Out-Null
    Set-Content -LiteralPath (Join-Path $emptySummary 'events.jsonl') -Value ''
    try {
        Write-TraceSummary -SessionDirectory $emptySummary
        $failures.Add('empty JSON summary unexpectedly succeeded')
    } catch {
        if (-not $_.Exception.Message.Contains('contains no JSON events')) {
            $failures.Add('empty JSON summary reported the wrong failure')
        }
    }

    $validSummary = Join-Path $testRoot 'summary-valid'
    New-Item -ItemType Directory -Path $validSummary | Out-Null
    '{"event":"pen_contact_started","seq":1}' |
        Set-Content -LiteralPath (Join-Path $validSummary 'events.jsonl')
    Write-TraceSummary -SessionDirectory $validSummary
    $validSummaryPath = Join-Path $validSummary 'summary.md'
    if (
        -not (Test-Path -LiteralPath $validSummaryPath -PathType Leaf) -or
        -not (Get-Content -LiteralPath $validSummaryPath -Raw).Contains('- Events: 1')
    ) {
        $failures.Add('valid JSON summary control did not publish its summary')
    }

    function Invoke-FailClosedScenario {
        param(
            [Parameter(Mandatory = $true)][string]$Name,
            [Parameter(Mandatory = $true)]
            [ValidateSet('Start', 'Checkpoint', 'Stop', 'Status')]
            [string]$Action,
            [string]$Active = '__ABSENT__',
            [string]$Incomplete = '__ABSENT__',
            [string]$PublicationFailed = '__ABSENT__',
            [string]$Last = '__ABSENT__',
            [string]$RecoveryLock = '__ABSENT__',
            [string[]]$ActiveSequence = @(),
            [string]$ExpectedState,
            [string]$ExpectedStateAfter,
            [string]$ExpectedRecoveryLockAfter,
            [bool]$ExpectExpectedStateAbsent = $false,
            [bool]$ExpectSuccess = $false,
            [string]$ExpectedMessage,
            [bool]$TransportError = $false,
            [string]$Metadata = '__VALID__',
            [string]$PidState = '__LIVE__',
            [string]$RecoveryResult = '__SUCCESS__',
            [bool]$AllowLastRead = $false,
            [bool]$AllowRemoteMutation = $false,
            [bool]$AllowTraceControl = $false
        )

        $log = Join-Path $testRoot ($Name + '.calls')
        $destination = Join-Path $testRoot ($Name + '-bundles')
        $stateDirectory = Join-Path $testRoot ($Name + '-state')
        New-Item -ItemType Directory -Path $stateDirectory | Out-Null
        if ($ExpectedState) {
            New-Item -ItemType Directory -Path $destination | Out-Null
            Set-Content `
                -LiteralPath (Join-Path $destination '.native-spread-expected-session.txt') `
                -Value $ExpectedState `
                -Encoding ascii
        }
        $env:SN_TRACE_FAKE_LOG = $log
        $env:SN_TRACE_FAKE_STATE_DIR = $stateDirectory
        $env:SN_TRACE_FAKE_ACTIVE = $Active
        $env:SN_TRACE_FAKE_ACTIVE_SEQUENCE = if ($ActiveSequence.Count -gt 0) {
            $ActiveSequence -join [char]30
        } else {
            ''
        }
        $env:SN_TRACE_FAKE_START_SESSION = $validActiveSession
        $env:SN_TRACE_FAKE_INCOMPLETE = $Incomplete
        $env:SN_TRACE_FAKE_PUBLICATION_FAILED = $PublicationFailed
        $env:SN_TRACE_FAKE_LAST = $Last
        if ($RecoveryLock -ne '__ABSENT__') {
            Set-Content `
                -LiteralPath (Join-Path $stateDirectory 'recovery-lock.txt') `
                -Value $RecoveryLock `
                -NoNewline
        }
        $env:SN_TRACE_FAKE_TRANSPORT_ERROR = $TransportError.ToString().ToLowerInvariant()
        $env:SN_TRACE_FAKE_METADATA = $Metadata
        $env:SN_TRACE_FAKE_PID_STATE = $PidState
        $env:SN_TRACE_FAKE_RECOVERY_RESULT = $RecoveryResult
        $env:SN_TRACE_FAKE_REPLACEMENT = $validOtherSession

        $previousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $scenarioOutput = (& $powershell `
                -NoProfile `
                -ExecutionPolicy Bypass `
                -File $traceScript `
                -Action $Action `
                -Adb $fakeAdb `
                -NoPing `
                -Destination $destination 2>&1 | Out-String)
            $exitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        if ($ExpectSuccess -and $exitCode -ne 0) {
            $failures.Add("$Name unexpectedly failed with $exitCode")
        }
        if (-not $ExpectSuccess -and $exitCode -eq 0) {
            $failures.Add("$Name unexpectedly succeeded")
        }
        if ($ExpectedMessage -and -not $scenarioOutput.Contains($ExpectedMessage)) {
            $failures.Add(
                "$Name did not report expected message: $ExpectedMessage"
            )
        }
        $expectedStatePath = Join-Path `
            $destination `
            '.native-spread-expected-session.txt'
        if ($ExpectExpectedStateAbsent) {
            if (Test-Path -LiteralPath $expectedStatePath) {
                $failures.Add(
                    "$Name retained expected-session state after exact recovery"
                )
            }
        } elseif ($ExpectedStateAfter) {
            $actualExpectedState = if (Test-Path -LiteralPath $expectedStatePath) {
                [string](Get-Content -LiteralPath $expectedStatePath -Raw).Trim()
            } else {
                $null
            }
            if ($actualExpectedState -ne $ExpectedStateAfter) {
                $failures.Add(
                    "$Name expected-session state was '$actualExpectedState', " +
                    "expected '$ExpectedStateAfter'"
                )
            }
        }
        if ($ExpectedRecoveryLockAfter) {
            $recoveryStatePath = Join-Path `
                $stateDirectory `
                'recovery-lock.txt'
            $actualRecoveryState = if (
                Test-Path -LiteralPath $recoveryStatePath
            ) {
                [string](
                    Get-Content -LiteralPath $recoveryStatePath -Raw
                ).Trim()
            } else {
                $null
            }
            if ($actualRecoveryState -ne $ExpectedRecoveryLockAfter) {
                $failures.Add(
                    "$Name recovery guard was '$actualRecoveryState', " +
                    "expected '$ExpectedRecoveryLockAfter'"
                )
            }
        }

        $calls = if (Test-Path -LiteralPath $log) {
            Get-Content -LiteralPath $log -Raw
        } else {
            ''
        }
        $separator = [string][char]31
        $forbiddenCalls = @(
            ('pull' + $separator),
            ('am' + $separator + 'broadcast'),
            'rm -f',
            'rmdir ',
            'mkdir ',
            'screencap ',
            'mv '
        )
        if ($AllowRemoteMutation) {
            $forbiddenCalls = @(
                $forbiddenCalls | Where-Object {
                    $_ -notin @('rm -f', 'rmdir ', 'mkdir ', 'mv ')
                }
            )
        }
        if ($AllowTraceControl) {
            $forbiddenCalls = @(
                $forbiddenCalls | Where-Object {
                    $_ -ne ('am' + $separator + 'broadcast')
                }
            )
        }
        if (-not $AllowLastRead) {
            $forbiddenCalls += '/last.txt'
        }
        foreach ($forbidden in $forbiddenCalls) {
            if ($calls.Contains($forbidden)) {
                $failures.Add(
                    "$Name reached forbidden fallback/mutation: $forbidden"
                )
            }
        }
        if (-not $ExpectSuccess -and (Test-Path -LiteralPath $destination)) {
            $localArtifacts = @(
                Get-ChildItem -LiteralPath $destination -Force |
                    Where-Object {
                        -not (
                            $ExpectedState -and
                            $_.Name -eq '.native-spread-expected-session.txt'
                        )
                    }
            )
            if ($localArtifacts.Count -ne 0) {
                $failures.Add(
                    "$Name left local artifacts after a failed action"
                )
            }
        }
    }

    Invoke-FailClosedScenario `
        -Name 'clean-status-control' `
        -Action Status `
        -ExpectSuccess $true `
        -AllowLastRead $true `
        -ExpectedMessage 'No Native Spread annotation trace has been recorded.'
    Invoke-FailClosedScenario `
        -Name 'live-status-control' `
        -Action Status `
        -Active $validActiveSession `
        -ExpectSuccess $true `
        -ExpectedMessage "Recording: $validActiveSession"
    Invoke-FailClosedScenario `
        -Name 'start-success-control' `
        -Action Start `
        -ExpectSuccess $true `
        -ExpectedMessage "Recording Native Spread annotation trace: $validActiveSession" `
        -ExpectedStateAfter $validActiveSession `
        -AllowTraceControl $true

    Invoke-FailClosedScenario `
        -Name 'active-pointer-changed-checkpoint' `
        -Action Checkpoint `
        -ExpectedState $validActiveSession `
        -ExpectedStateAfter $validActiveSession `
        -ActiveSequence @(
            $validActiveSession,
            $validActiveSession,
            $validOtherSession
        ) `
        -ExpectedMessage 'The active trace changed while its failure guards were checked.'
    Invoke-FailClosedScenario `
        -Name 'unstable-active-pointer-status' `
        -Action Status `
        -Active '__CHANGED__' `
        -ExpectedMessage 'simulated changing active pointer'
    Invoke-FailClosedScenario `
        -Name 'stale-last-stop' `
        -Action Stop `
        -ExpectedState $validActiveSession `
        -ExpectedStateAfter $validActiveSession `
        -Last $validLastSession `
        -AllowLastRead $true `
        -ExpectedMessage 'Refusing stale last.txt fallback.'
    Invoke-FailClosedScenario `
        -Name 'abandoned-pointer-recovery-failure-stop' `
        -Action Stop `
        -Active $validActiveSession `
        -ExpectedState $validActiveSession `
        -ExpectedStateAfter $validActiveSession `
        -PidState '__ABSENT__' `
        -RecoveryResult '__FAIL__' `
        -AllowRemoteMutation $true `
        -ExpectedMessage 'simulated abandoned-pointer recovery failure'
    Invoke-FailClosedScenario `
        -Name 'abandoned-pointer-replaced-during-claim-stop' `
        -Action Stop `
        -Active $validActiveSession `
        -ExpectedState $validActiveSession `
        -ExpectedStateAfter $validActiveSession `
        -ExpectedRecoveryLockAfter $validOtherSession `
        -PidState '__ABSENT__' `
        -RecoveryResult '__REPLACED__' `
        -AllowRemoteMutation $true `
        -ExpectedMessage 'replacement was retained inside the recovery guard'
    Invoke-FailClosedScenario `
        -Name 'abandoned-pointer-recovery-clears-matching-expected-stop' `
        -Action Stop `
        -Active $validActiveSession `
        -ExpectedState $validActiveSession `
        -ExpectExpectedStateAbsent $true `
        -PidState '__ABSENT__' `
        -AllowRemoteMutation $true `
        -ExpectedMessage 'partial directory remains'
    Invoke-FailClosedScenario `
        -Name 'abandoned-pointer-android-rename-ctime-change-stop' `
        -Action Stop `
        -Active $validActiveSession `
        -ExpectedState $validActiveSession `
        -ExpectExpectedStateAbsent $true `
        -PidState '__ABSENT__' `
        -RecoveryResult '__CTIME_CHANGED_BY_RENAME__' `
        -AllowRemoteMutation $true `
        -ExpectedMessage 'partial directory remains'
    Invoke-FailClosedScenario `
        -Name 'abandoned-pointer-recovery-retains-mismatched-expected-stop' `
        -Action Stop `
        -Active $validActiveSession `
        -ExpectedState $validOtherSession `
        -ExpectedStateAfter $validOtherSession `
        -PidState '__ABSENT__' `
        -AllowRemoteMutation $true `
        -ExpectedMessage 'Retained expected-session state'

    foreach ($action in @('Start', 'Checkpoint', 'Stop')) {
        Invoke-FailClosedScenario `
            -Name "retained-recovery-guard-$action" `
            -Action $action `
            -RecoveryLock $validOtherSession `
            -ExpectedMessage 'recovery remains unresolved'
    }
    Invoke-FailClosedScenario `
        -Name 'retained-recovery-guard-Status' `
        -Action Status `
        -RecoveryLock $validOtherSession `
        -ExpectSuccess $true `
        -ExpectedMessage 'An abandoned-pointer recovery remains guarded'

    foreach ($action in @('Start', 'Checkpoint', 'Stop', 'Status')) {
        Invoke-FailClosedScenario `
            -Name "malformed-active-$action" `
            -Action $action `
            -Active '../malformed'
        Invoke-FailClosedScenario `
            -Name "malformed-incomplete-$action" `
            -Action $action `
            -Incomplete '../malformed'
        Invoke-FailClosedScenario `
            -Name "malformed-publication-$action" `
            -Action $action `
            -PublicationFailed '../malformed'
    }

    foreach ($action in @('Start', 'Checkpoint', 'Stop', 'Status')) {
        Invoke-FailClosedScenario `
            -Name "space-padded-active-$action" `
            -Action $action `
            -Active ' active-session '
    }
    foreach ($action in @('Stop', 'Status')) {
        Invoke-FailClosedScenario `
            -Name "multiline-last-$action" `
            -Action $action `
            -Last "$validLastSession`n`n" `
            -AllowLastRead $true
    }

    Invoke-FailClosedScenario `
        -Name 'valid-incomplete-start' `
        -Action Start `
        -Incomplete $validOtherSession `
        -ExpectedMessage 'remains unresolved'
    Invoke-FailClosedScenario `
        -Name 'unreadable-publication-start' `
        -Action Start `
        -PublicationFailed '__ERROR__'
    Invoke-FailClosedScenario `
        -Name 'nonregular-active-status' `
        -Action Status `
        -Active '__NOT_REGULAR__'
    Invoke-FailClosedScenario `
        -Name 'unreadable-session-metadata-stop' `
        -Action Stop `
        -Active $validActiveSession `
        -Metadata '__ERROR__'
    Invoke-FailClosedScenario `
        -Name 'malformed-session-metadata-stop' `
        -Action Stop `
        -Active $validActiveSession `
        -Metadata '__MALFORMED__'
    Invoke-FailClosedScenario `
        -Name 'pidof-failure-stop' `
        -Action Stop `
        -Active $validActiveSession `
        -PidState '__ERROR__'
    Invoke-FailClosedScenario `
        -Name 'transport-failure-start' `
        -Action Start `
        -TransportError $true

    if ($failures.Count -gt 0) {
        throw (
            "Native Spread trace helper fail-closed tests failed:`n- " +
            ($failures -join "`n- ")
        )
    }
    Write-Host 'Native Spread trace helper fail-closed tests: PASS'
} finally {
    Remove-Item Env:SN_TRACE_FAKE_LOG -ErrorAction SilentlyContinue
    Remove-Item Env:SN_TRACE_FAKE_STATE_DIR -ErrorAction SilentlyContinue
    Remove-Item Env:SN_TRACE_FAKE_ACTIVE -ErrorAction SilentlyContinue
    Remove-Item Env:SN_TRACE_FAKE_ACTIVE_SEQUENCE -ErrorAction SilentlyContinue
    Remove-Item Env:SN_TRACE_FAKE_START_SESSION -ErrorAction SilentlyContinue
    Remove-Item Env:SN_TRACE_FAKE_INCOMPLETE -ErrorAction SilentlyContinue
    Remove-Item Env:SN_TRACE_FAKE_PUBLICATION_FAILED -ErrorAction SilentlyContinue
    Remove-Item Env:SN_TRACE_FAKE_LAST -ErrorAction SilentlyContinue
    Remove-Item Env:SN_TRACE_FAKE_TRANSPORT_ERROR -ErrorAction SilentlyContinue
    Remove-Item Env:SN_TRACE_FAKE_METADATA -ErrorAction SilentlyContinue
    Remove-Item Env:SN_TRACE_FAKE_PID_STATE -ErrorAction SilentlyContinue
    Remove-Item Env:SN_TRACE_FAKE_RECOVERY_RESULT -ErrorAction SilentlyContinue
    Remove-Item Env:SN_TRACE_FAKE_REPLACEMENT -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
