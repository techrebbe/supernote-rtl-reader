param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Start', 'Checkpoint', 'Stop', 'Status')]
    [string]$Action,

    [string]$Label = 'manual',

    [string]$Adb = 'adb',

    [string]$Serial,

    [string]$Destination,

    [string]$ExpectedSession,

    [switch]$NoPing
)

$ErrorActionPreference = 'Stop'

if (-not $Destination) {
    $downloads = Join-Path (
        [Environment]::GetFolderPath('UserProfile')
    ) 'Downloads'
    if (Test-Path -LiteralPath $downloads) {
        $Destination = Join-Path $downloads 'SupernoteNativeSpreadTraceBundles'
    } else {
        $Destination = Join-Path $PSScriptRoot 'trace-bundles'
    }
}

if (-not $Serial -and $env:ANDROID_SERIAL) {
    $Serial = $env:ANDROID_SERIAL
}

$traceAction = 'com.techrebbe.supernote.spreadprobe.TRACE_CONTROL'
$documentPackage = 'com.supernote.document'
$remoteRoot = '/storage/emulated/0/Download/SupernoteNativeSpreadTrace'
$recoveredAbandonedTraceSession = $null
$abandonedRecoveryPending = $false
$incompleteTraceSession = $null
$publicationFailedTraceSession = $null
$traceSessionPattern =
    '^[0-9]{8}-[0-9]{6}-[0-9]{3}-p[1-9][0-9]{0,9}-[A-Za-z0-9._-]{1,72}$'
$expectedSessionStatePath = Join-Path `
    $Destination `
    '.native-spread-expected-session.txt'

if ($Adb -eq 'adb' -and -not (Get-Command adb -ErrorAction SilentlyContinue)) {
    $sdkAdb = Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe'
    if (Test-Path -LiteralPath $sdkAdb) {
        $Adb = $sdkAdb
    }
}

function Invoke-Adb {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)

    $adbArguments = @()
    if ($Serial) {
        $adbArguments += @('-s', $Serial)
    }
    $adbArguments += $Arguments

    $stderrFile = [IO.Path]::GetTempFileName()
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = @(& $Adb @adbArguments 2> $stderrFile)
        $exitCode = $LASTEXITCODE
        $stderrOutput = @(
            Get-Content -LiteralPath $stderrFile -ErrorAction SilentlyContinue
        )
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
        Remove-Item -LiteralPath $stderrFile -Force -ErrorAction SilentlyContinue
    }
    $normalizedOutput = @(
        foreach ($item in $output) {
            if ($item -is [System.Management.Automation.ErrorRecord]) {
                $item.Exception.Message
            } else {
                [string]$item
            }
        }
    )
    $combinedOutput = @($normalizedOutput) + @($stderrOutput)
    if ($exitCode -ne 0) {
        throw "adb failed ($exitCode): $($combinedOutput -join [Environment]::NewLine)"
    }
    # adb reports successful pull progress on stderr. Preserve it for failures,
    # but do not replay it as a PowerShell NativeCommandError on a successful
    # trace collection.
    return $normalizedOutput
}

function Assert-DeviceConnected {
    $state = (Invoke-Adb get-state | Out-String).Trim()
    if ($state -ne 'device') {
        throw "Expected one authorized adb device, got: $state"
    }
}

function Send-TraceControl {
    param([string]$Command, [string]$CheckpointLabel)

    $arguments = @(
        'shell', 'am', 'broadcast',
        '-a', $traceAction,
        '-p', $documentPackage,
        '--es', 'command', $Command
    )
    if ($CheckpointLabel) {
        $arguments += @('--es', 'label', $CheckpointLabel)
    }
    Invoke-Adb @arguments | Out-Host
}

function Read-RemotePointer {
    param(
        [ValidateSet(
            'active',
            'last',
            'incomplete',
            'publication-failed'
        )]
        [string]$Name
    )

    $pointer = "$remoteRoot/$Name.txt"
    $result = @(
        Invoke-Adb shell (
            "if [ ! -e '$pointer' ]; then " +
            "printf '%s\n' '__SNTRACE_ABSENT__'; " +
            "elif [ -L '$pointer' ] || [ ! -f '$pointer' ]; then " +
            "printf '%s\n' '__SNTRACE_NOT_REGULAR__' >&2; exit 74; " +
            "else LC_ALL=C; export LC_ALL; " +
            "pointer_snapshot_before=`$(stat -c '%i:%s:%Y' '$pointer') " +
            "|| exit 75; " +
            "pointer_value=`$(cat '$pointer') || exit 75; " +
            "pointer_snapshot_after=`$(stat -c '%i:%s:%Y' '$pointer') " +
            "|| exit 75; " +
            "if [ `"`$pointer_snapshot_before`" != " +
            "`"`$pointer_snapshot_after`" ]; then " +
            "printf '%s\n' '__SNTRACE_CHANGED__' >&2; exit 76; fi; " +
            "case `"`$pointer_value`" in " +
            "''|*[!A-Za-z0-9._-]*) " +
            "printf '%s\n' '__SNTRACE_MALFORMED__' >&2; exit 76;; " +
            "esac; " +
            "pointer_size=`$(printf '%s\n' `"`$pointer_snapshot_after`" | " +
            "sed -n 's/^[^:]*:\([^:]*\):.*$/\1/p') || exit 75; " +
            "expected_size=`$((`${#pointer_value} + 1)); " +
            "if [ `"`$pointer_size`" -ne `"`$expected_size`" ]; then " +
            "printf '%s\n' '__SNTRACE_MALFORMED__' >&2; exit 76; fi; " +
            "printf '%s\n' '__SNTRACE_PRESENT__'; " +
            "printf '%s\n' `"`$pointer_value`"; fi"
        )
    )
    if ($result.Count -lt 1) {
        throw "No status was returned while reading trace pointer: $pointer"
    }
    $status = ([string]$result[0]).Trim()
    if ($status -eq '__SNTRACE_ABSENT__') {
        if ($result.Count -ne 1) {
            throw "Ambiguous absent trace pointer response: $pointer"
        }
        return $null
    }
    if ($status -ne '__SNTRACE_PRESENT__') {
        throw "Invalid status while reading trace pointer '$pointer': $status"
    }
    if ($result.Count -ne 2) {
        throw "Malformed trace pointer response: $pointer"
    }
    $value = [string]$result[1]
    if (
        $value -notmatch $traceSessionPattern -or
        $value.IndexOfAny([char[]]@("`r", "`n")) -ge 0
    ) {
        throw "Malformed trace pointer content was retained: $pointer"
    }
    return $value
}

function Read-PublicationFailedTraceState {
    $script:publicationFailedTraceSession = $null
    $session = Read-RemotePointer -Name publication-failed
    if ($null -eq $session) {
        return
    }
    if ($session -match $traceSessionPattern) {
        $script:publicationFailedTraceSession = $session
    } else {
        $script:publicationFailedTraceSession =
            '[invalid publication-failed pointer]'
        Write-Warning (
            'Retained an invalid trace publication-failure pointer. ' +
            'Explicit operator recovery is required.'
        )
    }
}

function Read-IncompleteTraceState {
    $script:incompleteTraceSession = $null
    $session = Read-RemotePointer -Name incomplete
    if ($null -eq $session) {
        return
    }
    if ($session -match $traceSessionPattern) {
        $script:incompleteTraceSession = $session
    } else {
        $script:incompleteTraceSession = '[invalid incomplete pointer]'
        Write-Warning (
            'Retained an invalid Native Spread incomplete pointer. ' +
            'Explicit operator recovery is required.'
        )
    }
}

function Read-AbandonedRecoveryState {
    $script:abandonedRecoveryPending = $false
    $recoveryLock = "$remoteRoot/.active-recovery"
    $result = @(
        Invoke-Adb shell (
            "if [ ! -e '$recoveryLock' ]; then " +
            "printf '%s\n' '__SNTRACE_RECOVERY_ABSENT__'; " +
            "elif [ -L '$recoveryLock' ] || " +
            "[ ! -d '$recoveryLock' ]; then " +
            "printf '%s\n' '__SNTRACE_RECOVERY_NOT_DIRECTORY__' >&2; " +
            "exit 73; else " +
            "printf '%s\n' '__SNTRACE_RECOVERY_PRESENT__'; fi"
        )
    )
    if ($result.Count -ne 1) {
        throw 'Ambiguous abandoned-pointer recovery state.'
    }
    $status = ([string]$result[0]).Trim()
    if ($status -eq '__SNTRACE_RECOVERY_ABSENT__') {
        return
    }
    if ($status -ne '__SNTRACE_RECOVERY_PRESENT__') {
        throw "Invalid abandoned-pointer recovery state: $status"
    }
    $script:abandonedRecoveryPending = $true
}

function Assert-NoUnresolvedTraceFailure {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Start', 'Checkpoint', 'Stop', 'Status')]
        [string]$CurrentAction
    )

    if ($CurrentAction -eq 'Status') {
        return
    }
    if ($script:abandonedRecoveryPending) {
        throw (
            'An abandoned-pointer recovery remains unresolved. The atomic ' +
            'recovery guard was retained; explicit operator recovery is ' +
            "required before $CurrentAction."
        )
    }
    if ($script:publicationFailedTraceSession) {
        throw (
            'Native Spread trace publication remains unresolved: ' +
            $script:publicationFailedTraceSession + '. The guard was retained; ' +
            'explicit operator recovery is required before ' + $CurrentAction + '.'
        )
    }
    if ($script:incompleteTraceSession) {
        throw (
            'An incomplete Native Spread trace remains unresolved: ' +
            $script:incompleteTraceSession + '. The guard was retained; ' +
            'explicit operator recovery is required before ' + $CurrentAction + '.'
        )
    }
}

function Assert-ValidTraceSession {
    param(
        [AllowNull()][AllowEmptyString()][string]$Session,
        [Parameter(Mandatory = $true)][string]$PointerName
    )

    if ($null -eq $Session) {
        throw "Trace pointer '$PointerName' is absent."
    }
    if ($Session -notmatch $traceSessionPattern) {
        throw (
            "Trace pointer '$PointerName' is malformed and was retained. " +
            'Explicit operator recovery is required.'
        )
    }
}

function Read-LocalExpectedTraceSession {
    if (-not (Test-Path -LiteralPath $expectedSessionStatePath)) {
        return $null
    }
    $item = Get-Item -LiteralPath $expectedSessionStatePath -Force
    if ($item.PSIsContainer -or $item.Attributes.HasFlag(
            [IO.FileAttributes]::ReparsePoint
        )) {
        throw (
            'Expected-session state is not a regular local file: ' +
            $expectedSessionStatePath
        )
    }
    $lines = @(Get-Content -LiteralPath $expectedSessionStatePath)
    if ($lines.Count -ne 1) {
        throw "Expected-session state is malformed: $expectedSessionStatePath"
    }
    $session = [string]$lines[0]
    Assert-ValidTraceSession `
        -Session $session `
        -PointerName expected-session
    return $session
}

function Read-ExpectedTraceSession {
    if ($ExpectedSession) {
        Assert-ValidTraceSession `
            -Session $ExpectedSession `
            -PointerName expected-session
        return $ExpectedSession
    }
    return Read-LocalExpectedTraceSession
}

function Publish-ExpectedTraceSession {
    param([Parameter(Mandatory = $true)][string]$Session)

    Assert-ValidTraceSession -Session $Session -PointerName active
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    if (Test-Path -LiteralPath $expectedSessionStatePath) {
        throw (
            'Refusing to replace unresolved expected-session state: ' +
            $expectedSessionStatePath
        )
    }
    $temporaryState = $expectedSessionStatePath + '.partial-' +
        [Guid]::NewGuid().ToString('N')
    try {
        Set-Content `
            -LiteralPath $temporaryState `
            -Value $Session `
            -Encoding ascii
        Move-Item `
            -LiteralPath $temporaryState `
            -Destination $expectedSessionStatePath
        $published = Read-ExpectedTraceSession
        if ($published -ne $Session) {
            throw 'Expected-session state failed post-publication validation.'
        }
    } finally {
        if (Test-Path -LiteralPath $temporaryState) {
            Remove-Item -LiteralPath $temporaryState -Force
        }
    }
}

function Clear-ExpectedTraceSession {
    param([Parameter(Mandatory = $true)][string]$Session)

    $published = Read-LocalExpectedTraceSession
    if ($published -ne $Session) {
        throw (
            "Expected-session state changed to '$published'; " +
            "expected '$Session'."
        )
    }
    Remove-Item -LiteralPath $expectedSessionStatePath -Force
    if (Test-Path -LiteralPath $expectedSessionStatePath) {
        throw "Could not clear expected-session state for '$Session'."
    }
}

function Clear-MatchingLocalExpectedTraceSession {
    param([Parameter(Mandatory = $true)][string]$Session)

    $published = Read-LocalExpectedTraceSession
    if ($null -eq $published) {
        return
    }
    if ($published -ne $Session) {
        Write-Warning (
            "Retained expected-session state '$published' because it does " +
            "not match recovered abandoned session '$Session'."
        )
        return
    }
    Clear-ExpectedTraceSession -Session $Session
}

function Read-TraceOwnerProcessId {
    param([Parameter(Mandatory = $true)][string]$Session)

    Assert-ValidTraceSession -Session $Session -PointerName active
    $properties = "$remoteRoot/$Session/session.properties"
    $result = @(
        Invoke-Adb shell (
            "if [ ! -e '$properties' ]; then " +
            "printf '%s\n' '__SNTRACE_METADATA_ABSENT__' >&2; exit 77; " +
            "elif [ ! -f '$properties' ]; then " +
            "printf '%s\n' '__SNTRACE_METADATA_NOT_REGULAR__' >&2; exit 78; " +
            "else process_key_count=`$(grep -c '^processId=' " +
            "'$properties'); grep_status=`$?; " +
            "if [ `"`$grep_status`" -gt 1 ] " +
            "|| [ `"`$process_key_count`" -ne 1 ]; then exit 79; fi; " +
            "sed -n 's/^processId=\([1-9][0-9]*\)$/\1/p' " +
            "'$properties' || exit 79; fi"
        )
    )
    if ($result.Count -ne 1) {
        throw (
            "Trace '$Session' has ambiguous process metadata; active.txt " +
            'was retained.'
        )
    }
    $processId = [string]$result[0]
    if ($processId -notmatch '^[1-9][0-9]*$') {
        throw (
            "Trace '$Session' has invalid process metadata; active.txt " +
            'was retained.'
        )
    }
    return $processId
}

function Read-DocumentProcessIds {
    $result = @(
        Invoke-Adb shell (
            "pid_output=`$(pidof '$documentPackage' 2>&1); " +
            "pid_status=`$?; " +
            "if [ `"`$pid_status`" -eq 0 ]; then " +
            "printf '%s\n' '__SNTRACE_PID_LIST__'; " +
            "printf '%s\n' `"`$pid_output`"; " +
            "elif [ `"`$pid_status`" -eq 1 ] " +
            "&& [ -z `"`$pid_output`" ]; then " +
            "printf '%s\n' '__SNTRACE_NO_PROCESS__'; " +
            "else printf '%s\n' `"`$pid_output`" >&2; exit 80; fi"
        )
    )
    if (
        $result.Count -eq 1 -and
        ([string]$result[0]).Trim() -eq '__SNTRACE_NO_PROCESS__'
    ) {
        return @()
    }
    if (
        $result.Count -ne 2 -or
        ([string]$result[0]).Trim() -ne '__SNTRACE_PID_LIST__'
    ) {
        throw 'Could not determine the Supernote document process state.'
    }
    $pids = @(
        ([string]$result[1]) -split ' ' |
            Where-Object { $_ -ne '' }
    )
    if ($pids.Count -eq 0 -or @(
        $pids | Where-Object { $_ -notmatch '^[1-9][0-9]*$' }
    ).Count -ne 0) {
        throw 'Supernote document process IDs were malformed.'
    }
    return $pids
}

function Assert-TraceFailureGuardsClear {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Start', 'Checkpoint', 'Stop')]
        [string]$CurrentAction
    )

    Read-AbandonedRecoveryState
    Read-PublicationFailedTraceState
    Read-IncompleteTraceState
    Assert-NoUnresolvedTraceFailure -CurrentAction $CurrentAction
}

function Read-GuardedActiveTraceSession {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Start', 'Checkpoint', 'Stop')]
        [string]$CurrentAction,
        [string]$ExpectedSession
    )

    Assert-TraceFailureGuardsClear -CurrentAction $CurrentAction
    $first = Read-RemotePointer -Name active
    Assert-ValidTraceSession -Session $first -PointerName active
    Assert-TraceFailureGuardsClear -CurrentAction $CurrentAction
    $second = Read-RemotePointer -Name active
    Assert-ValidTraceSession -Session $second -PointerName active
    if ($first -ne $second) {
        throw 'The active trace changed while its failure guards were checked.'
    }
    if ($ExpectedSession -and $second -ne $ExpectedSession) {
        throw (
            "Active trace changed to '$second'; expected '$ExpectedSession'."
        )
    }
    return $second
}

function Assert-CompletedTraceStillPullable {
    param([Parameter(Mandatory = $true)][string]$Session)

    Assert-ValidTraceSession -Session $Session -PointerName last
    Assert-TraceFailureGuardsClear -CurrentAction Stop
    $active = Read-RemotePointer -Name active
    if ($null -ne $active) {
        Assert-ValidTraceSession -Session $active -PointerName active
        throw (
            "Trace '$active' became active before '$Session' could be pulled."
        )
    }
    $last = Read-RemotePointer -Name last
    Assert-ValidTraceSession -Session $last -PointerName last
    if ($last -ne $Session) {
        throw "Completed trace changed to '$last'; expected '$Session'."
    }
    Assert-TraceFailureGuardsClear -CurrentAction Stop
    $confirmedActive = Read-RemotePointer -Name active
    if ($null -ne $confirmedActive) {
        Assert-ValidTraceSession `
            -Session $confirmedActive `
            -PointerName active
        throw (
            "Trace '$confirmedActive' became active before '$Session' " +
            'could be pulled.'
        )
    }
    $confirmedLast = Read-RemotePointer -Name last
    Assert-ValidTraceSession -Session $confirmedLast -PointerName last
    if ($confirmedLast -ne $Session) {
        throw (
            "Completed trace changed to '$confirmedLast'; " +
            "expected '$Session'."
        )
    }
}

function Reconcile-AbandonedTracePointer {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Start', 'Checkpoint', 'Stop', 'Status')]
        [string]$CurrentAction
    )

    $script:recoveredAbandonedTraceSession = $null
    $session = Read-RemotePointer -Name active
    if ($null -eq $session) {
        return
    }

    if ($session -notmatch $traceSessionPattern) {
        $script:recoveredAbandonedTraceSession = '[invalid pointer]'
        Write-Warning (
            'Detected and retained an invalid Native Spread active-trace ' +
            'pointer. Explicit operator recovery is required.'
        )
        if ($CurrentAction -eq 'Status') {
            return
        }
        throw (
            'The active trace pointer is invalid and was retained. ' +
            "Refusing $CurrentAction so an older completed trace cannot be used."
        )
    }

    $processId = Read-TraceOwnerProcessId -Session $session
    $livePids = @(Read-DocumentProcessIds)
    if ($livePids -contains $processId) {
        if ($CurrentAction -eq 'Start') {
            throw (
                "Trace '$session' is already active. Stop it before starting " +
                'another recording.'
            )
        }
        return
    }

    if ($CurrentAction -ne 'Stop') {
        $script:recoveredAbandonedTraceSession = $session
        Write-Warning (
            "Detected abandoned Native Spread trace '$session' from " +
            "document process $processId. active.txt was retained so an " +
            'older completed trace cannot be substituted.'
        )
        if ($CurrentAction -ne 'Status') {
            throw (
                "Refusing $CurrentAction while abandoned trace '$session' " +
                'remains guarded. Run Stop for explicit recovery.'
            )
        }
        return
    }

    # Claim the exact filesystem object instead of checking its contents and
    # then unlinking a path which may have been replaced. The atomic recovery
    # directory also serializes concurrent helpers and remains as a guard if
    # the helper exits after the rename. A verified pointer is archived rather
    # than deleted, preserving the object identity used for validation. Do not
    # include ctime (%Z) in the cross-rename identity: Android updates it for
    # the rename itself. Device, inode, size, mtime, and the exact pointer value
    # still prove that the claimed object is the one which was authorized.
    $activePointer = "$remoteRoot/active.txt"
    $recoveryLock = "$remoteRoot/.active-recovery"
    $claimedPointer = "$recoveryLock/active.txt"
    $archivedRecovery = "$remoteRoot/.abandoned-$session"
    $archivedPointer = "$archivedRecovery/active.txt"
    $result = @(
        Invoke-Adb shell (
            "if [ -e '$archivedRecovery' ]; then " +
            "echo __TRACE_ABANDONED_ARCHIVE_EXISTS__ >&2; exit 82; fi; " +
            "if ! mkdir '$recoveryLock'; then " +
            "echo __TRACE_ABANDONED_LOCK_FAILED__ >&2; exit 82; fi; " +
            "if [ -L '$activePointer' ] || [ ! -f '$activePointer' ]; then " +
            "rmdir '$recoveryLock' || exit 82; " +
            "echo __TRACE_POINTER_CHANGED__; exit 0; fi; " +
            "candidate_identity=`$(stat -c '%d:%i:%s:%Y' " +
            "'$activePointer') || exit 82; " +
            "candidate_value=`$(cat '$activePointer') || exit 82; " +
            "candidate_confirmed=`$(stat -c '%d:%i:%s:%Y' " +
            "'$activePointer') || exit 82; " +
            "candidate_size=`$(stat -c '%s' '$activePointer') || exit 82; " +
            "expected_size=`$((`${#candidate_value} + 1)); " +
            "if [ `"`$candidate_identity`" != " +
            "`"`$candidate_confirmed`" ] || " +
            "[ `"`$candidate_value`" != '$session' ] || " +
            "[ `"`$candidate_size`" -ne `"`$expected_size`" ]; then " +
            "rmdir '$recoveryLock' || exit 82; " +
            "echo __TRACE_POINTER_CHANGED__; exit 0; fi; " +
            "if ! mv '$activePointer' '$claimedPointer'; then " +
            "rmdir '$recoveryLock' || exit 82; " +
            "echo __TRACE_POINTER_CHANGED__; exit 0; fi; " +
            "claimed_identity=`$(stat -c '%d:%i:%s:%Y' " +
            "'$claimedPointer') || exit 82; " +
            "claimed_value=`$(cat '$claimedPointer') || exit 82; " +
            "claimed_confirmed=`$(stat -c '%d:%i:%s:%Y' " +
            "'$claimedPointer') || exit 82; " +
            "claimed_size=`$(stat -c '%s' '$claimedPointer') || exit 82; " +
            "claimed_expected_size=`$((`${#claimed_value} + 1)); " +
            "if [ `"`$candidate_confirmed`" != " +
            "`"`$claimed_identity`" ] || " +
            "[ `"`$claimed_identity`" != `"`$claimed_confirmed`" ] || " +
            "[ `"`$claimed_value`" != '$session' ] || " +
            "[ `"`$claimed_size`" -ne `"`$claimed_expected_size`" ]; then " +
            "echo __TRACE_POINTER_REPLACEMENT_RETAINED__; exit 0; fi; " +
            "if ! mv '$recoveryLock' '$archivedRecovery'; then " +
            "echo __TRACE_ABANDONED_ARCHIVE_FAILED__ >&2; exit 82; fi; " +
            "archived_identity=`$(stat -c '%d:%i:%s:%Y' " +
            "'$archivedPointer') || exit 82; " +
            "if [ `"`$archived_identity`" != " +
            "`"`$claimed_confirmed`" ]; then " +
            "echo __TRACE_ABANDONED_ARCHIVE_CHANGED__ >&2; exit 82; fi; " +
            "echo __TRACE_ABANDONED_ARCHIVED__"
        )
    )
    if ($result.Count -ne 1) {
        throw 'Abandoned-pointer recovery returned an ambiguous result.'
    }
    $recoveryStatus = ([string]$result[0]).Trim()
    if ($recoveryStatus -eq '__TRACE_POINTER_REPLACEMENT_RETAINED__') {
        $script:abandonedRecoveryPending = $true
        throw (
            "Trace '$session' changed while Stop atomically claimed its " +
            'active pointer. The replacement was retained inside the ' +
            "recovery guard at '$recoveryLock'; explicit operator recovery " +
            'is required. Refusing last.txt fallback.'
        )
    }
    if ($recoveryStatus -eq '__TRACE_POINTER_CHANGED__') {
        throw (
            "Trace '$session' changed before Stop could claim its active " +
            'pointer. The current pointer was retained. Refusing last.txt ' +
            'fallback.'
        )
    }
    if ($recoveryStatus -ne '__TRACE_ABANDONED_ARCHIVED__') {
        throw "Unexpected abandoned-pointer recovery result: $recoveryStatus"
    }
    if ($recoveryStatus -eq '__TRACE_ABANDONED_ARCHIVED__') {
        $script:recoveredAbandonedTraceSession = $session
        Write-Warning (
            "Recovered abandoned Native Spread trace '$session' " +
            "from document process $processId. Its partial directory was " +
            'retained, and its exact active pointer was archived without ' +
            'publishing it as the last completed trace.'
        )
        Clear-MatchingLocalExpectedTraceSession -Session $session
    }
}

function Wait-TraceFinalization {
    param(
        [Parameter(Mandatory = $true)][string]$Session,
        [int]$TimeoutSeconds = 60
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    Write-Host 'Waiting for the final annotation snapshot...'
    do {
        $publicationFailed = Read-RemotePointer -Name publication-failed
        if ($null -ne $publicationFailed) {
            throw (
                "Trace '$Session' finalized its worker but completion is " +
                "guarded by publication-failed session '$publicationFailed'. " +
                "Its partial directory remains at '$remoteRoot/$Session'."
            )
        }
        $incomplete = Read-RemotePointer -Name incomplete
        if ($null -ne $incomplete) {
            throw (
                "Trace '$Session' could not obtain a stable final " +
                "annotation snapshot; incomplete guard '$incomplete' " +
                "remains at '$remoteRoot'."
            )
        }
        $activeSession = Read-RemotePointer -Name active
        if ($null -eq $activeSession) {
            $lastSession = Read-RemotePointer -Name last
            if ($null -eq $lastSession) {
                throw "Trace '$Session' finalized without a completed pointer."
            }
            if ($lastSession -ne $Session) {
                throw "Trace finalized as '$lastSession', expected '$Session'."
            }
            Write-Host 'Final annotation snapshot completed.'
            return
        }
        Assert-ValidTraceSession `
            -Session $activeSession `
            -PointerName active
        if ($activeSession -and $activeSession -ne $Session) {
            throw "A different trace became active: $activeSession"
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)

    throw "Timed out waiting for trace '$Session' to finalize after $TimeoutSeconds seconds. The bundle was not pulled."
}

function Get-SafeLabel {
    param([string]$Value)

    $safe = $Value -replace '[^A-Za-z0-9._-]', '_'
    if ($safe.Length -gt 48) {
        $safe = $safe.Substring(0, 48)
    }
    if (-not $safe) {
        return 'checkpoint'
    }
    return $safe
}

function Save-RemoteScreenshot {
    param([string]$Session, [string]$CheckpointLabel)

    Assert-ValidTraceSession -Session $Session -PointerName active
    $safeLabel = Get-SafeLabel $CheckpointLabel
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    # Screenshots are staged outside the session directory so a document
    # finalizing concurrently cannot have its already-published bundle mutated.
    $remoteDirectory = "$remoteRoot/.screenshots/$Session"
    $remoteFile = "$remoteDirectory/$stamp-$safeLabel.png"
    $remotePartial = "$remoteFile.partial"
    Invoke-Adb shell (
        "if [ -e '$remoteDirectory' ] && " +
        "{ [ -L '$remoteDirectory' ] || [ ! -d '$remoteDirectory' ]; }; " +
        "then exit 83; fi; " +
        "mkdir -p '$remoteDirectory' || exit 83; " +
        "if [ ! -f '$remoteRoot/active.txt' ] || " +
        "! grep -Fqx '$Session' '$remoteRoot/active.txt'; then exit 84; fi; " +
        "if [ -e '$remoteFile' ]; then exit 85; fi; " +
        "rm -f '$remotePartial' || exit 85; " +
        "screencap -p '$remotePartial' || " +
        "{ rm -f '$remotePartial'; exit 86; }; " +
        "if [ ! -f '$remotePartial' ] || [ ! -s '$remotePartial' ]; then " +
        "rm -f '$remotePartial'; exit 86; fi; " +
        "if [ ! -f '$remoteRoot/active.txt' ] || " +
        "! grep -Fqx '$Session' '$remoteRoot/active.txt'; then " +
        "rm -f '$remotePartial'; exit 87; fi; " +
        "mv '$remotePartial' '$remoteFile' || " +
        "{ rm -f '$remotePartial'; exit 88; }; " +
        "if [ ! -f '$remoteFile' ] || [ -L '$remoteFile' ]; then exit 88; fi"
    ) | Out-Null
    Write-Host "Screenshot: $remoteFile"
}

function Pull-StagedScreenshots {
    param(
        [Parameter(Mandatory = $true)][string]$Session,
        [Parameter(Mandatory = $true)][string]$LocalSession
    )

    $remoteDirectory = "$remoteRoot/.screenshots/$Session"
    $state = @(
        Invoke-Adb shell (
            "if [ ! -e '$remoteDirectory' ]; then " +
            "printf '%s\n' '__SNTRACE_SCREENSHOTS_ABSENT__'; " +
            "elif [ -L '$remoteDirectory' ] || [ ! -d '$remoteDirectory' ]; then " +
            "printf '%s\n' '__SNTRACE_SCREENSHOTS_NOT_DIRECTORY__' >&2; " +
            "exit 81; else printf '%s\n' '__SNTRACE_SCREENSHOTS_PRESENT__'; fi"
        )
    )
    if ($state.Count -ne 1) {
        throw "Ambiguous screenshot staging state for trace '$Session'."
    }
    $status = ([string]$state[0]).Trim()
    if ($status -eq '__SNTRACE_SCREENSHOTS_ABSENT__') {
        return
    }
    if ($status -ne '__SNTRACE_SCREENSHOTS_PRESENT__') {
        throw "Invalid screenshot staging state for trace '$Session'."
    }
    $localScreenshots = Join-Path $LocalSession 'screenshots'
    New-Item -ItemType Directory -Force -Path $localScreenshots | Out-Null
    Invoke-Adb pull "$remoteDirectory/." $localScreenshots | Out-Host
}

function Ping-ForUser {
    if ($NoPing) {
        return
    }
    [console]::Beep(880, 250)
    Start-Sleep -Milliseconds 120
    [console]::Beep(1175, 250)
}

function Write-TraceSummary {
    param([string]$SessionDirectory)

    $eventPath = Join-Path $SessionDirectory 'events.jsonl'
    if (-not (Test-Path -LiteralPath $eventPath)) {
        throw "Trace bundle is missing events.jsonl: $SessionDirectory"
    }

    $events = @()
    $parseErrors = 0
    foreach ($line in Get-Content -LiteralPath $eventPath) {
        if (-not $line.Trim()) {
            continue
        }
        try {
            $events += $line | ConvertFrom-Json
        } catch {
            $parseErrors++
        }
    }
    if ($parseErrors -ne 0) {
        throw (
            "Trace bundle contains $parseErrors malformed JSON event " +
            "record(s): $eventPath"
        )
    }
    if ($events.Count -eq 0) {
        throw "Trace bundle contains no JSON events: $eventPath"
    }

    $boundaries = @($events | Where-Object event -eq 'annotation_boundary')
    $snapshots = @(
        $events |
            Where-Object { $_.event -eq 'mark_snapshot' -and $_.exists -eq $true }
    )
    $contacts = @($events | Where-Object event -eq 'pen_contact_started')
    $failures = @(
        $events | Where-Object {
            $_.event -match '(failed|error|aborted|unstable)$' -or
            ($_.event -eq 'module_log' -and
                $_.message -match '(failed|error|aborted)')
        }
    )

    $summary = [System.Collections.Generic.List[string]]::new()
    $summary.Add('# Native Spread annotation trace')
    $summary.Add('')
    $summary.Add("- Events: $($events.Count)")
    $summary.Add("- Pen transactions observed: $($contacts.Count)")
    $summary.Add("- Annotation boundaries: $($boundaries.Count)")
    $summary.Add("- Changed `.mark` snapshots: $($snapshots.Count)")
    $summary.Add("- Potential failures: $($failures.Count)")
    $summary.Add("- JSON parse errors: $parseErrors")
    $summary.Add('')
    $summary.Add('## Annotation boundaries')
    $summary.Add('')
    $summary.Add('| Seq | Tx | Boundary | Reader | Mark | File trails | Current trails | Mark SHA | File fingerprint | Current fingerprint |')
    $summary.Add('|---:|---:|---|---:|---:|---:|---:|---|---|---|')
    foreach ($event in $boundaries) {
        $fileFingerprint = [string]$event.fileTrails.orderedFingerprint
        $currentFingerprint = [string]$event.currentTrails.orderedFingerprint
        if ($fileFingerprint.Length -gt 12) {
            $fileFingerprint = $fileFingerprint.Substring(0, 12)
        }
        if ($currentFingerprint.Length -gt 12) {
            $currentFingerprint = $currentFingerprint.Substring(0, 12)
        }
        $markHash = [string]$event.markSha256
        if ($markHash.Length -gt 12) {
            $markHash = $markHash.Substring(0, 12)
        }
        $summary.Add(
            "| $($event.seq) | $($event.transaction) | $($event.boundary) | $($event.visibleReaderPage) | $($event.markPage) | $($event.fileTrails.count) | $($event.currentTrails.count) | $markHash | $fileFingerprint | $currentFingerprint |"
        )
    }

    $summary.Add('')
    $summary.Add('## Changed mark snapshots')
    $summary.Add('')
    foreach ($event in $snapshots) {
        $summary.Add(
            "- Seq $($event.seq): $($event.reason) -- $($event.sha256) -- $($event.snapshot)"
        )
    }

    $summary.Add('')
    $summary.Add('## Potential failures')
    $summary.Add('')
    if ($failures.Count -eq 0) {
        $summary.Add('- None recorded.')
    } else {
        foreach ($event in $failures) {
            $detail = if ($event.message) {
                $event.message
            } elseif ($event.error) {
                $event.error
            } else {
                $event.event
            }
            $summary.Add("- Seq $($event.seq): $detail")
        }
    }

    $summary | Set-Content -LiteralPath (
        Join-Path $SessionDirectory 'summary.md'
    ) -Encoding utf8
}

Assert-DeviceConnected
Read-AbandonedRecoveryState
Read-PublicationFailedTraceState
Read-IncompleteTraceState
Assert-NoUnresolvedTraceFailure -CurrentAction $Action
Reconcile-AbandonedTracePointer -CurrentAction $Action

switch ($Action) {
    'Start' {
        $existingExpected = Read-ExpectedTraceSession
        if ($null -ne $existingExpected) {
            throw (
                "Expected-session state '$existingExpected' is unresolved. " +
                'Run Stop before starting another trace.'
            )
        }
        Send-TraceControl -Command 'start' -CheckpointLabel $Label
        Start-Sleep -Milliseconds 900
        try {
            $session = Read-GuardedActiveTraceSession -CurrentAction Start
        } catch {
            $logcatArguments = @(
                'logcat', '-v', 'raw', '-d', '-s',
                'SN_SPREAD_PROBE:I', '*:S'
            )
            $diagnostic = Invoke-Adb @logcatArguments
            throw "Trace did not start. Open an editable Native Spread document first.`n$($diagnostic -join [Environment]::NewLine)"
        }
        Publish-ExpectedTraceSession -Session $session
        Write-Host "Recording Native Spread annotation trace: $session"
        Write-Host 'Perform the requested pen action, then run Checkpoint or Stop.'
        Ping-ForUser
    }

    'Checkpoint' {
        $expected = Read-ExpectedTraceSession
        if ($null -eq $expected) {
            throw (
                'Checkpoint requires the expected session recorded by Start ' +
                'or supplied with -ExpectedSession.'
            )
        }
        $session = Read-GuardedActiveTraceSession -CurrentAction Checkpoint
        if ($session -ne $expected) {
            throw "Active trace '$session' does not match expected '$expected'."
        }
        Send-TraceControl -Command 'checkpoint' -CheckpointLabel $Label
        Start-Sleep -Milliseconds 250
        Read-GuardedActiveTraceSession `
            -CurrentAction Checkpoint `
            -ExpectedSession $session | Out-Null
        Save-RemoteScreenshot -Session $session -CheckpointLabel $Label
        Read-GuardedActiveTraceSession `
            -CurrentAction Checkpoint `
            -ExpectedSession $session | Out-Null
        Write-Host "Checkpoint recorded: $Label"
        Ping-ForUser
    }

    'Stop' {
        if ($recoveredAbandonedTraceSession) {
            throw (
                "Trace '$recoveredAbandonedTraceSession' ended when the " +
                'Supernote document process exited. Its partial directory ' +
                "remains at '$remoteRoot/$recoveredAbandonedTraceSession'. " +
                'Stop did not pull the preceding completed session.'
            )
        }
        $expected = Read-ExpectedTraceSession
        if ($null -eq $expected) {
            throw (
                'Stop requires the expected session recorded by Start or ' +
                'supplied with -ExpectedSession. Refusing to substitute last.txt.'
            )
        }
        $session = Read-RemotePointer -Name active
        $sessionWasActive = $null -ne $session
        if ($sessionWasActive) {
            $session = Read-GuardedActiveTraceSession `
                -CurrentAction Stop `
                -ExpectedSession $expected
        }
        if (-not $sessionWasActive) {
            Assert-TraceFailureGuardsClear -CurrentAction Stop
            $session = Read-RemotePointer -Name last
            Assert-ValidTraceSession -Session $session -PointerName last
            if ($session -ne $expected) {
                throw (
                    "Completed trace '$session' does not match the Start " +
                    "session '$expected'. Refusing stale last.txt fallback."
                )
            }
        }
        if ($sessionWasActive) {
            Send-TraceControl -Command 'checkpoint' -CheckpointLabel 'final'
            Start-Sleep -Milliseconds 250
            Read-GuardedActiveTraceSession `
                -CurrentAction Stop `
                -ExpectedSession $session | Out-Null
            Save-RemoteScreenshot -Session $session -CheckpointLabel 'final'
            Read-GuardedActiveTraceSession `
                -CurrentAction Stop `
                -ExpectedSession $session | Out-Null
            Send-TraceControl -Command 'stop' -CheckpointLabel $Label
            Wait-TraceFinalization -Session $session
        } else {
            Write-Host 'The document closed before Stop; pulling the last completed session.'
        }

        New-Item -ItemType Directory -Force -Path $Destination | Out-Null
        $localSession = Join-Path $Destination $session
        $archive = "$localSession.zip"
        if (Test-Path -LiteralPath $localSession) {
            throw "Refusing to replace an existing trace bundle: $localSession"
        }
        if (Test-Path -LiteralPath $archive) {
            throw "Refusing to replace an existing archive: $archive"
        }
        # Keep the temporary parent short. Windows adb is not long-path aware;
        # repeating the full session name here can push nested mark snapshots
        # past MAX_PATH even though their final promoted paths are valid.
        $stagingRoot = Join-Path $Destination (
            '.partial-' + [Guid]::NewGuid().ToString('N')
        )
        $stagedSession = Join-Path $stagingRoot $session
        $stagedArchive = Join-Path $stagingRoot ($session + '.zip')
        New-Item -ItemType Directory -Path $stagingRoot | Out-Null
        try {
            Assert-CompletedTraceStillPullable -Session $session
            Invoke-Adb pull "$remoteRoot/$session" $stagingRoot | Out-Host
            if (-not (Test-Path -LiteralPath $stagedSession -PathType Container)) {
                throw "Trace pull did not create the staged session: $stagedSession"
            }
            Assert-CompletedTraceStillPullable -Session $session
            Pull-StagedScreenshots `
                -Session $session `
                -LocalSession $stagedSession
            Assert-CompletedTraceStillPullable -Session $session
            $logcatArguments = @(
                'logcat', '-v', 'threadtime', '-d', '-s',
                'SN_SPREAD_PROBE:I', '*:S'
            )
            Invoke-Adb @logcatArguments |
                Set-Content -LiteralPath (
                    Join-Path $stagedSession 'module-logcat.txt'
                )
            Write-TraceSummary -SessionDirectory $stagedSession
            Compress-Archive `
                -LiteralPath $stagedSession `
                -DestinationPath $stagedArchive
            if (-not (Test-Path -LiteralPath $stagedArchive -PathType Leaf)) {
                throw "Trace archive was not created: $stagedArchive"
            }
            $stagedHash = Get-FileHash `
                -Algorithm SHA256 `
                -LiteralPath $stagedArchive
            Assert-CompletedTraceStillPullable -Session $session

            Move-Item -LiteralPath $stagedSession -Destination $localSession
            if (-not (Test-Path -LiteralPath $localSession -PathType Container)) {
                throw "Trace directory promotion failed: $localSession"
            }
            Move-Item -LiteralPath $stagedArchive -Destination $archive
            if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
                throw "Trace archive promotion failed: $archive"
            }
            if (Test-Path -LiteralPath $stagingRoot) {
                Remove-Item -LiteralPath $stagingRoot
            }
        } catch {
            Write-Warning (
                "Incomplete local trace staging was retained at '$stagingRoot'."
            )
            throw
        }
        $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $archive
        if ($hash.Hash -ne $stagedHash.Hash) {
            throw "Trace archive changed during atomic promotion: $archive"
        }
        Write-Host "Trace bundle: $localSession"
        Write-Host "Archive:      $archive"
        Write-Host "SHA-256:      $($hash.Hash)"
        Clear-ExpectedTraceSession -Session $session
        Ping-ForUser
    }

    'Status' {
        if ($abandonedRecoveryPending) {
            Write-Host (
                'An abandoned-pointer recovery remains guarded. Inspect ' +
                "'$remoteRoot/.active-recovery' and perform explicit " +
                'operator recovery before another trace action.'
            )
            return
        }
        if ($publicationFailedTraceSession) {
            Write-Host (
                'Trace publication remains unresolved: ' +
                $publicationFailedTraceSession
            )
            return
        }
        if ($incompleteTraceSession) {
            Write-Host (
                'An incomplete trace remains guarded: ' +
                $incompleteTraceSession
            )
            return
        }
        if ($recoveredAbandonedTraceSession) {
            Write-Host (
                'No active trace. Abandoned session: ' +
                $recoveredAbandonedTraceSession +
                '. Its active pointer was retained for Stop.'
            )
            return
        }
        $session = Read-RemotePointer -Name active
        if ($null -ne $session) {
            Assert-ValidTraceSession -Session $session -PointerName active
            Write-Host "Recording: $session"
        } else {
            $last = Read-RemotePointer -Name last
            if ($null -ne $last) {
                Assert-ValidTraceSession -Session $last -PointerName last
                Write-Host "No active trace. Last session: $last"
            } else {
                Write-Host 'No Native Spread annotation trace has been recorded.'
            }
        }
    }
}
