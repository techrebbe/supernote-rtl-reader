param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Start', 'Checkpoint', 'Stop', 'Status')]
    [string]$Action,

    [string]$Label = 'manual',

    [string]$Adb = 'adb',

    [string]$Destination = $(
        Join-Path $PSScriptRoot 'trace-bundles'
    )
)

$ErrorActionPreference = 'Stop'

$traceAction = 'com.techrebbe.supernote.spreadprobe.TRACE_CONTROL'
$documentPackage = 'com.supernote.document'
$remoteRoot = '/storage/emulated/0/Download/SupernoteNativeSpreadTrace'

if ($Adb -eq 'adb' -and -not (Get-Command adb -ErrorAction SilentlyContinue)) {
    $sdkAdb = Join-Path $env:LOCALAPPDATA 'Android\Sdk\platform-tools\adb.exe'
    if (Test-Path -LiteralPath $sdkAdb) {
        $Adb = $sdkAdb
    }
}

function Invoke-Adb {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)

    $output = & $Adb @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "adb failed ($LASTEXITCODE): $($output -join [Environment]::NewLine)"
    }
    return $output
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
    param([ValidateSet('active', 'last')][string]$Name)

    $value = Invoke-Adb shell "cat '$remoteRoot/$Name.txt'"
    return ($value | Out-String).Trim()
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

    $safeLabel = Get-SafeLabel $CheckpointLabel
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss-fff'
    $remoteDirectory = "$remoteRoot/$Session/screenshots"
    $remoteFile = "$remoteDirectory/$stamp-$safeLabel.png"
    Invoke-Adb shell mkdir -p $remoteDirectory | Out-Null
    Invoke-Adb shell screencap -p $remoteFile | Out-Null
    Write-Host "Screenshot: $remoteFile"
}

function Ping-ForUser {
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

switch ($Action) {
    'Start' {
        Send-TraceControl -Command 'start' -CheckpointLabel $Label
        Start-Sleep -Milliseconds 900
        try {
            $session = Read-RemotePointer -Name active
        } catch {
            $diagnostic = Invoke-Adb logcat -v raw -d -s 'SN_SPREAD_PROBE:I' '*:S'
            throw "Trace did not start. Open an editable Native Spread document first.`n$($diagnostic -join [Environment]::NewLine)"
        }
        Write-Host "Recording Native Spread annotation trace: $session"
        Write-Host 'Perform the requested pen action, then run Checkpoint or Stop.'
        Ping-ForUser
    }

    'Checkpoint' {
        $session = Read-RemotePointer -Name active
        Send-TraceControl -Command 'checkpoint' -CheckpointLabel $Label
        Start-Sleep -Milliseconds 250
        Save-RemoteScreenshot -Session $session -CheckpointLabel $Label
        Write-Host "Checkpoint recorded: $Label"
        Ping-ForUser
    }

    'Stop' {
        $sessionWasActive = $true
        try {
            $session = Read-RemotePointer -Name active
        } catch {
            $sessionWasActive = $false
            $session = Read-RemotePointer -Name last
        }
        if ($sessionWasActive) {
            Send-TraceControl -Command 'checkpoint' -CheckpointLabel 'final'
            Start-Sleep -Milliseconds 250
            Save-RemoteScreenshot -Session $session -CheckpointLabel 'final'
            Send-TraceControl -Command 'stop' -CheckpointLabel $Label
            Start-Sleep -Milliseconds 500
        } else {
            Write-Host 'The document closed before Stop; pulling the last completed session.'
        }

        New-Item -ItemType Directory -Force -Path $Destination | Out-Null
        $localSession = Join-Path $Destination $session
        if (Test-Path -LiteralPath $localSession) {
            throw "Refusing to replace an existing trace bundle: $localSession"
        }
        Invoke-Adb pull "$remoteRoot/$session" $Destination | Out-Host
        Invoke-Adb logcat -v threadtime -d -s 'SN_SPREAD_PROBE:I' '*:S' |
            Set-Content -LiteralPath (Join-Path $localSession 'module-logcat.txt')
        Write-TraceSummary -SessionDirectory $localSession

        $archive = "$localSession.zip"
        if (Test-Path -LiteralPath $archive) {
            throw "Refusing to replace an existing archive: $archive"
        }
        Compress-Archive -LiteralPath $localSession -DestinationPath $archive
        $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $archive
        Write-Host "Trace bundle: $localSession"
        Write-Host "Archive:      $archive"
        Write-Host "SHA-256:      $($hash.Hash)"
        Ping-ForUser
    }

    'Status' {
        try {
            $session = Read-RemotePointer -Name active
            Write-Host "Recording: $session"
        } catch {
            try {
                $last = Read-RemotePointer -Name last
                Write-Host "No active trace. Last session: $last"
            } catch {
                Write-Host 'No Native Spread annotation trace has been recorded.'
            }
        }
    }
}
