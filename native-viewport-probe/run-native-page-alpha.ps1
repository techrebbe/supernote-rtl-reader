[CmdletBinding()]
param(
    [ValidateSet('SN078C10015092')]
    [string]$Serial = 'SN078C10015092',
    [ValidateSet('manual-physical-v1', 'adb-system-settings-v1')]
    [string]$RotationAuthority = 'manual-physical-v1'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$authorizedSerial = 'SN078C10015092'
$authorizedModel = 'Supernote Nomad'
$authorizedSdk = '30'
$authorizedFingerprint = 'Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys'
$authorizedUser = '0'
$hostPackage = 'com.techrebbe.supernote.nativepagehost'
$androidSdk = if ($env:ANDROID_SDK_ROOT) {
    $env:ANDROID_SDK_ROOT
} elseif ($env:ANDROID_HOME) {
    $env:ANDROID_HOME
} else {
    Join-Path $env:LOCALAPPDATA 'Android\Sdk'
}
$adb = Join-Path $androidSdk 'platform-tools\adb.exe'
$pythonRuntime = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
$buildHelper = Join-Path $PSScriptRoot 'build-native-page-host-alpha.ps1'
$installHelper = Join-Path $PSScriptRoot 'install-native-page-host-alpha.ps1'
$runner = Join-Path $PSScriptRoot 'native_page_alpha_runner.py'
$rotationController = Join-Path $PSScriptRoot 'native_page_alpha_rotation_controller.py'
$alphaDirectory = Join-Path $PSScriptRoot 'build\native-page-host-alpha'
$alphaApk = Join-Path $alphaDirectory 'native-page-host-alpha.apk'
$alphaMetadata = Join-Path $alphaDirectory 'native-page-host-alpha.json'
$outputRoot = Join-Path $PSScriptRoot 'build\native-page-alpha-runs'
$lockDirectory = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) `
    'SupernoteAlpha\NativePageHostLocks\SN078C10015092'
$lockPath = Join-Path $lockDirectory 'session.lock'

function Assert-ExactDeviceLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Output,
        [Parameter(Mandatory)]
        [int]$ExitCode,
        [Parameter(Mandatory)]
        [string]$Expected,
        [Parameter(Mandatory)]
        [string]$Label
    )
    $lines = @($Output | ForEach-Object { [string]$_ })
    if ($ExitCode -ne 0 -or $lines.Count -ne 1 -or
            $lines[0] -cne $Expected) {
        throw "Exact authorized Nomad $Label was not proved."
    }
}

if ($Serial -cne $authorizedSerial) {
    throw 'Only the authorized Nomad serial is admitted by this alpha.'
}
$requiredTools = @($adb, $pythonRuntime, $buildHelper, $installHelper, $runner)
if ($RotationAuthority -ceq 'adb-system-settings-v1') {
    $requiredTools += $rotationController
}
foreach ($required in $requiredTools) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required alpha tool is missing: $required"
    }
}

[IO.Directory]::CreateDirectory($lockDirectory) | Out-Null
$sessionLock = $null
$coordinatorExitCode = 1
try {
    try {
        $sessionLock = [IO.File]::Open(
            $lockPath, [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    } catch {
        throw 'Another native-page alpha transaction holds the exact Nomad session lock.'
    }

    # This independent, read-only gate runs before either build or install.
    # Each command is structurally bound to the only authorized serial.
    $deviceState = @(& $adb -s $authorizedSerial get-state 2>&1)
    $deviceStateExit = $LASTEXITCODE
    Assert-ExactDeviceLine -Output $deviceState -ExitCode $deviceStateExit `
        -Expected 'device' -Label 'online state'

    $deviceSerial = @(& $adb -s $authorizedSerial get-serialno 2>&1)
    $deviceSerialExit = $LASTEXITCODE
    Assert-ExactDeviceLine -Output $deviceSerial -ExitCode $deviceSerialExit `
        -Expected $authorizedSerial -Label 'serial'

    $deviceModel = @(& $adb -s $authorizedSerial shell getprop ro.product.model 2>&1)
    $deviceModelExit = $LASTEXITCODE
    Assert-ExactDeviceLine -Output $deviceModel -ExitCode $deviceModelExit `
        -Expected $authorizedModel -Label 'model'

    $deviceSdk = @(& $adb -s $authorizedSerial shell getprop ro.build.version.sdk 2>&1)
    $deviceSdkExit = $LASTEXITCODE
    Assert-ExactDeviceLine -Output $deviceSdk -ExitCode $deviceSdkExit `
        -Expected $authorizedSdk -Label 'Android SDK'

    $deviceFingerprint = @(& $adb -s $authorizedSerial shell getprop ro.build.fingerprint 2>&1)
    $deviceFingerprintExit = $LASTEXITCODE
    Assert-ExactDeviceLine -Output $deviceFingerprint -ExitCode $deviceFingerprintExit `
        -Expected $authorizedFingerprint -Label 'firmware fingerprint'

    $deviceUser = @(& $adb -s $authorizedSerial shell am get-current-user 2>&1)
    $deviceUserExit = $LASTEXITCODE
    Assert-ExactDeviceLine -Output $deviceUser -ExitCode $deviceUserExit `
        -Expected $authorizedUser -Label 'foreground user'

    & $buildHelper
    if ($LASTEXITCODE -ne 0) {
        throw 'Deterministic alpha build helper did not complete successfully.'
    }
    foreach ($artifact in @($alphaApk, $alphaMetadata)) {
        if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
            throw "Verified alpha artifact is missing: $artifact"
        }
    }

    $installOutput = @(& $installHelper -Serial $authorizedSerial -AndroidSdk $androidSdk `
        -Apk $alphaApk -Metadata $alphaMetadata -SessionLock $sessionLock 2>&1 |
        ForEach-Object { [string]$_ })
    $installExitCode = $LASTEXITCODE
    foreach ($line in $installOutput) {
        Write-Host $line
    }
    if ($installExitCode -ne 0) {
        throw 'Alpha installer did not complete successfully.'
    }
    $receiptPattern = [regex]::new(
        '^NATIVE_PAGE_HOST_ALPHA_INSTALLED serial=SN078C10015092 ' +
        'package=com\.techrebbe\.supernote\.nativepagehost versionCode=2 ' +
        'apkSha256=3798c204360db82941db7516e774517b273a51e025cce4848a642a5de61c6a03 ' +
        'signerSha256=d3f9ce76640125df1037e4536b680e29684da5ae7c171147f3206e26c7e568b4 ' +
        'priorPackage=(absent|same|upgraded) packageRollback=([^ ]+)$',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
    $installReceipts = @($installOutput | Where-Object {
        $receiptPattern.IsMatch($_)
    })
    if ($installReceipts.Count -ne 1) {
        throw 'Alpha installer did not return one exact package-state receipt.'
    }
    $receiptMatch = $receiptPattern.Match($installReceipts[0])
    if (-not $receiptMatch.Success) {
        throw 'Alpha package prior state is absent or ambiguous.'
    }
    $priorPackage = $receiptMatch.Groups[1].Value
    $packageRollback = $receiptMatch.Groups[2].Value
    $expectedRollback = @{
        absent = 'uninstall-required'
        same = 'unchanged'
        upgraded = 'not-exact'
    }[$priorPackage]
    if ($packageRollback -cne $expectedRollback) {
        throw 'Alpha installer package rollback state is inconsistent.'
    }
    if ($priorPackage -ceq 'upgraded') {
        throw 'The one-click alpha never authorizes a persistent package upgrade.'
    }

    if ($RotationAuthority -ceq 'manual-physical-v1') {
        Write-Host 'The visual alpha is ready. Its launcher may look portrait; after the disposable page opens, hold the Nomad physically in landscape. Do not touch the page or pen.'
        & $pythonRuntime -u $runner --adb $adb --serial $authorizedSerial `
            --host-metadata $alphaMetadata --output-root $outputRoot `
            --rotation-authority $RotationAuthority
    } else {
        Write-Host 'The exploratory ADB-rotation alpha is ready. Its external controller will journal every rotation change and restore the original settings. Do not touch the page or pen.'
        [IO.Directory]::CreateDirectory($outputRoot) | Out-Null
        $controllerNonce = [Guid]::NewGuid().ToString('N')
        $rotationJournal = Join-Path $outputRoot `
            ('.rotation-controller-' + $controllerNonce + '.jsonl')
        $rotationEvidence = Join-Path $outputRoot `
            ('.rotation-controller-' + $controllerNonce + '.evidence.json')
        & $pythonRuntime -u $rotationController --adb $adb `
            --serial $authorizedSerial --runner $runner `
            --host-metadata $alphaMetadata --output-root $outputRoot `
            --journal $rotationJournal --evidence $rotationEvidence
    }
    $runnerExitCode = $LASTEXITCODE
    if ($runnerExitCode -notin @(0, 3)) {
        if ($priorPackage -ceq 'absent') {
            Write-Warning 'The newly installed host is retained because exact session cleanup was not proved. Do not uninstall it until the report is reviewed.'
        }
        $coordinatorExitCode = $runnerExitCode
    } else {
        if ($priorPackage -ceq 'absent') {
            # The runner exits 0 or 3 only after the exact foreign task, host
            # task, session display, and staged fixture scope are proved clean.
            $uninstallOutput = @(& $adb -s $authorizedSerial uninstall $hostPackage 2>&1 |
                ForEach-Object { [string]$_ })
            $uninstallExitCode = $LASTEXITCODE
            if ($uninstallExitCode -ne 0 -or
                    @($uninstallOutput | Where-Object { $_.Trim() -ceq 'Success' }).Count -ne 1) {
                throw 'Exact newly installed alpha host could not be rolled back.'
            }
            $packageOutput = @(& $adb -s $authorizedSerial shell pm path $hostPackage 2>&1 |
                ForEach-Object { [string]$_ })
            $packageExitCode = $LASTEXITCODE
            if ($packageExitCode -notin @(0, 1) -or
                    @($packageOutput | Where-Object { $_ -cmatch '^package:' }).Count -ne 0) {
                throw 'Alpha host package absence was not proved after rollback.'
            }
            $pidOutput = @(& $adb -s $authorizedSerial shell pidof $hostPackage 2>&1 |
                ForEach-Object { [string]$_ })
            $pidExitCode = $LASTEXITCODE
            if ($pidExitCode -notin @(0, 1) -or
                    @($pidOutput | Where-Object { $_ -cmatch '[0-9]' }).Count -ne 0) {
                throw 'Alpha host process absence was not proved after rollback.'
            }
            $displayOutput = @(& $adb -s $authorizedSerial shell dumpsys display 2>&1 |
                ForEach-Object { [string]$_ })
            if ($LASTEXITCODE -ne 0 -or
                    @($displayOutput | Where-Object { $_.Contains('NativePageVisualOnly-') }).Count -ne 0) {
                throw 'Native-page alpha display absence was not preserved after rollback.'
            }
            Write-Host 'The newly installed visual host was uninstalled after exact session cleanup.'
        } else {
            Write-Host 'The pre-existing byte-identical visual host installation was left unchanged.'
        }
        if ($runnerExitCode -eq 3) {
            Write-Warning 'The alpha exposed a diagnostic/preflight failure, but proved its narrow device state clean.'
            $coordinatorExitCode = 3
        } else {
            $coordinatorExitCode = 0
        }
    }
} finally {
    if ($null -ne $sessionLock) {
        $sessionLock.Dispose()
    }
}
exit $coordinatorExitCode
