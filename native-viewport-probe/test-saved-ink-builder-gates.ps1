$ErrorActionPreference = 'Stop'
$probeRoot = $PSScriptRoot
$builder = Join-Path $probeRoot 'build-saved-ink-reader.ps1'
$check = Join-Path $probeRoot 'check.ps1'

function Get-FunctionSource {
    param([string]$ScriptPath, [string]$Name)
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $ScriptPath, [ref]$tokens, [ref]$errors)
    if ($errors.Count -ne 0) {throw "Cannot parse $ScriptPath"}
    $matches = @($ast.FindAll({param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $Name
    }, $true))
    if ($matches.Count -ne 1) {throw "Expected one $Name in $ScriptPath"}
    return $matches[0].Extent.Text
}

function Assert-Rejected {
    param([string]$Name, [string]$ExpectedMessage, [scriptblock]$Action)
    $rejected = $false
    try {& $Action | Out-Null} catch {
        if ($_.Exception -isnot [Management.Automation.RuntimeException] -or
                $_.Exception.Message -cne $ExpectedMessage) {
            throw "Unexpected rejection for ${Name}: $($_.Exception.Message)"
        }
        $rejected = $true
    }
    if (-not $rejected) {throw "Expected fail-closed rejection: $Name"}
}

foreach ($name in @('ConvertTo-CanonicalSourceBytes',
        'Get-CanonicalSourceBytes', 'Assert-PinnedSource',
        'Assert-OrdinaryDirectoryChain', 'Get-SafeBuildParent')) {
    $source = Get-FunctionSource -ScriptPath $builder -Name $name
    if ($name -in @('Assert-OrdinaryDirectoryChain', 'Get-SafeBuildParent') -and
            $source -cne (Get-FunctionSource -ScriptPath $check -Name $name)) {
        throw "Builder and host check disagree on $name"
    }
    . ([scriptblock]::Create($source))
}
$builderText = [IO.File]::ReadAllText($builder)
$checkText = [IO.File]::ReadAllText($check)
$builderPinLines = @($checkText -split '\r?\n' | Where-Object {
    $_.StartsWith('$expectedSavedInkBuilderSha256=',
        [StringComparison]::Ordinal)
})
if ($builderPinLines.Count -ne 1 -or $builderPinLines[0] -cnotmatch
        '^\$expectedSavedInkBuilderSha256=''([0-9a-f]{64})''$') {
    throw 'Expected exactly one canonical SavedInk builder pin'
}
$expectedBuilderDigest = $Matches[1]
$canonicalBuilder = ConvertTo-CanonicalSourceBytes `
    ([IO.File]::ReadAllBytes($builder))
$hasher = [Security.Cryptography.SHA256]::Create()
try {
    $actualBuilderDigest = ([BitConverter]::ToString(
        $hasher.ComputeHash([byte[]]$canonicalBuilder))).Replace('-','').ToLowerInvariant()
} finally {$hasher.Dispose()}
if ($actualBuilderDigest -cne $expectedBuilderDigest) {
    throw 'Reviewed builder source does not match the host-check pin'
}
$builderGateAt = $builderText.IndexOf('$buildParent = Get-SafeBuildParent',
    [StringComparison]::Ordinal)
$builderCreateAt = $builderText.IndexOf(
    'New-Item -ItemType Directory -Path $buildRoot',
    [StringComparison]::Ordinal)
$checkGateAt = $checkText.IndexOf('$buildParent=Get-SafeBuildParent',
    [StringComparison]::Ordinal)
$checkCreateAt = $checkText.IndexOf(
    'New-Item -ItemType Directory -Path $buildPath',
    [StringComparison]::Ordinal)
if ($builderGateAt -lt 0 -or $builderCreateAt -lt 0 -or
        $checkGateAt -lt 0 -or $checkCreateAt -lt 0 -or
        $builderGateAt -ge $builderCreateAt -or
        $checkGateAt -ge $checkCreateAt) {
    throw 'Output path validation must precede output creation'
}

$fixture = Join-Path ([IO.Path]::GetTempPath()) `
    ('saved-ink-gates-' + [guid]::NewGuid().ToString('N'))
$sourceFile = Join-Path $fixture 'source.java'
$ordinary = Join-Path $fixture 'ordinary'
$ordinaryBuild = Join-Path $ordinary 'build'
$linkedProbe = Join-Path $fixture 'linked-probe'
$buildJunction = Join-Path $linkedProbe 'build'
$clonedCheck = Join-Path $linkedProbe 'check.ps1'
$ancestorReal = Join-Path $fixture 'ancestor-real'
$ancestorChild = Join-Path $ancestorReal 'child'
$ancestorJunction = Join-Path $fixture 'ancestor-junction'
$outside = Join-Path $fixture 'outside'
try {
    New-Item -ItemType Directory -Path $fixture,$ordinary,$linkedProbe,`
        $ancestorReal,$ancestorChild,$outside | Out-Null

    $lf = [Text.UTF8Encoding]::new($false).GetBytes("alpha`nbeta`n")
    [IO.File]::WriteAllBytes($sourceFile, $lf)
    $digest = (Get-FileHash -Algorithm SHA256 -LiteralPath $sourceFile).Hash.ToLowerInvariant()
    Assert-PinnedSource -LiteralPath $sourceFile `
        -ExpectedSha256 $digest -ExpectedBytes $lf.Length
    [IO.File]::WriteAllBytes($sourceFile,
        [Text.UTF8Encoding]::new($false).GetBytes("alpha`r`nbeta`r`n"))
    Assert-PinnedSource -LiteralPath $sourceFile `
        -ExpectedSha256 $digest -ExpectedBytes $lf.Length
    Assert-Rejected 'canonical size' `
        "Pinned canonical source size changed: $sourceFile" {
        Assert-PinnedSource -LiteralPath $sourceFile `
            -ExpectedSha256 $digest -ExpectedBytes ($lf.Length + 1)
    }
    [IO.File]::WriteAllBytes($sourceFile,
        [Text.UTF8Encoding]::new($false).GetBytes("alpha`r`nbeta`n"))
    Assert-Rejected 'mixed newlines' `
        'Pinned source has mixed or bare-CR newlines.' {
        Assert-PinnedSource -LiteralPath $sourceFile `
            -ExpectedSha256 $digest -ExpectedBytes $lf.Length
    }
    [IO.File]::WriteAllBytes($sourceFile,
        [Text.UTF8Encoding]::new($false).GetBytes("alphx`nbeta`n"))
    Assert-Rejected 'same-size source mutation' `
        "Pinned source digest changed: $sourceFile" {
        Assert-PinnedSource -LiteralPath $sourceFile `
            -ExpectedSha256 $digest -ExpectedBytes $lf.Length
    }
    [IO.File]::WriteAllBytes($sourceFile,
        [byte[]](0x61,0xE2,0x80,0xA8,0x62))
    Assert-Rejected 'Unicode line separator' `
        'Pinned source has a Unicode line separator.' {
        Assert-PinnedSource -LiteralPath $sourceFile `
            -ExpectedSha256 $digest -ExpectedBytes 5
    }

    $actualBuild = Get-SafeBuildParent -ProbeRoot $ordinary
    if (-not [string]::Equals($actualBuild, $ordinaryBuild,
            [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Ordinary build parent was not accepted'
    }
    New-Item -ItemType Junction -Path $buildJunction -Target $outside | Out-Null
    Assert-Rejected 'preexisting build junction' `
        "Build output has a non-directory or reparse ancestor: $buildJunction" {
        Get-SafeBuildParent -ProbeRoot $linkedProbe
    }
    [IO.File]::Copy($check, $clonedCheck)
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = (Get-Process -Id $PID).Path
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $arguments = @('-NoLogo','-NoProfile','-NonInteractive',
        '-ExecutionPolicy','Bypass','-File',$clonedCheck,
        '-Jdk','unused','-AndroidJar','unused','-JsonJar','unused',
        '-Python','unused','-PythonPath','unused')
    if ($null -ne $start.PSObject.Properties['ArgumentList']) {
        foreach ($argument in $arguments) {
            [void]$start.ArgumentList.Add($argument)
        }
    } else {
        $start.Arguments = '-NoLogo -NoProfile -NonInteractive ' +
            '-ExecutionPolicy Bypass -File "' + $clonedCheck + '" ' +
            '-Jdk unused -AndroidJar unused -JsonJar unused ' +
            '-Python unused -PythonPath unused'
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $started = $false
    try {
        $started = $process.Start()
        if (-not $started) {throw 'Cloned host check did not start'}
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(10000)) {
            throw 'Cloned host check exceeded the 10-second deadline'
        }
        if (-not [Threading.Tasks.Task]::WaitAll(
                [Threading.Tasks.Task[]]@($stdoutTask,$stderrTask),5000)) {
            throw 'Cloned host check output exceeded the 5-second deadline'
        }
        if ($process.ExitCode -eq 0 -or $stdoutTask.Result.Length -ne 0 -or
                -not $stderrTask.Result.Contains(
                    'Build output has a non-directory or reparse') -or
                -not $stderrTask.Result.Contains($buildJunction)) {
            throw "Host check did not reject the build junction before output: exit=$($process.ExitCode) stdout=$($stdoutTask.Result) stderr=$($stderrTask.Result)"
        }
    } finally {
        try {
            if ($started -and -not $process.HasExited) {
                $killTree = [Diagnostics.Process].GetMethod(
                    'Kill',[type[]]@([bool]))
                try {
                    if ($null -ne $killTree) {$process.Kill($true)}
                    else {$process.Kill()}
                } catch {
                    if (-not $process.HasExited) {throw}
                }
                if (-not $process.WaitForExit(5000)) {
                    throw 'Cloned host check could not be stopped within 5 seconds'
                }
            }
        } finally {$process.Dispose()}
    }
    New-Item -ItemType Junction -Path $ancestorJunction `
        -Target $ancestorReal | Out-Null
    Assert-Rejected 'junction in probe-root ancestry' `
        "Build output has a non-directory or reparse ancestor: $ancestorJunction" {
        Get-SafeBuildParent -ProbeRoot (Join-Path $ancestorJunction 'child')
    }
    if (@(Get-ChildItem -LiteralPath $outside -Force).Count -ne 0 -or
            (Test-Path -LiteralPath (Join-Path $ancestorChild 'build'))) {
        throw 'Rejected output path nevertheless received a write'
    }
    Write-Output 'SAVED_INK_BUILDER_GATE_TESTS_PASS tests=11'
} finally {
    if (Test-Path -LiteralPath $sourceFile) {[IO.File]::Delete($sourceFile)}
    if (Test-Path -LiteralPath $clonedCheck) {[IO.File]::Delete($clonedCheck)}
    if (Test-Path -LiteralPath $buildJunction) {
        [IO.Directory]::Delete($buildJunction)
    }
    if (Test-Path -LiteralPath $ancestorJunction) {
        [IO.Directory]::Delete($ancestorJunction)
    }
    foreach ($directory in @($ordinaryBuild,$ordinary,$linkedProbe,
            $ancestorChild,$ancestorReal,$outside,$fixture)) {
        if (Test-Path -LiteralPath $directory) {
            [IO.Directory]::Delete($directory)
        }
    }
}
