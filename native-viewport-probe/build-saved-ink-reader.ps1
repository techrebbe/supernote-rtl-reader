param(
    [string]$Jdk,
    [string]$AndroidSdk,
    [string]$Python
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Jdk)) {
    $Jdk=$(if ($env:RTL_READER_BUILD_JDK) {
        $env:RTL_READER_BUILD_JDK } else { 'C:\Program Files\Java\jdk-17' })
}
if ([string]::IsNullOrWhiteSpace($AndroidSdk)) {
    $AndroidSdk=$(if ($env:RTL_READER_BUILD_ANDROID_SDK) {
        $env:RTL_READER_BUILD_ANDROID_SDK } else { throw (
        'AndroidSdk is required (parameter or RTL_READER_BUILD_ANDROID_SDK).' ) })
}
if ([string]::IsNullOrWhiteSpace($Python)) {
    $Python=$(if ($env:RTL_READER_BUILD_PYTHON) {
        $env:RTL_READER_BUILD_PYTHON } else { throw (
        'Python is required (parameter or RTL_READER_BUILD_PYTHON).' ) })
}
$capturedProbeRoot = $env:RTL_READER_AUTHENTICATED_PROBE_ROOT
$capturedBuildScript = $env:RTL_READER_AUTHENTICATED_BUILD_SOURCE
if (($null -eq $capturedProbeRoot) -ne ($null -eq $capturedBuildScript)) {
    throw 'Authenticated builder root and source must be supplied together.'
}
$probeRoot = [IO.Path]::GetFullPath($(if ($capturedProbeRoot) {
    $capturedProbeRoot } else { $PSScriptRoot }))
$source = Join-Path $probeRoot 'java\com\techrebbe\supernote\viewportprobe\SavedInkReader.java'
$packager = Join-Path $probeRoot 'saved_ink_reader_artifact.py'
$tests = Join-Path $probeRoot 'test_saved_ink_reader_artifact.py'
$invoker = Join-Path $probeRoot 'invoke-authenticated-production.ps1'
$buildScript = $(if ($capturedBuildScript) {
    [IO.Path]::GetFullPath($capturedBuildScript) } else { $PSCommandPath })
$buildScriptItem = Get-Item -LiteralPath $buildScript -Force
if (($buildScriptItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not (Test-Path -LiteralPath $buildScript -PathType Leaf)) {
    throw 'Build script is not one ordinary regular file.'
}
$initialBuildScriptBytes = $buildScriptItem.Length
$initialBuildScriptSha256 = (Get-FileHash -Algorithm SHA256 `
    -LiteralPath $buildScript).Hash.ToLowerInvariant()
$androidJar = Join-Path $AndroidSdk 'platforms\android-35\android.jar'
$buildTools = Join-Path $AndroidSdk 'build-tools\35.0.0'
$d8 = Join-Path $buildTools 'd8.bat'
$d8Jar = Join-Path $buildTools 'lib\d8.jar'
$javac = Join-Path $Jdk 'bin\javac.exe'
$java = Join-Path $Jdk 'bin\java.exe'
$jdkRelease = Join-Path $Jdk 'release'
$jdkModules = Join-Path $Jdk 'lib\modules'
$jdkBin = Join-Path $Jdk 'bin'

$expectedFiles = @{
    $source = @('67b4991fdeb6ed385665487af02add44e15be54c7f54b441d5a797d38f9ee148', 48933L)
    $jdkRelease = @('00d3211a59bc9f2577f93962e9210de8578c49fd2625022cb38606817d3a71f9', 1306L)
    $jdkModules = @('81f0e1bb87cd303ddcce2b216e27da416bd20799d9a9811ea1b070123cefff0f', 125748850L)
    $javac = @('ff58ff79e356c4f62e0fdf67af6f71dcc7b8fb63edb5156d3eb064342e2a56a5', 23664L)
    $java = @('9da06bd6c880c0c8d1a63e3716f8ef7996f146c41e6d339e4eafc93df28392f9', 54384L)
    $androidJar = @('4566663c3876e022b4fa4ced8c8697c4ab1688267f090114fd92d027b32e619b', 27092450L)
    $d8 = @('ccc279cdc020fc20cb7889d829b9dc36a462ce4fca8ac713088f6be100b714d0', 3156L)
    $d8Jar = @('305622ad00535684534eb8f742cbf5e628a9abc09d8ea4d39d1babb95bf0cee5', 16614740L)
    $Python = @('b7a12c3af0b4db44191eec14ea095eba731b7328917f570806183093d19ddca2', 107312L)
}

# Filled only after both reviewed Python files exist. Their exact bytes are
# checked before any compiler or packager is launched.
$expectedPackagerSha256 = '53b68403b9d517a123f32c02a25abc48077cc83d0b9a1617ddaac222d2d1c29c'
$expectedTestsSha256 = '7e51b717d5fe2ac3b534af90d2529095429e4aedfd6c6d13a424bd5674062d15'
$expectedInvokerSha256 = 'e736e77a33793e2c2a85b616702a73a88194174dc742fcb086a6be4692b3ce24'
$expectedArtifactSha256 = 'fe0d42d26a8f2a21ee0a14cb88f0f57bee8cd98d5e3abfeaf8e75da4391e09b2'
$expectedDexSha256 = 'ede82ef546ac99cc0a4489fb1b78909ecd3f5d440ff34322cb0cf5677034c097'
$expectedAuthoritySha256 = 'c6d449a492d8b4f99c79608a80be01d3de14ec6f98ad1ca39a3c0b8e9381586c'

function Assert-PinnedFile {
    param(
        [Parameter(Mandatory=$true)][string]$LiteralPath,
        [Parameter(Mandatory=$true)][string]$ExpectedSha256,
        [Parameter(Mandatory=$true)][long]$ExpectedBytes
    )
    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
        throw "Pinned build input is missing: $LiteralPath"
    }
    $item = Get-Item -LiteralPath $LiteralPath -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $item.Length -ne $ExpectedBytes) {
        throw "Pinned build input metadata changed: $LiteralPath"
    }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $LiteralPath).Hash.ToLowerInvariant()
    if ($actual -cne $ExpectedSha256) {
        throw "Pinned build input digest changed: $LiteralPath"
    }
}

function ConvertTo-CanonicalSourceBytes {
    param([Parameter(Mandatory=$true)][byte[]]$Raw)
    foreach ($separator in @(
            [byte[]](0xc2,0x85), [byte[]](0xe2,0x80,0xa8),
            [byte[]](0xe2,0x80,0xa9))) {
        for ($at = 0; $at -le $Raw.Length - $separator.Length; $at++) {
            $match = $true
            for ($offset = 0; $offset -lt $separator.Length; $offset++) {
                if ($Raw[$at + $offset] -ne $separator[$offset]) {$match = $false; break}
            }
            if ($match) { throw 'Pinned source has a Unicode line separator.' }
        }
    }
    $cr = 0
    $lf = 0
    $crlf = 0
    for ($at = 0; $at -lt $Raw.Length; $at++) {
        if ($Raw[$at] -eq 13) {
            $cr++
            if ($at + 1 -lt $Raw.Length -and $Raw[$at + 1] -eq 10) {$crlf++}
        }
        if ($Raw[$at] -eq 10) {$lf++}
    }
    if ($cr -ne 0 -and ($cr -ne $crlf -or $lf -ne $crlf)) {
        throw 'Pinned source has mixed or bare-CR newlines.'
    }
    $decoder = [Text.UTF8Encoding]::new($false, $true)
    $text = $decoder.GetString($Raw)
    if ($cr -ne 0) {$text = $text.Replace("`r`n", "`n")}
    return [Text.UTF8Encoding]::new($false).GetBytes($text)
}

function Get-CanonicalSourceBytes {
    param([Parameter(Mandatory=$true)][string]$LiteralPath)
    return ConvertTo-CanonicalSourceBytes ([IO.File]::ReadAllBytes($LiteralPath))
}

function Assert-PinnedSource {
    param(
        [Parameter(Mandatory=$true)][string]$LiteralPath,
        [Parameter(Mandatory=$true)][string]$ExpectedSha256
    )
    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
        throw "Pinned source is missing: $LiteralPath"
    }
    $item = Get-Item -LiteralPath $LiteralPath -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Pinned source is not an ordinary file: $LiteralPath"
    }
    $canonical = Get-CanonicalSourceBytes -LiteralPath $LiteralPath
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $actual = ([BitConverter]::ToString(
            $hasher.ComputeHash($canonical))).Replace('-','').ToLowerInvariant()
    } finally {$hasher.Dispose()}
    if ($actual -cne $ExpectedSha256) {
        throw "Pinned source digest changed: $LiteralPath"
    }
}

foreach ($entry in $expectedFiles.GetEnumerator()) {
    Assert-PinnedFile -LiteralPath $entry.Key `
        -ExpectedSha256 $entry.Value[0] -ExpectedBytes $entry.Value[1]
}
if ($expectedPackagerSha256 -notmatch '^[0-9a-f]{64}$' -or
        $expectedTestsSha256 -notmatch '^[0-9a-f]{64}$' -or
        $expectedInvokerSha256 -notmatch '^[0-9a-f]{64}$' -or
        $expectedArtifactSha256 -notmatch '^[0-9a-f]{64}$' -or
        $expectedDexSha256 -notmatch '^[0-9a-f]{64}$' -or
        $expectedAuthoritySha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'Reviewed source and final artifact hashes have not been frozen.'
}
Assert-PinnedSource -LiteralPath $packager -ExpectedSha256 $expectedPackagerSha256
Assert-PinnedSource -LiteralPath $tests -ExpectedSha256 $expectedTestsSha256
Assert-PinnedFile -LiteralPath $buildScript `
    -ExpectedSha256 $initialBuildScriptSha256 -ExpectedBytes $initialBuildScriptBytes

$ambientJavaNames = @(
    'CLASSPATH', 'D8_OPTS', 'JAVACMD', 'JAVA_OPTS', 'JAVA_TOOL_OPTIONS',
    'JDK_JAVAC_OPTIONS', 'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS'
)
$savedAmbient = @{}
foreach ($name in $ambientJavaNames) {
    $savedAmbient[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$savedJavaHome = [Environment]::GetEnvironmentVariable('JAVA_HOME', 'Process')
$invokerSourceAuthority = $null
try {
foreach ($name in $ambientJavaNames) {
    Remove-Item "Env:$name" -ErrorAction SilentlyContinue
}
$env:JAVA_HOME = $Jdk
foreach ($name in $ambientJavaNames) {
    if ($null -ne [Environment]::GetEnvironmentVariable($name, 'Process')) {
        throw "Failed to clear ambient Java input: $name"
    }
}

$buildParent = [IO.Path]::GetFullPath((Join-Path $probeRoot 'build'))
if (-not $buildParent.StartsWith($probeRoot, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Refusing build output outside probe root.'
}
$buildRoot = Join-Path $buildParent ('saved-ink-v2-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $buildRoot | Out-Null

# Retain the reviewed wrapper from one exact capture. The retained read handle
# denies writes, deletion and name replacement while each fresh child executes
# that pinned original pathname through `-File`.
$invokerItem = Get-Item -LiteralPath $invoker -Force
if (($invokerItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not (Test-Path -LiteralPath $invoker -PathType Leaf)) {
    throw 'Authenticated invoker is not one ordinary regular file.'
}
$invokerSourceAuthority = [IO.FileStream]::new(
    $invoker, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
if ($invokerSourceAuthority.Length -ne $invokerItem.Length -or
        $invokerSourceAuthority.Length -lt 1 -or
        $invokerSourceAuthority.Length -gt 262144) {
    throw 'Authenticated invoker source size changed during capture.'
}
$invokerRaw = [byte[]]::new([int]$invokerSourceAuthority.Length)
$invokerAt = 0
while ($invokerAt -lt $invokerRaw.Length) {
    $read = $invokerSourceAuthority.Read(
        $invokerRaw, $invokerAt, $invokerRaw.Length - $invokerAt)
    if ($read -le 0) {throw 'Authenticated invoker source was truncated.'}
    $invokerAt += $read
}
$invokerBytes = ConvertTo-CanonicalSourceBytes $invokerRaw
$invokerHasher = [Security.Cryptography.SHA256]::Create()
try {
    $capturedInvokerHash = ([BitConverter]::ToString(
        $invokerHasher.ComputeHash($invokerBytes))).Replace('-','').ToLowerInvariant()
} finally {$invokerHasher.Dispose()}
if ($capturedInvokerHash -cne $expectedInvokerSha256) {
    throw 'Authenticated invoker source differs from reviewed bytes.'
}
function ConvertTo-NativeQuotedArgument([string]$Value) {
    if ($null -eq $Value) {$Value = ''}
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {return $Value}
    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append([char]0x22)
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]0x5c) {
            $slashes++
        } elseif ($character -eq [char]0x22) {
            if ($slashes -gt 0) {[void]$builder.Append([char]0x5c, 2 * $slashes)}
            [void]$builder.Append([char]0x5c)
            [void]$builder.Append([char]0x22)
            $slashes = 0
        } else {
            if ($slashes -gt 0) {[void]$builder.Append([char]0x5c, $slashes); $slashes = 0}
            [void]$builder.Append($character)
        }
    }
    if ($slashes -gt 0) {[void]$builder.Append([char]0x5c, 2 * $slashes)}
    [void]$builder.Append([char]0x22)
    return $builder.ToString()
}

function Invoke-AuthenticatedTool {
    param(
        [Parameter(Mandatory=$true)][string]$Mode,
        [Parameter(Mandatory=$true)][string[]]$Arguments
    )
    $shell = (Get-Process -Id $PID).Path
    $startInfo = [Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $shell
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardInput = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $argumentJson = ConvertTo-Json -Compress -InputObject @($Arguments)
    $encodedArguments = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes($argumentJson))
    $nativeArguments = @(
        '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', $invoker, '-Python', $Python, '-Mode', $Mode,
        '-ProbeRoot', $probeRoot, '-EncodedCommandArguments', $encodedArguments
    )
    if ($null -ne $startInfo.PSObject.Properties['ArgumentList']) {
        foreach ($argument in $nativeArguments) {
            [void]$startInfo.ArgumentList.Add([string]$argument)
        }
    } else {
        $startInfo.Arguments = (@($nativeArguments | ForEach-Object {
            ConvertTo-NativeQuotedArgument ([string]$_)
        }) -join ' ')
    }
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {throw 'Authenticated tool process did not start.'}
        $process.StandardInput.Close()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        [Threading.Tasks.Task]::WaitAll(
            [Threading.Tasks.Task[]]@($stdoutTask, $stderrTask))
        $stdout = $stdoutTask.Result
        $stderr = $stderrTask.Result
        if ($process.ExitCode -ne 0 -or $stderr.Length -ne 0 -or
                -not $stdout.EndsWith("`n", [StringComparison]::Ordinal) -or
                $stdout.Contains("`r") -or
                $stdout.Substring(0, $stdout.Length - 1).Contains("`n")) {
            throw ("Authenticated SavedInk tool failed with exit code " +
                "$($process.ExitCode): stdoutChars=$($stdout.Length) " +
                "stdoutCr=$($stdout.Contains("`r")) " +
                "stdoutLf=$($stdout.Contains("`n")) " +
                "stderrChars=$($stderr.Length): $stderr")
        }
        Write-Host $stdout.Substring(0, $stdout.Length - 1)
    } finally {
        $process.Dispose()
    }
    Assert-PinnedSource -LiteralPath $invoker -ExpectedSha256 $expectedInvokerSha256
    $invokerSourceAuthority.Position = 0
    $retainedInvokerRaw = [byte[]]::new($invokerRaw.Length)
    $retainedAt = 0
    while ($retainedAt -lt $retainedInvokerRaw.Length) {
        $read = $invokerSourceAuthority.Read(
            $retainedInvokerRaw, $retainedAt,
            $retainedInvokerRaw.Length - $retainedAt)
        if ($read -le 0) {throw 'Authenticated invoker source changed after execution.'}
        $retainedAt += $read
    }
    if (-not [Linq.Enumerable]::SequenceEqual(
                [byte[]]$retainedInvokerRaw, [byte[]]$invokerRaw)) {
        throw 'Authenticated invoker source changed during tool execution.'
    }
}

function Invoke-Packager {
    param([Parameter(Mandatory=$true)][string[]]$Arguments)
    Invoke-AuthenticatedTool -Mode 'saved-ink-artifact' -Arguments $Arguments
}

function Invoke-CleanBuild {
    param([Parameter(Mandatory=$true)][string]$PassRoot)
    $classes = Join-Path $PassRoot 'classes'
    $dex = Join-Path $PassRoot 'dex'
    New-Item -ItemType Directory -Path $PassRoot,$classes,$dex | Out-Null

    $javacOutput = & $javac -encoding UTF-8 --release 8 -classpath $androidJar `
        -d $classes $source 2>&1
    $javacExit = $LASTEXITCODE
    foreach ($line in $javacOutput) { Write-Host $line }
    if ($javacExit -ne 0) {
        throw "SavedInkReader javac failed with exit code $javacExit"
    }
    $classJar = Join-Path $PassRoot 'saved-ink-reader-classes.jar'
    Invoke-Packager @('class-jar', '--classes', $classes, '--output', $classJar)

    $d8Output = & $d8 --no-desugaring --min-api 30 --lib $androidJar `
        --output $dex $classJar 2>&1
    $d8Exit = $LASTEXITCODE
    foreach ($line in $d8Output) { Write-Host $line }
    if ($d8Exit -ne 0) {
        throw "SavedInkReader D8 failed with exit code $d8Exit"
    }
    $dexFile = Join-Path $dex 'classes.dex'
    if (-not (Test-Path -LiteralPath $dexFile -PathType Leaf)) {
        throw 'D8 did not create classes.dex.'
    }
    $artifact = Join-Path $PassRoot 'saved-ink-reader-v2.jar'
    Invoke-Packager @(
        'package', '--source', $source, '--classes', $classes,
        '--dex', $dexFile, '--output', $artifact,
        '--jdk-release', $jdkRelease, '--jdk-modules', $jdkModules,
        '--jdk-bin', $jdkBin, '--javac', $javac, '--java', $java,
        '--android-jar', $androidJar, '--d8-launcher', $d8,
        '--d8-jar', $d8Jar, '--python', $Python
    )
    Invoke-Packager @('verify', '--artifact', $artifact)
    Invoke-Packager @(
        'verify-final', '--artifact', $artifact,
        '--expected-artifact-sha256', $expectedArtifactSha256,
        '--expected-dex-sha256', $expectedDexSha256,
        '--expected-authority-sha256', $expectedAuthoritySha256
    )
    return $artifact
}

$first = Invoke-CleanBuild (Join-Path $buildRoot 'pass-1')
$second = Invoke-CleanBuild (Join-Path $buildRoot 'pass-2')
$firstHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $first).Hash.ToLowerInvariant()
$secondHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $second).Hash.ToLowerInvariant()
if ($firstHash -cne $secondHash) {
    throw 'Two clean SavedInkReader builds are not byte-for-byte identical.'
}

$finalArtifact = Join-Path $buildRoot `
    ('saved-ink-reader-v2-' + $expectedFiles[$source][0].Substring(0, 12) + '.jar')
Invoke-Packager @('publish-copy', '--source', $first, '--output', $finalArtifact)
Invoke-Packager @(
    'verify-final', '--artifact', $finalArtifact,
    '--expected-artifact-sha256', $expectedArtifactSha256,
    '--expected-dex-sha256', $expectedDexSha256,
    '--expected-authority-sha256', $expectedAuthoritySha256
)
$provenance = Join-Path $buildRoot 'saved-ink-reader-v2-provenance.json'
Assert-PinnedFile -LiteralPath $buildScript `
    -ExpectedSha256 $initialBuildScriptSha256 -ExpectedBytes $initialBuildScriptBytes
Invoke-Packager @(
    'provenance', '--artifact', $finalArtifact,
    '--repeat', $second, '--output', $provenance,
    '--build-script', $buildScript, '--tests', $tests
)
Invoke-Packager @(
    'verify-provenance', '--artifact', $finalArtifact,
    '--repeat', $second, '--provenance', $provenance,
    '--build-script', $buildScript, '--tests', $tests
)

Invoke-AuthenticatedTool -Mode 'saved-ink-artifact-tests' -Arguments @(
    '--artifact', $finalArtifact, '--repeat', $second,
    '--provenance', $provenance, '--build-script', $buildScript)

# Recheck every external input after both compiles, packaging and tests.
foreach ($entry in $expectedFiles.GetEnumerator()) {
    Assert-PinnedFile -LiteralPath $entry.Key `
        -ExpectedSha256 $entry.Value[0] -ExpectedBytes $entry.Value[1]
}
Assert-PinnedSource -LiteralPath $packager -ExpectedSha256 $expectedPackagerSha256
Assert-PinnedSource -LiteralPath $tests -ExpectedSha256 $expectedTestsSha256
Assert-PinnedSource -LiteralPath $invoker -ExpectedSha256 $expectedInvokerSha256
Assert-PinnedFile -LiteralPath $buildScript `
    -ExpectedSha256 $initialBuildScriptSha256 -ExpectedBytes $initialBuildScriptBytes

$artifactHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $finalArtifact).Hash.ToLowerInvariant()
$dexHash = (Get-FileHash -Algorithm SHA256 `
    -LiteralPath (Join-Path $buildRoot 'pass-1\dex\classes.dex')).Hash.ToLowerInvariant()
Write-Output 'SAVED_INK_READER_DEVICE_ARTIFACT_PASS'
Write-Output "Artifact: $finalArtifact"
Write-Output "Artifact SHA-256: $artifactHash"
Write-Output "DEX SHA-256: $dexHash"
Write-Output "Provenance: $provenance"
} finally {
    if ($null -ne $invokerSourceAuthority) {
        $invokerSourceAuthority.Dispose()
    }
    if ($null -eq $savedJavaHome) {
        Remove-Item 'Env:JAVA_HOME' -ErrorAction SilentlyContinue
    } else {
        [Environment]::SetEnvironmentVariable('JAVA_HOME', $savedJavaHome, 'Process')
    }
    foreach ($name in $ambientJavaNames) {
        if ($null -eq $savedAmbient[$name]) {
            Remove-Item "Env:$name" -ErrorAction SilentlyContinue
        } else {
            [Environment]::SetEnvironmentVariable(
                $name, $savedAmbient[$name], 'Process')
        }
    }
}
