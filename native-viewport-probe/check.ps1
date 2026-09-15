param(
    [Parameter(Mandatory=$true)][string]$Jdk,
    [Parameter(Mandatory=$true)][string]$AndroidJar,
    [Parameter(Mandatory=$true)][string]$JsonJar,
    [Parameter(Mandatory=$true)][string]$Python,
    [Parameter(Mandatory=$true)][string]$PythonPath,
    [string]$Node='node'
)
$ErrorActionPreference='Stop'
$probeRoot=$PSScriptRoot
$repoRoot=Split-Path $probeRoot -Parent
$buildPath=Join-Path $probeRoot ('build/check-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $buildPath | Out-Null
$builderSourceAuthority=$null
$builderSnapshotAuthority=$null

function ConvertTo-CanonicalScriptBytes([byte[]]$Raw) {
    foreach ($separator in @(
            [byte[]](0xc2,0x85), [byte[]](0xe2,0x80,0xa8),
            [byte[]](0xe2,0x80,0xa9))) {
        for ($at=0; $at -le $Raw.Length-$separator.Length; $at++) {
            $match=$true
            for ($offset=0; $offset -lt $separator.Length; $offset++) {
                if ($Raw[$at+$offset] -ne $separator[$offset]) {$match=$false; break}
            }
            if ($match) {throw 'Authenticated script has a Unicode line separator'}
        }
    }
    $cr=0; $lf=0; $crlf=0
    for ($at=0; $at -lt $Raw.Length; $at++) {
        if ($Raw[$at] -eq 13) {
            $cr++
            if ($at+1 -lt $Raw.Length -and $Raw[$at+1] -eq 10) {$crlf++}
        }
        if ($Raw[$at] -eq 10) {$lf++}
    }
    if ($cr -ne 0 -and ($cr -ne $crlf -or $lf -ne $crlf)) {
        throw 'Authenticated script has mixed or bare-CR newlines'
    }
    $text=[Text.UTF8Encoding]::new($false,$true).GetString($Raw)
    if ($cr -ne 0) {$text=$text.Replace("`r`n","`n")}
    return [Text.UTF8Encoding]::new($false).GetBytes($text)
}

function Get-Sha256Lower([byte[]]$Bytes) {
    $hasher=[Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $hasher.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()
    } finally {$hasher.Dispose()}
}

try {
$javac=Join-Path $Jdk 'bin/javac.exe'
$java=Join-Path $Jdk 'bin/java.exe'
$sourceRoot=Join-Path $repoRoot 'native-spread-module/src/com/techrebbe/supernote/spreadprobe/v2'
$sources=@('Affine2D.java','PointD.java','RectD.java') | ForEach-Object { Join-Path $sourceRoot $_ }
$sources+=Join-Path $probeRoot 'java/com/techrebbe/supernote/viewportprobe/ViewportFrame.java'
$sources+=Join-Path $probeRoot 'test/ViewportFrameTest.java'
$sources+=Join-Path $probeRoot 'java/com/techrebbe/supernote/viewportprobe/DisplayProbeLayout.java'
$sources+=Join-Path $probeRoot 'java/com/techrebbe/supernote/viewportprobe/DisplayProbeLifecycle.java'
$sources+=Join-Path $probeRoot 'test/DisplayProbeLayoutTest.java'
& $javac -encoding UTF-8 --release 8 -d $buildPath @sources
if ($LASTEXITCODE -ne 0) {throw 'Viewport contract compilation failed'}
& $java -cp $buildPath ViewportFrameTest
if ($LASTEXITCODE -ne 0) {throw 'Viewport contract tests failed'}
& $java -cp $buildPath DisplayProbeLayoutTest
if ($LASTEXITCODE -ne 0) {throw 'Display surface layout tests failed'}
$savedInkSources=@(
    (Join-Path $probeRoot 'host-stubs/android/graphics/Point.java'),
    (Join-Path $probeRoot 'host-stubs/android/graphics/PointF.java'),
    (Join-Path $probeRoot 'host-stubs/android/graphics/Rect.java'),
    (Join-Path $probeRoot 'java/com/example/libsupernote/GoldenTrailRecord.java'),
    (Join-Path $probeRoot 'java/com/techrebbe/supernote/viewportprobe/SavedInkReader.java'),
    (Join-Path $probeRoot 'test/java/com/techrebbe/supernote/viewportprobe/SavedInkBudgetTest.java')
)
& $javac -encoding UTF-8 --release 8 -classpath $AndroidJar -d $buildPath @savedInkSources
if ($LASTEXITCODE -ne 0) {throw 'Saved-ink diagnostic compilation failed'}
& $java -cp "$buildPath;$JsonJar;$AndroidJar" com.techrebbe.supernote.viewportprobe.SavedInkBudgetTest
if ($LASTEXITCODE -ne 0) {throw 'Saved-ink budget tests failed'}
$golden=Join-Path $buildPath ('saved-ink-java-golden-' + [guid]::NewGuid().ToString('N') + '.json')
$goldenFrame=Join-Path $buildPath ('saved-ink-java-golden-frame-' + [guid]::NewGuid().ToString('N') + '.txt')
& $java -cp "$buildPath;$JsonJar;$AndroidJar" `
    com.techrebbe.supernote.viewportprobe.SavedInkBudgetTest --emit-golden $golden
if ($LASTEXITCODE -ne 0) {throw 'Saved-ink Java golden emission failed'}
& $java -cp "$buildPath;$JsonJar;$AndroidJar" `
    com.techrebbe.supernote.viewportprobe.SavedInkBudgetTest --emit-golden-frame $goldenFrame
if ($LASTEXITCODE -ne 0) {throw 'Saved-ink Java framed golden emission failed'}

# Capture and hash the exact reviewed builder, then retain its original
# FileShare.Read descriptor while a fresh child executes that same path. The
# retained handle denies writes, deletion and name replacement through the
# child build and final Python gate.
$savedInkBuilder=Join-Path $probeRoot 'build-saved-ink-reader.ps1'
$expectedSavedInkBuilderSha256='5e5bf09b002c2dbed900081067f561c3fd25b37064a6de158eb66acf1408823b'
$builderItem=Get-Item -LiteralPath $savedInkBuilder -Force
if (($builderItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        -not (Test-Path -LiteralPath $savedInkBuilder -PathType Leaf) -or
        $builderItem.Length -lt 1 -or $builderItem.Length -gt 262144) {
    throw 'SavedInk builder is not one bounded ordinary file'
}
$builderSourceAuthority=[IO.FileStream]::new(
    $savedInkBuilder,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
if ($builderSourceAuthority.Length -ne $builderItem.Length) {
    throw 'SavedInk builder identity changed during capture'
}
$builderRaw=[byte[]]::new([int]$builderSourceAuthority.Length)
$builderAt=0
while ($builderAt -lt $builderRaw.Length) {
    $read=$builderSourceAuthority.Read(
        $builderRaw,$builderAt,$builderRaw.Length-$builderAt)
    if ($read -le 0) {throw 'SavedInk builder was truncated during capture'}
    $builderAt+=$read
}
$builderSource=ConvertTo-CanonicalScriptBytes $builderRaw
if ((Get-Sha256Lower $builderSource) -cne $expectedSavedInkBuilderSha256) {
    throw 'SavedInk builder differs from the reviewed source authority'
}
$builderSnapshot=$savedInkBuilder

$builderStart=[Diagnostics.ProcessStartInfo]::new()
$builderStart.FileName=(Get-Process -Id $PID).Path
$builderStart.UseShellExecute=$false
$builderStart.CreateNoWindow=$true
$builderStart.RedirectStandardInput=$false
$builderStart.RedirectStandardOutput=$true
$builderStart.RedirectStandardError=$true
if ($savedInkBuilder.Contains('"')) {
    throw 'SavedInk builder path cannot be represented for Windows PowerShell'
}
if ($null -ne $builderStart.PSObject.Properties['ArgumentList']) {
    foreach ($argument in @('-NoLogo','-NoProfile','-NonInteractive',
            '-ExecutionPolicy','Bypass','-File',$savedInkBuilder)) {
        [void]$builderStart.ArgumentList.Add($argument)
    }
} else {
    $builderStart.Arguments =
        '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass ' +
        '-File "' + $savedInkBuilder + '"'
}
$builderStart.EnvironmentVariables['RTL_READER_AUTHENTICATED_PROBE_ROOT']=$probeRoot
$builderStart.EnvironmentVariables['RTL_READER_AUTHENTICATED_BUILD_SOURCE']=$builderSnapshot
$builderStart.EnvironmentVariables['RTL_READER_BUILD_JDK']=$Jdk
$androidSdkForBuilder=Split-Path (
    Split-Path (Split-Path $AndroidJar -Parent) -Parent) -Parent
$expectedAndroidJarForBuilder=Join-Path $androidSdkForBuilder `
    'platforms\android-35\android.jar'
$expectedAndroidJarFull=[IO.Path]::GetFullPath($expectedAndroidJarForBuilder)
$actualAndroidJarFull=[IO.Path]::GetFullPath($AndroidJar)
if (-not [string]::Equals(
        $expectedAndroidJarFull,
        $actualAndroidJarFull,
        [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Android SDK root does not match the exact android.jar contract'
}
$builderStart.EnvironmentVariables['RTL_READER_BUILD_ANDROID_SDK']=$androidSdkForBuilder
$builderStart.EnvironmentVariables['RTL_READER_BUILD_PYTHON']=$Python
$builderProcess=[Diagnostics.Process]::new()
$builderProcess.StartInfo=$builderStart
try {
    if (-not $builderProcess.Start()) {throw 'SavedInk builder process did not start'}
    $builderStdoutTask=$builderProcess.StandardOutput.ReadToEndAsync()
    $builderStderrTask=$builderProcess.StandardError.ReadToEndAsync()
    $builderProcess.WaitForExit()
    [Threading.Tasks.Task]::WaitAll(
        [Threading.Tasks.Task[]]@($builderStdoutTask,$builderStderrTask))
    $builderStdout=$builderStdoutTask.Result
    $builderStderr=$builderStderrTask.Result
    if ($builderProcess.ExitCode -ne 0 -or $builderStderr.Length -ne 0) {
        throw "Authenticated SavedInk builder failed: $builderStderr"
    }
} finally {
    $builderProcess.Dispose()
}
$builderSourceAuthority.Position=0
$builderAfter=[byte[]]::new($builderRaw.Length)
$builderAfterAt=0
while ($builderAfterAt -lt $builderAfter.Length) {
    $read=$builderSourceAuthority.Read(
        $builderAfter,$builderAfterAt,$builderAfter.Length-$builderAfterAt)
    if ($read -le 0) {throw 'SavedInk builder changed after execution'}
    $builderAfterAt+=$read
}
if (-not [Linq.Enumerable]::SequenceEqual(
            [byte[]]$builderRaw,[byte[]]$builderAfter) -or
        (Get-Sha256Lower (ConvertTo-CanonicalScriptBytes (
            [IO.File]::ReadAllBytes($savedInkBuilder)))) -cne
            $expectedSavedInkBuilderSha256 -or
        $builderSourceAuthority.Length -ne $builderRaw.Length) {
    throw 'SavedInk builder authority changed during execution'
}
$builderWire=$builderStdout.Replace("`r`n","`n")
if ($builderWire.Contains("`r") -or -not $builderWire.EndsWith("`n")) {
    throw 'SavedInk builder terminal wire is not uniform newline text'
}
$builderLines=@($builderWire.Substring(0,$builderWire.Length-1).Split("`n"))
if ($builderLines.Count -ne 18) {
    throw 'SavedInk builder terminal inventory changed from exact 18 lines'
}
$expectedBuilderStatuses=@(
    'CLASS_JAR_CREATED','ARTIFACT_CREATED','ARTIFACT_VERIFIED',
    'FINAL_ARTIFACT_VERIFIED','CLASS_JAR_CREATED','ARTIFACT_CREATED',
    'ARTIFACT_VERIFIED','FINAL_ARTIFACT_VERIFIED','COPY_PUBLISHED',
    'FINAL_ARTIFACT_VERIFIED','PROVENANCE_CREATED','PROVENANCE_VERIFIED')
for ($index=0; $index -lt $expectedBuilderStatuses.Count; $index++) {
    try {$record=$builderLines[$index] | ConvertFrom-Json -ErrorAction Stop}
    catch {throw 'SavedInk builder emitted invalid JSON authority'}
    if ($record.status -cne $expectedBuilderStatuses[$index]) {
        throw 'SavedInk builder status sequence changed'
    }
}
if ($builderLines[12] -cne 'SAVED_INK_READER_ARTIFACT_TESTS_PASS tests=12' -or
        $builderLines[13] -cne 'SAVED_INK_READER_DEVICE_ARTIFACT_PASS' -or
        $builderLines[15] -cne ('Artifact SHA-256: ' +
            'fe0d42d26a8f2a21ee0a14cb88f0f57bee8cd98d5e3abfeaf8e75da4391e09b2') -or
        $builderLines[16] -cne ('DEX SHA-256: ' +
            'ede82ef546ac99cc0a4489fb1b78909ecd3f5d440ff34322cb0cf5677034c097') -or
        -not $builderLines[14].StartsWith('Artifact: ',[StringComparison]::Ordinal) -or
        -not $builderLines[17].StartsWith('Provenance: ',[StringComparison]::Ordinal)) {
    throw 'SavedInk builder final authority inventory changed'
}
$savedInkDeviceArtifact=$builderLines[14].Substring('Artifact: '.Length)
$savedInkProvenance=$builderLines[17].Substring('Provenance: '.Length)
$savedInkBuildRoot=Split-Path $savedInkDeviceArtifact -Parent
$savedInkRepeatArtifact=Join-Path $savedInkBuildRoot 'pass-2\saved-ink-reader-v2.jar'
$hostSourceRoot=Join-Path $probeRoot 'display-host/src'
$hostSources=@(
    (Join-Path $hostSourceRoot 'com/techrebbe/supernote/viewportdisplayprobe/CalibrationActivity.java'),
    (Join-Path $hostSourceRoot 'com/techrebbe/supernote/viewportdisplayprobe/DisplayProbeActivity.java')
)
$discoveredHostSources=@(Get-ChildItem -LiteralPath $hostSourceRoot -Recurse -File -Filter '*.java' |
    ForEach-Object FullName)
$hostSourceDifference=@(Compare-Object ($hostSources | Sort-Object) ($discoveredHostSources | Sort-Object))
if ($hostSourceDifference.Count -ne 0) {
    throw 'Display-host Java source inventory differs from the exact two-file allowlist'
}
& $javac -encoding UTF-8 --release 8 -classpath "$AndroidJar;$buildPath" -d $buildPath @hostSources
if ($LASTEXITCODE -ne 0) {throw 'Display-only Android host compilation failed'}
$resolvedPythonPath=(Resolve-Path -LiteralPath $PythonPath -ErrorAction Stop).Path
$gatePath=Join-Path $probeRoot 'pinned_elftools_gate.py'
$expectedGateSha256='ff7021874c16321f71b4309e131d78061d0d71c4cd6d14743574fc4eb229cd2f'
$gateBootstrap=@'
import hashlib, os, stat, sys, types

def fail():
    raise SystemExit(126)

def identity(value):
    fields = (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
              value.st_size, value.st_mtime_ns,
              getattr(value, "st_file_attributes", 0))
    return fields + ((value.st_ctime_ns,) if os.name == "posix" else ())

def capture(path, expected, limit):
    descriptor = None
    try:
        named = os.lstat(path)
        if (not stat.S_ISREG(named.st_mode) or
                getattr(named, "st_file_attributes", 0) & 0x400 or
                named.st_size < 1 or named.st_size > limit):
            fail()
        flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
                 getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0))
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or
                getattr(opened, "st_file_attributes", 0) & 0x400 or
                identity(opened) != identity(named)):
            fail()
        chunks = []
        remaining = opened.st_size + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        final_named = os.lstat(path)
        if (len(raw) != opened.st_size or identity(after) != identity(opened) or
                identity(final_named) != identity(opened)):
            fail()
    except (OSError, OverflowError, TypeError, ValueError):
        fail()
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                fail()
    if any(separator in raw for separator in (
            b"\xc2\x85", b"\xe2\x80\xa8", b"\xe2\x80\xa9")):
        fail()
    if b"\r" in raw:
        if raw.count(b"\r") != raw.count(b"\r\n") or raw.count(b"\n") != raw.count(b"\r\n"):
            fail()
        raw = raw.replace(b"\r\n", b"\n")
    if hashlib.sha256(raw).hexdigest() != expected:
        fail()
    return raw

gate_path, expected_digest, limit_text = sys.argv[1:4]
try:
    gate_limit = int(limit_text)
except ValueError:
    fail()
if gate_limit != 65536:
    fail()
gate_source = capture(gate_path, expected_digest, gate_limit)
sys.argv = [gate_path] + sys.argv[4:]
main = types.ModuleType("__main__")
main.__file__ = gate_path
main.__package__ = ""
main._rtl_reader_authenticated_gate_source = gate_source
sys.modules["__main__"] = main
exec(compile(gate_source, gate_path, "exec", dont_inherit=True),
     main.__dict__, main.__dict__)
'@
$gateBootstrapBytes=[Text.UTF8Encoding]::new($false).GetBytes($gateBootstrap)
$gateBootstrapEncoded=[Convert]::ToBase64String($gateBootstrapBytes)
$gateTransport="import base64;exec(compile(base64.b64decode('$gateBootstrapEncoded'),'<authenticated-gate-bootstrap>','exec'))"
$expectedProbeSha256='07e205bc314fc1cdbbc23fa58391b2f5450cdda791d83c08e32651a74f8e300b'
$savedErrorActionPreference=$ErrorActionPreference
$ErrorActionPreference='Continue'
try {
    $testOutput=@(& $Python -I -S -E -s -c $gateTransport `
        $gatePath $expectedGateSha256 65536 `
        --python-path $resolvedPythonPath --probe-root $probeRoot `
        --expected-probe-sha256 $expectedProbeSha256 `
        --saved-ink-raw-golden $golden --saved-ink-frame-golden $goldenFrame `
        --saved-ink-device-artifact $savedInkDeviceArtifact `
        --saved-ink-repeat-artifact $savedInkRepeatArtifact `
        --saved-ink-provenance $savedInkProvenance `
        --saved-ink-build-script $builderSnapshot 2>&1)
    $testExit=$LASTEXITCODE
} finally {
    $ErrorActionPreference=$savedErrorActionPreference
}
$testOutput | ForEach-Object { Write-Output $_ }
if ($testExit -ne 0) {throw 'Evidence validation tests failed'}

$ran=@($testOutput | Where-Object {
    [string]$_ -cmatch '^Ran 234 tests in [0-9]+(?:\.[0-9]+)?s$'
})
if ($ran.Count -ne 1) {throw 'Evidence validation test count changed from required 234'}
$terminal=@($testOutput | Where-Object { [string]$_ -ceq 'OK (skipped=20)' })
if ($terminal.Count -ne 1) {throw 'Evidence validation terminal result is not exact'}
$skipReasons=@($testOutput | ForEach-Object {
    $line=[string]$_
    if ($line -match " skipped '([^']+)'$") { $Matches[1] }
})
$expectedSkipReasons=@(
        'POSIX package-name replacement fault',
        'POSIX same-content name ABA fault',
        'POSIX partial-publication preservation',
        'POSIX post-link rollback race',
        'POSIX original-inode name ABA fault',
        'POSIX retained-parent swap',
        'POSIX process-group contract',
        'POSIX child-reaper contract',
        'POSIX nonblocking-pipe contract',
        'POSIX nonblocking authenticated-runner open',
        'POSIX nonblocking source-open races',
        'POSIX no-follow source-open race',
        'POSIX permits an OS-backed same-inode mutation',
        'POSIX outer-supervision contract',
        'POSIX no-follow ancestor walk',
        'Linux immutable memfd contract',
        'Linux post-fork cleanup fault',
        'Linux pre-exec deadline gate',
        'POSIX signal-fault retirement',
        'POSIX retained-directory authority'
)
$actualSkipWire=($skipReasons | Sort-Object -CaseSensitive) -join "`n"
$expectedSkipWire=($expectedSkipReasons | Sort-Object -CaseSensitive) -join "`n"
if ($skipReasons.Count -ne $expectedSkipReasons.Count -or
        $actualSkipWire -cne $expectedSkipWire) {
    throw 'Evidence validation skip set differs from the 20 required platform-only gates'
}
$pinnedParser='PINNED_ELFTOOLS {"files":54,"sha256":"09679ad9ea7781df8fe3ef1d39b2189261f57967e06c549ce2891b977018382a","version":"0.32"}'
$pinnedProbe='PINNED_PROBE_SOURCES {"files":15,"sha256":"07e205bc314fc1cdbbc23fa58391b2f5450cdda791d83c08e32651a74f8e300b"}'
if (@($testOutput | Where-Object { [string]$_ -ceq $pinnedParser }).Count -ne 1 -or
        @($testOutput | Where-Object { [string]$_ -ceq $pinnedProbe }).Count -ne 1) {
    throw 'Evidence validation did not execute the exact authenticated source snapshots'
}
$pinnedSavedInk='PINNED_SAVED_INK_GOLDEN {"frameBytes":2562,"payloadBytes":2532,"payloadSha256":"20a179534dfce744b9be97e8e40c1ab07ef19e1c1ddb618ed38f58002e648158"}'
if (@($testOutput | Where-Object {
        [string]$_ -ceq $pinnedSavedInk
    }).Count -ne 1) {
    throw 'Evidence validation did not authenticate the Java raw/framed saved-ink golden'
}
$expectedSavedInkProvenanceSha256=
    'c34c4aa5d8af8efbff4235ae2bc40a1473fc75e7644bcd60503974ce26234618'
$pinnedSavedInkArtifact='PINNED_SAVED_INK_DEVICE_ARTIFACT ' +
    '{"artifactBytes":37578,' +
    '"artifactSha256":"fe0d42d26a8f2a21ee0a14cb88f0f57bee8cd98d5e3abfeaf8e75da4391e09b2",' +
    '"authoritySha256":"c6d449a492d8b4f99c79608a80be01d3de14ec6f98ad1ca39a3c0b8e9381586c",' +
    '"buildScriptSha256":"' + $expectedSavedInkBuilderSha256 + '",' +
    '"dexBytes":31108,' +
    '"dexSha256":"ede82ef546ac99cc0a4489fb1b78909ecd3f5d440ff34322cb0cf5677034c097",' +
    '"provenanceSha256":"' + $expectedSavedInkProvenanceSha256 + '",' +
    '"tests":12,"twoCleanBuildsByteIdentical":true}'
if (@($testOutput | Where-Object {
        [string]$_ -ceq $pinnedSavedInkArtifact
    }).Count -ne 1) {
    throw 'Evidence validation did not authenticate the schema-v2 SavedInk artifact'
}
& $Node (Join-Path $probeRoot 'test_pen_boundary_snapshot.js')
if ($LASTEXITCODE -ne 0) {throw 'Pen-boundary observation tests failed'}
Write-Output 'HOST CHECKS PASS. Not a hardware/collector/viewport readiness claim.'
} finally {
    if ($null -ne $builderSnapshotAuthority) {$builderSnapshotAuthority.Dispose()}
    if ($null -ne $builderSourceAuthority) {$builderSourceAuthority.Dispose()}
}
