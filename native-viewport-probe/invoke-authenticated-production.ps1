param(
    [Parameter(Mandatory=$true)][string]$Python,
    [Parameter(Mandatory=$true)]
    [ValidateSet('display-inspect','display-verify','ink-oracle',
        'saved-ink-artifact','saved-ink-artifact-tests')]
    [string]$Mode,
    [string[]]$CommandArguments=@(),
    [string]$EncodedCommandArguments,
    [string]$ProbeRoot
)
$ErrorActionPreference='Stop'
if ($PSBoundParameters.ContainsKey('EncodedCommandArguments')) {
    try {
        if ($PSBoundParameters.ContainsKey('CommandArguments')) {
            throw 'mutually exclusive argument transports'
        }
        $argumentBytes = [Convert]::FromBase64String($EncodedCommandArguments)
        $argumentText = [Text.UTF8Encoding]::new($false, $true).GetString($argumentBytes)
        if ($argumentText -notmatch '^\[.*\]$') {
            throw 'encoded argument wire is not one JSON array'
        }
        if ($argumentText -ceq '[]') {
            $parsedArguments = [object[]]@()
        } else {
            $parsedValue = $argumentText | ConvertFrom-Json -ErrorAction Stop
            if ($parsedValue -isnot [Array]) {
                throw 'encoded argument wire is not one JSON array'
            }
            $parsedArguments = [object[]]$parsedValue
        }
        if (@($parsedArguments | Where-Object {$_ -isnot [string]}).Count -ne 0) {
            throw 'encoded arguments contain a non-string'
        }
        $CommandArguments = [string[]]$parsedArguments
    } catch {
        [Console]::Error.Write("AUTHENTICATED_PRODUCTION_WRAPPER_FAILED`n")
        exit 126
    }
}
$probeRoot=[IO.Path]::GetFullPath($(if ($ProbeRoot) {$ProbeRoot} else {$PSScriptRoot}))
$launcherPath=Join-Path $probeRoot 'production-launch/authenticated_launcher.py'
$expectedLauncherSha256='6c82a5c6e30e87eb957b713faa47691792ab13388ec41a882e006b0919c85212'
$bootstrap=@'
import contextlib, hashlib, io, os, stat, sys, types

FAIL = 126

def stop():
    raise RuntimeError("authenticated production bootstrap failed")

def canonical_source(raw):
    if any(separator in raw for separator in (
            b"\xc2\x85", b"\xe2\x80\xa8", b"\xe2\x80\xa9")):
        stop()
    if b"\r" not in raw:
        return raw
    if (raw.count(b"\r") != raw.count(b"\r\n") or
            raw.count(b"\n") != raw.count(b"\r\n")):
        stop()
    return raw.replace(b"\r\n", b"\n")

def identity(value):
    fields = (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
              value.st_size, value.st_mtime_ns,
              getattr(value, "st_file_attributes", 0))
    return fields + ((value.st_ctime_ns,) if os.name == "posix" else ())

def read_exact(descriptor, size):
    if type(size) is not int or not 0 < size <= 262144:
        stop()
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks = []
    remaining = size + 1
    while remaining:
        chunk = os.read(descriptor, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    if len(raw) != size:
        stop()
    return raw

def close_ambient_descriptors():
    if os.name == "posix" and os.path.isdir("/proc/self/fd"):
        candidates = []
        for name in os.listdir("/proc/self/fd"):
            if name.isascii() and name.isdecimal():
                candidates.append(int(name))
    else:
        candidates = range(3, 2048)
    for candidate in candidates:
        if candidate <= 2:
            continue
        try:
            os.close(candidate)
        except OSError:
            pass

def write_all(descriptor, payload):
    at = 0
    while at < len(payload):
        written = os.write(descriptor, payload[at:])
        if written <= 0:
            raise OSError("terminal write made no progress")
        at += written

def neutralize_terminal(descriptor, attribute):
    try:
        null_descriptor = os.open(os.devnull, os.O_WRONLY)
        if null_descriptor != descriptor:
            os.dup2(null_descriptor, descriptor)
            os.close(null_descriptor)
    except OSError:
        pass
    # The original TextIOWrapper never receives production output, but replace
    # it as well so interpreter shutdown cannot retry a failed inherited pipe.
    try:
        setattr(sys, attribute, io.StringIO())
    except BaseException:
        pass

descriptor = None
stdout = io.StringIO()
stderr = io.StringIO()
code = FAIL
publication_uncertain = False
publication_capable = False
mode = None
try:
    if len(sys.argv) < 6:
        stop()
    launcher_path, expected, limit_text, root, mode = sys.argv[1:6]
    if (len(expected) != 64 or
            any(character not in "0123456789abcdef" for character in expected) or
            limit_text != "262144" or
            mode not in ("display-inspect", "display-verify", "ink-oracle",
                         "saved-ink-artifact", "saved-ink-artifact-tests")):
        stop()
    publication_capable = (
        mode == "display-inspect" or
        (mode == "saved-ink-artifact" and len(sys.argv) > 6 and
         sys.argv[6] in ("class-jar", "package", "publish-copy", "provenance"))
    )
    close_ambient_descriptors()
    named = os.lstat(launcher_path)
    if (not stat.S_ISREG(named.st_mode) or
            getattr(named, "st_file_attributes", 0) & 0x400 or
            not 0 < named.st_size <= 262144):
        stop()
    flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) |
             getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) |
             getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0))
    descriptor = os.open(launcher_path, flags)
    os.set_inheritable(descriptor, False)
    if os.get_inheritable(descriptor):
        stop()
    opened = os.fstat(descriptor)
    if (not stat.S_ISREG(opened.st_mode) or identity(opened) != identity(named)):
        stop()
    file_bytes = read_exact(descriptor, opened.st_size)
    source = canonical_source(file_bytes)
    if (hashlib.sha256(source).hexdigest() != expected or
            identity(os.fstat(descriptor)) != identity(opened) or
            identity(os.lstat(launcher_path)) != identity(opened)):
        stop()

    # No caller-controlled frame or interactive input survives into production
    # code.  Project source is the retained exact capture above and in stage 2.
    null_descriptor = os.open(os.devnull, os.O_RDONLY)
    if null_descriptor != 0:
        os.dup2(null_descriptor, 0)
        os.close(null_descriptor)
    sys.stdin = open(0, "r", encoding="utf-8", closefd=False)
    sys.argv = [launcher_path, mode, root, *sys.argv[6:]]
    main = types.ModuleType("__main__")
    main.__file__ = launcher_path
    main.__package__ = ""
    main._authenticated_production_launcher_source = source
    sys.modules["__main__"] = main
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exec(compile(source, launcher_path, "exec", dont_inherit=True),
                 main.__dict__, main.__dict__)
    except SystemExit as result:
        code = result.code if type(result.code) is int else FAIL
    except BaseException:
        code = FAIL
    publication_uncertain = publication_capable and code in (0, 2)

    # Retain the bootstrap's own source authority through the entire command.
    if (identity(os.fstat(descriptor)) != identity(opened) or
            identity(os.lstat(launcher_path)) != identity(opened) or
            read_exact(descriptor, opened.st_size) != file_bytes):
        stop()
    if code not in (0, 1, 2, FAIL):
        stop()
except BaseException:
    code = 2 if publication_uncertain else FAIL
    stdout = io.StringIO()
    stderr = io.StringIO()
    stderr.write("PACKAGED_PUBLICATION_REVIEW_REQUIRED\n" if publication_uncertain
                 else "AUTHENTICATED_PRODUCTION_BOOTSTRAP_FAILED\n")
finally:
    if descriptor is not None:
        try:
            os.close(descriptor)
        except OSError:
            publication_uncertain = publication_uncertain or (
                publication_capable and code in (0, 2))
            code = 2 if publication_uncertain else FAIL
            stdout = io.StringIO()
            stderr = io.StringIO()
            stderr.write("PACKAGED_PUBLICATION_REVIEW_REQUIRED\n" if publication_uncertain
                         else "AUTHENTICATED_PRODUCTION_BOOTSTRAP_FAILED\n")

try:
    write_all(1, stdout.getvalue().encode("utf-8"))
    write_all(2, stderr.getvalue().encode("utf-8"))
except (OSError, UnicodeError, ValueError):
    code = 2 if publication_uncertain else FAIL
    neutralize_terminal(1, "stdout")
    neutralize_terminal(2, "stderr")
raise SystemExit(code)
'@

function ConvertTo-NativeQuotedArgument([string]$Value) {
    if ($null -eq $Value) {$Value=''}
    if ($Value.Length -gt 0 -and $Value -notmatch '[\s"]') {
        return $Value
    }
    $builder=[Text.StringBuilder]::new()
    [void]$builder.Append([char]0x22)
    $slashes=0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]0x5c) {
            $slashes++
        } elseif ($character -eq [char]0x22) {
            if ($slashes -gt 0) {
                [void]$builder.Append([char]0x5c, (2 * $slashes))
            }
            [void]$builder.Append([char]0x5c)
            [void]$builder.Append([char]0x22)
            $slashes=0
        } else {
            if ($slashes -gt 0) {
                [void]$builder.Append([char]0x5c, $slashes)
                $slashes=0
            }
            [void]$builder.Append($character)
        }
    }
    if ($slashes -gt 0) {
        [void]$builder.Append([char]0x5c, (2 * $slashes))
    }
    [void]$builder.Append([char]0x22)
    return $builder.ToString()
}

$startInfo=[Diagnostics.ProcessStartInfo]::new()
$startInfo.FileName=$Python
$startInfo.UseShellExecute=$false
$startInfo.CreateNoWindow=$true
$startInfo.RedirectStandardInput=$true
$startInfo.RedirectStandardOutput=$true
$startInfo.RedirectStandardError=$true
$nativeArguments=@(
    '-I', '-S', '-E', '-s', '-c', $bootstrap,
    $launcherPath, $expectedLauncherSha256, '262144', $probeRoot, $Mode
) + @($CommandArguments)
if ($null -ne $startInfo.PSObject.Properties['ArgumentList']) {
    foreach ($argument in $nativeArguments) {
        [void]$startInfo.ArgumentList.Add([string]$argument)
    }
} else {
    $startInfo.Arguments=(@($nativeArguments | ForEach-Object {
        ConvertTo-NativeQuotedArgument ([string]$_)
    }) -join ' ')
}

$process=$null
$stdoutBuffer=$null
$stderrBuffer=$null
$stdoutBytes=[byte[]]::new(0)
$stderrBytes=[byte[]]::new(0)
$exitCode=126
$started=$false
$publicationCapable=($Mode -eq 'display-inspect' -or
    ($Mode -eq 'saved-ink-artifact' -and $CommandArguments.Count -gt 0 -and
        $CommandArguments[0] -in @('class-jar','package','publish-copy','provenance')))
try {
    $process=[Diagnostics.Process]::new()
    $process.StartInfo=$startInfo
    if (-not $process.Start()) {throw 'Authenticated Python process did not start'}
    $started=$true
    $process.StandardInput.Close()
    $stdoutBuffer=[IO.MemoryStream]::new()
    $stderrBuffer=[IO.MemoryStream]::new()
    $stdoutTask=$process.StandardOutput.BaseStream.CopyToAsync($stdoutBuffer)
    $stderrTask=$process.StandardError.BaseStream.CopyToAsync($stderrBuffer)
    $process.WaitForExit()
    [Threading.Tasks.Task]::WaitAll(
        [Threading.Tasks.Task[]]@($stdoutTask, $stderrTask))
    $exitCode=$process.ExitCode
    if ($exitCode -notin @(0, 1, 2, 126)) {
        throw 'Authenticated Python process returned an invalid status'
    }
    $stdoutBytes=$stdoutBuffer.ToArray()
    $stderrBytes=$stderrBuffer.ToArray()
} catch {
    $stdoutBytes=[byte[]]::new(0)
    if ($publicationCapable -and $started) {
        $exitCode=2
        $stderrBytes=[Text.Encoding]::UTF8.GetBytes(
            "PACKAGED_PUBLICATION_REVIEW_REQUIRED`n")
    } else {
        $exitCode=126
        $stderrBytes=[Text.Encoding]::UTF8.GetBytes(
            "AUTHENTICATED_PRODUCTION_WRAPPER_FAILED`n")
    }
} finally {
    if ($stdoutBuffer -ne $null) {$stdoutBuffer.Dispose()}
    if ($stderrBuffer -ne $null) {$stderrBuffer.Dispose()}
    if ($process -ne $null) {$process.Dispose()}
}

function Open-CheckedStandardOutput([IO.Stream]$ConsoleStream) {
    $fields=@()
    $type=$ConsoleStream.GetType()
    while ($null -ne $type) {
        $candidate=$type.GetField('_handle',
            [Reflection.BindingFlags]'Instance,NonPublic')
        if ($null -ne $candidate) {$fields+=@($candidate)}
        $type=$type.BaseType
    }
    if ($fields.Count -ne 1) {
        throw 'Standard terminal handle authority is unavailable'
    }
    $stored=$fields[0].GetValue($ConsoleStream)
    if ($stored -is [Microsoft.Win32.SafeHandles.SafeFileHandle]) {
        if ($stored.IsInvalid -or $stored.IsClosed) {
            throw 'Standard terminal handle is invalid'
        }
        $handle=$stored.DangerousGetHandle()
    } elseif ($stored -is [IntPtr]) {
        $handle=[IntPtr]$stored
    } else {
        throw 'Standard terminal handle type is unsupported'
    }
    if ($handle -eq [IntPtr]::Zero -or $handle -eq [IntPtr](-1)) {
        throw 'Standard terminal handle is invalid'
    }
    $borrowed=[Microsoft.Win32.SafeHandles.SafeFileHandle]::new($handle,$false)
    try {
        return [IO.FileStream]::new(
            $borrowed,[IO.FileAccess]::Write,4096,$false)
    } catch {
        $borrowed.Dispose()
        throw
    }
}

try {
    $stdoutConsole=[Console]::OpenStandardOutput()
    $stderrConsole=[Console]::OpenStandardError()
    $stdoutStream=Open-CheckedStandardOutput $stdoutConsole
    $stderrStream=Open-CheckedStandardOutput $stderrConsole
    if ($stdoutBytes.Length -gt 0) {
        $stdoutStream.Write($stdoutBytes, 0, $stdoutBytes.Length)
        $stdoutStream.Flush()
    }
    if ($stderrBytes.Length -gt 0) {
        $stderrStream.Write($stderrBytes, 0, $stderrBytes.Length)
        $stderrStream.Flush()
    }
} catch {
    $exitCode=if ($publicationCapable -and $started -and
        $exitCode -in @(0, 2)) {2} else {126}
} finally {
    if ($null -ne $stdoutStream) {$stdoutStream.Dispose()}
    if ($null -ne $stderrStream) {$stderrStream.Dispose()}
}
exit $exitCode
