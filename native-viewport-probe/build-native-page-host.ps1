param(
    [Parameter(Mandatory=$true)][string]$Jdk,
    [Parameter(Mandatory=$true)][string]$AndroidSdk,
    [Parameter(Mandatory=$true)][string]$Python,
    [string]$CanonicalTextPolicySelfTestOutput=''
)

$ErrorActionPreference='Stop'

# Neither JVM launch hooks nor Python import/startup policy may come from the
# caller. Reject every nonempty Python-prefixed variable (including future
# site/startup knobs) plus the JVM's documented injection/classpath variables.
$forbiddenInheritedEnvironment=@('JAVA_TOOL_OPTIONS','_JAVA_OPTIONS',
    'JDK_JAVA_OPTIONS','JDK_JAVAC_OPTIONS','JAVA_OPTIONS','CLASSPATH')
foreach ($entry in [Environment]::GetEnvironmentVariables('Process').GetEnumerator()) {
    $name=[string]$entry.Key
    $value=[string]$entry.Value
    if ($value.Length -gt 0 -and ($forbiddenInheritedEnvironment -ccontains $name.ToUpperInvariant() `
            -or $name.StartsWith('PYTHON',[StringComparison]::OrdinalIgnoreCase))) {
        throw "Inherited build-process injection environment is forbidden: $name"
    }
}

function Get-BytesSha256([byte[]]$payload) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($payload))).Replace('-','').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

# Canonical text evidence is strict UTF-8 without BOM, contains no NUL, uses
# LF only, and ends in exactly one LF. Input may use all-LF or all-CRLF, but a
# lone CR or mixed newline form is rejected rather than silently repaired.
function ConvertTo-CanonicalEvidenceUtf8([byte[]]$payload,[string]$label) {
    if ($null -eq $payload -or $payload.Length -eq 0) { throw "$label is empty" }
    if ($payload.Length -ge 3 -and $payload[0] -eq 0xef -and $payload[1] -eq 0xbb `
            -and $payload[2] -eq 0xbf) {
        throw "$label contains a UTF-8 BOM"
    }
    $utf8=[Text.UTF8Encoding]::new($false,$true)
    try { $text=$utf8.GetString($payload) }
    catch { throw "$label is not strict UTF-8" }
    if ($text.IndexOf([char]0) -ge 0) { throw "$label contains an embedded NUL" }
    $hasCrLf=$text.Contains("`r`n")
    $withoutCrLf=$text.Replace("`r`n",'')
    if ($withoutCrLf.Contains("`r")) { throw "$label contains a lone CR" }
    if ($hasCrLf -and $withoutCrLf.Contains("`n")) {
        throw "$label mixes LF and CRLF newlines"
    }
    $body=$text.Replace("`r`n","`n").TrimEnd([char[]]@([char]10))
    if ($body.Length -eq 0) { throw "$label contains no evidence text" }
    $canonical=$utf8.GetBytes($body + "`n")
    if (($canonical.Length -ge 3 -and $canonical[0] -eq 0xef -and $canonical[1] -eq 0xbb `
            -and $canonical[2] -eq 0xbf) -or $canonical[-1] -ne 10 `
            -or ($canonical.Length -gt 1 -and $canonical[-2] -eq 10) `
            -or $canonical.Contains([byte]13) -or $canonical.Contains([byte]0)) {
        throw "$label canonical byte policy failed"
    }
    return ,$canonical
}

function Write-NewBytes([string]$path,[byte[]]$payload) {
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,
        [IO.FileShare]::None)
    try { $stream.Write($payload,0,$payload.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
}

function Invoke-CanonicalTextPolicySelfTest([string]$outputPath) {
    $expected=[byte[]](0x61,0x6c,0x70,0x68,0x61,0x0a,0xce,0xb2,0x0a)
    $expectedSha='4cce75f4e4dcdd0119627d7674ef7747a4634666bcb9b13e29cf0e4742ad9803'
    $lf=ConvertTo-CanonicalEvidenceUtf8 $expected 'self-test LF'
    $crlf=ConvertTo-CanonicalEvidenceUtf8 `
        ([byte[]](0x61,0x6c,0x70,0x68,0x61,0x0d,0x0a,0xce,0xb2,0x0d,0x0a,
            0x0d,0x0a)) 'self-test CRLF'
    if ([Convert]::ToBase64String($lf) -cne 'YWxwaGEKzrIK' `
            -or [Convert]::ToBase64String($crlf) -cne 'YWxwaGEKzrIK' `
            -or (Get-BytesSha256 $lf) -cne $expectedSha `
            -or (Get-BytesSha256 $crlf) -cne $expectedSha) {
        throw 'canonical UTF-8 self-test digest differed'
    }
    $rejected=@(
        [byte[]](0xef,0xbb,0xbf,0x61,0x0a),
        [byte[]](0xc3,0x28),
        [byte[]](0x61,0x00,0x0a),
        [byte[]](0x61,0x0d,0x62),
        [byte[]](0x61,0x0d,0x0a,0x62,0x0a)
    )
    foreach ($candidate in $rejected) {
        $failed=$false
        try { ConvertTo-CanonicalEvidenceUtf8 $candidate 'self-test rejection' | Out-Null }
        catch { $failed=$true }
        if (-not $failed) { throw 'canonical UTF-8 self-test accepted invalid bytes' }
    }
    $wire=[Text.Encoding]::ASCII.GetBytes(
        "CANONICAL_TEXT_POLICY_V1 sha256=$expectedSha base64=YWxwaGEKzrIK bytes=9`n")
    Write-NewBytes $outputPath $wire
}

if ($CanonicalTextPolicySelfTestOutput.Length -gt 0) {
    Invoke-CanonicalTextPolicySelfTest $CanonicalTextPolicySelfTestOutput
    return
}

# This is an integrity relation to the already-parsed, caller-reviewed root,
# not a circular claim that a script authenticates itself. A changed disk policy
# must not become the authority for the later cross-engine evidence children.
$parsedBuildPolicyText=$MyInvocation.MyCommand.ScriptBlock.ToString()
$probeRoot=$PSScriptRoot
$hostRoot=Join-Path $probeRoot 'native-page-host'
$androidJar=Join-Path $AndroidSdk 'platforms/android-35/android.jar'
$buildTools=Join-Path $AndroidSdk 'build-tools/35.0.0'
$javac=Join-Path $Jdk 'bin/javac.exe'
$javap=Join-Path $Jdk 'bin/javap.exe'
$java=Join-Path $Jdk 'bin/java.exe'
$d8=Join-Path $buildTools 'd8.bat'
$d8Jar=Join-Path $buildTools 'lib/d8.jar'
$aapt=Join-Path $buildTools 'aapt.exe'
$zipalign=Join-Path $buildTools 'zipalign.exe'
$jdkRelease=Join-Path $Jdk 'release'
$jdkModules=Join-Path $Jdk 'lib/modules'
$jvmDll=Join-Path $Jdk 'bin/server/jvm.dll'
$pythonDll=Join-Path (Split-Path -Parent $Python) 'python312.dll'
$pythonRoot=Split-Path -Parent $Python
$pythonLib=Join-Path $pythonRoot 'Lib'
$pythonDlls=Join-Path $pythonRoot 'DLLs'
$powershell5Source='C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$runtimeDependenciesRoot=Split-Path -Parent $pythonRoot
$powershell7=Join-Path $runtimeDependenciesRoot 'native\powershell\pwsh.exe'

foreach ($required in @($androidJar,$javac,$javap,$java,$d8,$d8Jar,$aapt,$zipalign,
        $jdkRelease,$jdkModules,$jvmDll,$Python,$pythonDll,$powershell5Source,$powershell7)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required build tool missing: $required"
    }
}
foreach ($requiredDirectory in @($pythonLib,$pythonDlls)) {
    if (-not (Test-Path -LiteralPath $requiredDirectory -PathType Container)) {
        throw "Required build runtime directory missing: $requiredDirectory"
    }
}

function Assert-PinnedHash([string]$path,[string]$expected,[string]$label) {
    $actual=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $expected) { throw "$label differs from pinned toolchain authority: $actual" }
    return $actual
}

# Retain each exact tool/runtime file before its first hash or execution. On
# Windows FileShare.Read denies write/delete/rename while still allowing the
# operating system and child processes to read or execute the admitted file.
$toolLocks=New-Object 'System.Collections.Generic.List[System.IDisposable]'
$snapshotLocks=$null
$artifactLocks=$null
try {
foreach ($tool in @($androidJar,$javac,$javap,$java,$d8,$d8Jar,$aapt,$zipalign,
        $jdkRelease,$jdkModules,$jvmDll,$Python,$pythonDll,$powershell5Source,$powershell7)) {
    $toolLocks.Add([IO.File]::Open($tool,[IO.FileMode]::Open,[IO.FileAccess]::Read,
        [IO.FileShare]::Read))
}

$toolHashes=[ordered]@{
    androidJar=Assert-PinnedHash $androidJar '4566663c3876e022b4fa4ced8c8697c4ab1688267f090114fd92d027b32e619b' 'android.jar'
    java=Assert-PinnedHash $java '9da06bd6c880c0c8d1a63e3716f8ef7996f146c41e6d339e4eafc93df28392f9' 'java.exe'
    javac=Assert-PinnedHash $javac 'ff58ff79e356c4f62e0fdf67af6f71dcc7b8fb63edb5156d3eb064342e2a56a5' 'javac.exe'
    javap=Assert-PinnedHash $javap 'bd5a9f99365fd432f79162f4ed9ca9b956c78cc81dfb6962adb6d207075711fb' 'javap.exe'
    jdkRelease=Assert-PinnedHash $jdkRelease '00d3211a59bc9f2577f93962e9210de8578c49fd2625022cb38606817d3a71f9' 'JDK release'
    jdkModules=Assert-PinnedHash $jdkModules '81f0e1bb87cd303ddcce2b216e27da416bd20799d9a9811ea1b070123cefff0f' 'JDK modules'
    jvm=Assert-PinnedHash $jvmDll '0d0dffd2f99760ff850b03afa179e60b4730f982377fdf475d6428084889ae25' 'jvm.dll'
    python=Assert-PinnedHash $Python '372c2eae555b344520bf147be0096e009069aeca4e7f78d6aecea6d53158056a' 'python.exe'
    pythonDll=Assert-PinnedHash $pythonDll 'c1ce6d603041759061139f482c4b90c4ac9db676e30abf52fda66a794aab1bd0' 'python312.dll'
    d8Bat=Assert-PinnedHash $d8 'ccc279cdc020fc20cb7889d829b9dc36a462ce4fca8ac713088f6be100b714d0' 'd8.bat'
    d8Jar=Assert-PinnedHash $d8Jar '305622ad00535684534eb8f742cbf5e628a9abc09d8ea4d39d1babb95bf0cee5' 'd8.jar'
    aapt=Assert-PinnedHash $aapt 'db0ba2050b8f6b37185d2ba458d6e25b565aefa3f3b96040adf0a82c3469ce3c' 'aapt.exe'
    zipalign=Assert-PinnedHash $zipalign 'aa2475ce201962b871fb8daec020da03fd6292c9c1f422cd0fe2e39b20d4f673' 'zipalign.exe'
    powershell5Launcher=Assert-PinnedHash $powershell5Source '8bb6fa8c283b4d92120b1ef249a9b311b0f804d4cabbe9981159976c8be76a5e' 'Windows PowerShell 5.1 launcher'
    powershell7Launcher=Assert-PinnedHash $powershell7 '362a356ce7f0940ec74f73a8fc2c990a2cc24a38a11c90bbd8eca947110ad139' 'PowerShell 7 launcher'
}
$activitySource=Join-Path $hostRoot 'src/com/techrebbe/supernote/nativepagehost/NativePageHostActivity.java'
$lifecycleSource=Join-Path $probeRoot 'java/com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle.java'
$layoutSource=Join-Path $probeRoot 'java/com/techrebbe/supernote/viewportprobe/DisplayProbeLayout.java'
$manifest=Join-Path $hostRoot 'AndroidManifest.xml'
$lifecycleTest=Join-Path $probeRoot 'test/NativePageHostLifecycleTest.java'
$canonicalizer=Join-Path $hostRoot 'canonicalize_apk.py'
$inspector=Join-Path $hostRoot 'inspect_native_page_host.py'
$packageTests=Join-Path $hostRoot 'test_native_page_host_package.py'
$hostReadme=Join-Path $hostRoot 'README.md'
$buildScriptSource=Join-Path $probeRoot 'build-native-page-host.ps1'

# One descriptor-read private snapshot is the only source authority used by tests,
# compilation, packaging, and inspection. Its open handles deny replacement.
$out=Join-Path $probeRoot ('build/native-page-host-' + [guid]::NewGuid().ToString('N'))
$snapshotRoot=Join-Path ([IO.Path]::GetTempPath()) ('nph-authority-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $snapshotRoot | Out-Null
$snapshotLocks=New-Object 'System.Collections.Generic.List[System.IDisposable]'
$artifactLocks=New-Object 'System.Collections.Generic.List[System.IDisposable]'
$retainedByPath=@{}
function Copy-ToRetainedAuthority([string]$source,[string]$destination,
        [System.Collections.Generic.List[System.IDisposable]]$locks) {
    New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
    $input=[IO.File]::Open($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $output=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,
            [IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
        try {
            $input.CopyTo($output)
            $output.Flush($true)
            $output.Position=0
            $locks.Add($output)
            $script:retainedByPath[$destination]=$output
            $output=$null
        } finally {
            if ($null -ne $output) { $output.Dispose() }
        }
    } finally { $input.Dispose() }
    return $destination
}

function Write-ToRetainedAuthority([string]$destination,[byte[]]$payload,
        [System.Collections.Generic.List[System.IDisposable]]$locks) {
    New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
    $output=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
    try {
        $output.Write($payload,0,$payload.Length)
        $output.Flush($true)
        $output.Position=0
        $locks.Add($output)
        $script:retainedByPath[$destination]=$output
        $output=$null
    } finally {
        if ($null -ne $output) { $output.Dispose() }
    }
    return $destination
}

function Copy-LockedSnapshot([string]$source,[string]$relative) {
    $destination=Join-Path $snapshotRoot $relative
    return Copy-ToRetainedAuthority $source $destination $snapshotLocks
}

# Windows cannot map an executable/Python extension while this process retains
# a write-capable handle to it. Create under exclusive authority, flush and close,
# then immediately admit the unique private path through a read-only retained
# handle. The fixed aggregate inventory authenticates the bytes before execution;
# that read handle thereafter denies write/delete/replacement while allowing DLL
# mapping. No reviewed code runs between creation and fixed-hash admission.
function Copy-LockedPythonRuntimeFile([string]$source,[string]$relative) {
    $destination=Join-Path $snapshotRoot $relative
    New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
    $input=[IO.File]::Open($source,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        $output=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,
            [IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        try { $input.CopyTo($output); $output.Flush($true) }
        finally { $output.Dispose() }
    } finally { $input.Dispose() }
    $retained=[IO.File]::Open($destination,[IO.FileMode]::Open,[IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    $snapshotLocks.Add($retained)
    $script:retainedByPath[$destination]=$retained
    return $destination
}

function Write-LockedSnapshot([string]$destination,[byte[]]$payload) {
    New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
    $output=[IO.File]::Open($destination,[IO.FileMode]::CreateNew,
        [IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
    try {
        $output.Write($payload,0,$payload.Length)
        $output.Flush($true)
        $output.Position=0
        $snapshotLocks.Add($output)
        $script:retainedByPath[$destination]=$output
        $output=$null
    } finally {
        if ($null -ne $output) { $output.Dispose() }
    }
    return $destination
}

function Read-RetainedBytes([string]$path) {
    $stream=$script:retainedByPath[$path]
    if ($null -eq $stream) { throw "No retained authority handle for $path" }
    $prior=$stream.Position
    try {
        $stream.Position=0
        $memory=New-Object IO.MemoryStream
        try { $stream.CopyTo($memory); return ,$memory.ToArray() } finally { $memory.Dispose() }
    } finally { $stream.Position=$prior }
}

function Get-RetainedHash([string]$path) {
    $stream=$script:retainedByPath[$path]
    if ($null -eq $stream) { throw "No retained authority handle for $path" }
    $prior=$stream.Position
    $sha=[Security.Cryptography.SHA256]::Create()
    try {
        $stream.Position=0
        return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','').ToLowerInvariant()
    }
    finally { $stream.Position=$prior; $sha.Dispose() }
}

function Get-RetainedLength([string]$path) {
    $stream=$script:retainedByPath[$path]
    if ($null -eq $stream) { throw "No retained authority handle for $path" }
    return $stream.Length
}

function Write-Unsigned16([IO.Stream]$stream,[uint16]$value) {
    if (-not [BitConverter]::IsLittleEndian) { throw 'ZIP writer requires little-endian host' }
    $bytes=[BitConverter]::GetBytes($value)
    $stream.Write($bytes,0,$bytes.Length)
}

function Write-Unsigned32([IO.Stream]$stream,[uint32]$value) {
    if (-not [BitConverter]::IsLittleEndian) { throw 'ZIP writer requires little-endian host' }
    $bytes=[BitConverter]::GetBytes($value)
    $stream.Write($bytes,0,$bytes.Length)
}

function New-Crc32Table() {
    $table=New-Object 'System.UInt32[]' 256
    for ($index=0; $index -lt 256; $index++) {
        [uint32]$entry=$index
        for ($bit=0; $bit -lt 8; $bit++) {
            if (($entry -band 1) -ne 0) {
                $entry=[uint32](0xedb88320 -bxor ($entry -shr 1))
            } else { $entry=[uint32]($entry -shr 1) }
        }
        $table[$index]=$entry
    }
    return ,$table
}

$crc32Table=New-Crc32Table
function Get-Crc32([byte[]]$payload) {
    [uint32]$crc=[uint32]::MaxValue
    foreach ($value in $payload) {
        $index=[int](($crc -bxor [uint32]$value) -band 0xff)
        $crc=[uint32](($crc -shr 8) -bxor $script:crc32Table[$index])
    }
    return [uint32]($crc -bxor [uint32]::MaxValue)
}

# Raw ZIP_STORED writer: sorted UTF-8 names, fixed 1980 timestamp, no extras,
# comments, data descriptors, compression, or Zip64. This avoids any
# PowerShell/.NET compression-engine dependency in the pre-interpreter bootstrap.
function New-PythonBootstrapZipBytes() {
    $encodingRoot=Join-Path $pythonRuntimeLibSnapshot 'encodings'
    $entryNames=New-Object 'System.Collections.Generic.List[string]'
    $entryPaths=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
    foreach ($item in @(Get-ChildItem -LiteralPath $encodingRoot -Recurse -File -Filter '*.py')) {
        $name='encodings/' + $item.FullName.Substring($encodingRoot.Length + 1).Replace(
            [char]92,[char]47)
        $entryNames.Add($name)
        $entryPaths.Add($name,$item.FullName)
    }
    $entryNames.Sort([StringComparer]::Ordinal)
    if ($entryNames.Count -ne 122) { throw 'Python bootstrap encoding inventory count differed' }
    $output=New-Object IO.MemoryStream
    $central=New-Object 'System.Collections.Generic.List[object]'
    try {
        foreach ($entryName in $entryNames) {
            $nameBytes=[Text.UTF8Encoding]::new($false,$true).GetBytes($entryName)
            $payload=Read-RetainedBytes $entryPaths[$entryName]
            if ($nameBytes.Length -gt 65535 -or $payload.Length -gt [uint32]::MaxValue) {
                throw 'Python bootstrap ZIP entry exceeded classic ZIP limits'
            }
            [uint32]$offset=$output.Position
            [uint32]$crc=Get-Crc32 $payload
            Write-Unsigned32 $output 0x04034b50
            Write-Unsigned16 $output 20
            Write-Unsigned16 $output 0x0800
            Write-Unsigned16 $output 0
            Write-Unsigned16 $output 0
            Write-Unsigned16 $output 0x0021
            Write-Unsigned32 $output $crc
            Write-Unsigned32 $output ([uint32]$payload.Length)
            Write-Unsigned32 $output ([uint32]$payload.Length)
            Write-Unsigned16 $output ([uint16]$nameBytes.Length)
            Write-Unsigned16 $output 0
            $output.Write($nameBytes,0,$nameBytes.Length)
            $output.Write($payload,0,$payload.Length)
            $central.Add([PSCustomObject]@{Name=$nameBytes;Crc=$crc;Size=$payload.Length;Offset=$offset})
        }
        [uint32]$centralOffset=$output.Position
        foreach ($entry in $central) {
            Write-Unsigned32 $output 0x02014b50
            Write-Unsigned16 $output 20
            Write-Unsigned16 $output 20
            Write-Unsigned16 $output 0x0800
            Write-Unsigned16 $output 0
            Write-Unsigned16 $output 0
            Write-Unsigned16 $output 0x0021
            Write-Unsigned32 $output ([uint32]$entry.Crc)
            Write-Unsigned32 $output ([uint32]$entry.Size)
            Write-Unsigned32 $output ([uint32]$entry.Size)
            Write-Unsigned16 $output ([uint16]$entry.Name.Length)
            Write-Unsigned16 $output 0
            Write-Unsigned16 $output 0
            Write-Unsigned16 $output 0
            Write-Unsigned16 $output 0
            Write-Unsigned32 $output 0
            Write-Unsigned32 $output ([uint32]$entry.Offset)
            $output.Write($entry.Name,0,$entry.Name.Length)
        }
        [uint32]$centralSize=$output.Position - $centralOffset
        Write-Unsigned32 $output 0x06054b50
        Write-Unsigned16 $output 0
        Write-Unsigned16 $output 0
        Write-Unsigned16 $output ([uint16]$central.Count)
        Write-Unsigned16 $output ([uint16]$central.Count)
        Write-Unsigned32 $output $centralSize
        Write-Unsigned32 $output $centralOffset
        Write-Unsigned16 $output 0
        return ,$output.ToArray()
    } finally { $output.Dispose() }
}

function Get-ReviewedPythonRuntimeFiles([string]$runtimeRoot,[string]$libRoot,[string]$dllRoot) {
    $records=New-Object 'System.Collections.Generic.List[object]'
    $runtimeRootItem=Get-Item -LiteralPath $runtimeRoot -Force
    if (-not $runtimeRootItem.PSIsContainer `
            -or ($runtimeRootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Python runtime root is not an ordinary directory: $runtimeRoot"
    }
    foreach ($item in @(Get-ChildItem -LiteralPath $runtimeRoot -File -Force)) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Python runtime authority contains a reparse point: $($item.FullName)"
        }
        $records.Add([PSCustomObject]@{Source=$item.FullName;Relative=$item.Name})
    }
    foreach ($rootRecord in @(
            [PSCustomObject]@{Prefix='Lib';Root=$libRoot},
            [PSCustomObject]@{Prefix='DLLs';Root=$dllRoot})) {
        $rootItem=Get-Item -LiteralPath $rootRecord.Root -Force
        if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Python runtime root is a reparse point: $($rootRecord.Root)"
        }
        foreach ($item in @(Get-ChildItem -LiteralPath $rootRecord.Root -Recurse -Force)) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Python runtime authority contains a reparse point: $($item.FullName)"
            }
            if ($item.PSIsContainer) { continue }
            $relative=$item.FullName.Substring($rootRecord.Root.Length + 1).Replace(
                [char]92,[char]47)
            $segments=$relative.Split([char]47)
            if ($rootRecord.Prefix -ceq 'Lib' -and
                    (($segments -ccontains 'site-packages') -or
                     ($segments -ccontains '__pycache__') -or
                     $item.Extension -ieq '.pyc')) {
                continue
            }
            $records.Add([PSCustomObject]@{
                Source=$item.FullName
                Relative=($rootRecord.Prefix + '/' + $relative)
            })
        }
    }
    return @($records | Sort-Object -Property @{Expression={$_.Relative};Ascending=$true})
}

$reviewedPythonRuntimeFileCount=783
$reviewedPythonRuntimeDirectoryCount=55
$reviewedPythonRuntimeRecordCount=838
$reviewedPythonRuntimeInventorySha256='3aa15c911493f4107b5860a9bccd9107781fe63efb56e07f83a72078c6d49f57'
$pythonRuntimeRootSnapshot=Join-Path $snapshotRoot 'python-runtime'
$pythonRuntimeLibSnapshot=Join-Path $pythonRuntimeRootSnapshot 'Lib'
$pythonRuntimeDllSnapshot=Join-Path $pythonRuntimeRootSnapshot 'DLLs'
$reviewedPython=Join-Path $pythonRuntimeRootSnapshot 'python.exe'

function Assert-ReviewedPythonRuntimeAuthority() {
    $rootItem=Get-Item -LiteralPath $pythonRuntimeRootSnapshot -Force
    if (-not $rootItem.PSIsContainer `
            -or ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Private Python runtime root is not an ordinary directory'
    }
    $records=New-Object 'System.Collections.Generic.List[string]'
    $fileCount=0
    $directoryCount=0
    foreach ($item in @(Get-ChildItem -LiteralPath $pythonRuntimeRootSnapshot -Recurse -Force)) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Private Python runtime contains a reparse point: $($item.FullName)"
        }
        $relative=$item.FullName.Substring($pythonRuntimeRootSnapshot.Length + 1).Replace(
            [char]92,[char]47)
        if ($item.PSIsContainer) {
            $directoryCount++
            $records.Add("D`t" + $relative)
            continue
        }
        $fileCount++
        if (-not $script:retainedByPath.ContainsKey($item.FullName)) {
            throw "Private Python runtime contains an unretained file: $relative"
        }
        $records.Add("F`t" + $relative + "`t" + (Get-RetainedLength $item.FullName) + "`t" +
            (Get-RetainedHash $item.FullName))
    }
    $records.Sort([StringComparer]::Ordinal)
    if ($fileCount -ne $reviewedPythonRuntimeFileCount `
            -or $directoryCount -ne $reviewedPythonRuntimeDirectoryCount `
            -or $records.Count -ne $reviewedPythonRuntimeRecordCount) {
        throw 'Private Python runtime file/directory inventory count differed'
    }
    $wire=[Text.UTF8Encoding]::new($false).GetBytes(($records -join "`n") + "`n")
    $actualInventorySha256=Get-BytesSha256 $wire
    if ($actualInventorySha256 -cne $reviewedPythonRuntimeInventorySha256) {
        throw "Private Python runtime inventory differs from reviewed authority: $actualInventorySha256"
    }
    $script:reviewedPythonRuntimeInventoryWire=$wire
}

function Invoke-PythonRuntimeAuthorityMutationSelfTest() {
    $unretained=Join-Path $pythonRuntimeRootSnapshot 'hostile-unretained.py'
    Write-NewBytes $unretained ([byte[]](0x78,0x0a))
    $additionRejected=$false
    try { Assert-ReviewedPythonRuntimeAuthority }
    catch { $additionRejected=$true }
    finally { [IO.File]::Delete($unretained) }
    if (-not $additionRejected) {
        throw 'Private Python runtime admitted an unretained file'
    }
    $shadowDirectory=Join-Path $pythonRuntimeLibSnapshot 'argparse'
    [IO.Directory]::CreateDirectory($shadowDirectory) | Out-Null
    $directoryRejected=$false
    try { Assert-ReviewedPythonRuntimeAuthority }
    catch { $directoryRejected=$true }
    finally { [IO.Directory]::Delete($shadowDirectory,$false) }
    if (-not $directoryRejected) {
        throw 'Private Python runtime admitted an unretained package-shadow directory'
    }
    $junction=Join-Path $pythonRuntimeLibSnapshot 'hostile-runtime-junction'
    $junctionRejected=$false
    try {
        New-Item -ItemType Junction -Path $junction -Target $pythonRuntimeDllSnapshot `
            -ErrorAction Stop | Out-Null
        try { Assert-ReviewedPythonRuntimeAuthority }
        catch { $junctionRejected=$true }
    } finally {
        if (Test-Path -LiteralPath $junction) { [IO.Directory]::Delete($junction,$false) }
    }
    if (-not $junctionRejected) {
        throw 'Private Python runtime admitted a directory reparse point'
    }
    $writeRejected=$false
    $probe=$null
    try {
        $probe=[IO.File]::Open($reviewedPython,[IO.FileMode]::Open,[IO.FileAccess]::Write,
            [IO.FileShare]::ReadWrite)
    } catch { $writeRejected=$true }
    finally { if ($null -ne $probe) { $probe.Dispose() } }
    if (-not $writeRejected) {
        throw 'Private Python runtime retained handle admitted a writer'
    }
    Assert-ReviewedPythonRuntimeAuthority
}

function ConvertTo-WindowsNativeArgument([string]$value) {
    if ($null -eq $value) { throw 'native process argument cannot be null' }
    if ($value.Length -gt 0 -and $value -notmatch '[\s"]') { return $value }
    $builder=New-Object Text.StringBuilder
    [void]$builder.Append([char]34)
    $slashes=0
    foreach ($character in $value.ToCharArray()) {
        if ($character -eq [char]92) {
            $slashes++
        } elseif ($character -eq [char]34) {
            for ($index=0; $index -lt (2 * $slashes + 1); $index++) {
                [void]$builder.Append([char]92)
            }
            [void]$builder.Append([char]34)
            $slashes=0
        } else {
            for ($index=0; $index -lt $slashes; $index++) {
                [void]$builder.Append([char]92)
            }
            $slashes=0
            [void]$builder.Append($character)
        }
    }
    for ($index=0; $index -lt (2 * $slashes); $index++) {
        [void]$builder.Append([char]92)
    }
    [void]$builder.Append([char]34)
    return $builder.ToString()
}

# The bootstrap imports only frozen CPython modules before checking authority.
# It verifies the complete retained file/directory namespace before exposing the
# private stdlib, then installs a process-lifetime audit guard. The guard rejects
# unlisted package shadows, reparse aliases, mutations, and sys.path drift even if
# an external writer races the pre-launch PowerShell inventory check.
$pythonIsolatedBootstrap=@'
import _frozen_importlib as frozen_importlib
import _frozen_importlib_external as frozen_importlib_external
import os,sys
expected_executable=os.path.normcase(os.path.realpath(sys.argv[1]))
expected_root=os.path.normcase(os.path.realpath(sys.argv[2]))
private_lib=os.path.normcase(os.path.realpath(sys.argv[3]))
private_dlls=os.path.normcase(os.path.realpath(sys.argv[4]))
review_root=os.path.normcase(os.path.realpath(sys.argv[5]))
inventory_path=os.path.normcase(os.path.realpath(sys.argv[6]))
expected_inventory_digest=sys.argv[7]
expected_file_count=int(sys.argv[8])
expected_directory_count=int(sys.argv[9])
helper_authority_wire=sys.argv[10]
powershell5_path=os.path.normcase(os.path.realpath(sys.argv[11]))
powershell5_digest=sys.argv[12]
powershell7_path=os.path.normcase(os.path.realpath(sys.argv[13]))
powershell7_digest=sys.argv[14]
script=os.path.normcase(os.path.realpath(sys.argv[15]))
target_args=sys.argv[16:]
flags=sys.flags
if not (flags.isolated == 1 and flags.no_site == 1 and flags.no_user_site == 1 and flags.ignore_environment == 1 and flags.safe_path and flags.dont_write_bytecode == 1):
    raise SystemExit('python isolation flags were not authoritative')
if (os.__spec__.origin != 'frozen'
        or frozen_importlib.__spec__.origin != 'frozen'
        or frozen_importlib_external.__spec__.origin != 'frozen'):
    raise SystemExit('python bootstrap modules were not frozen runtime authority')
if sys.version_info[:5] != (3,12,14,'final',0):
    raise SystemExit('private Python version authority changed')
if os.path.normcase(os.path.realpath(sys.executable)) != expected_executable:
    raise SystemExit('python executable authority changed')
if os.path.normcase(os.path.realpath(sys.prefix)) != expected_root or os.path.normcase(os.path.realpath(sys.base_prefix)) != expected_root:
    raise SystemExit('python runtime root authority changed')
bootstrap_zip=os.path.normcase(os.path.realpath(os.path.join(expected_root,'python-bootstrap.zip')))
expected_path=[bootstrap_zip]
if [os.path.normcase(os.path.realpath(value)) for value in sys.path] != [os.path.normcase(os.path.realpath(value)) for value in expected_path]:
    raise SystemExit('python base import path authority changed')
if os.path.dirname(script) != review_root:
    raise SystemExit('reviewed python script escaped its retained import root')
if expected_file_count != 783 or expected_directory_count != 55 or len(expected_inventory_digest) != 64:
    raise SystemExit('python inventory contract differed')
helper_authority={}
for record in helper_authority_wire.split(';'):
    fields=record.split('=')
    if (len(fields) != 2 or fields[0] in helper_authority
            or fields[0] not in ('canonicalize_apk.py','inspect_native_page_host.py',
                                 'test_native_page_host_package.py')
            or len(fields[1]) != 64
            or any(value not in '0123456789abcdef' for value in fields[1])):
        raise SystemExit('reviewed Python helper authority wire differed')
    helper_authority[fields[0]]=fields[1]
if set(helper_authority) != {'canonicalize_apk.py','inspect_native_page_host.py',
                             'test_native_page_host_package.py'}:
    raise SystemExit('reviewed Python helper authority inventory differed')
if (len(powershell5_digest) != 64 or len(powershell7_digest) != 64
        or any(value not in '0123456789abcdef'
               for value in powershell5_digest+powershell7_digest)
        or powershell5_path == powershell7_path):
    raise SystemExit('PowerShell launcher authority wire differed')
with open(inventory_path,'rb') as inventory_stream:
    inventory_bytes=inventory_stream.read()
if (not inventory_bytes.endswith(b'\n') or inventory_bytes.endswith(b'\n\n')
        or b'\r' in inventory_bytes or b'\0' in inventory_bytes):
    raise SystemExit('python inventory wire was not canonical')
try:
    inventory_text=inventory_bytes.decode('ascii')
except UnicodeDecodeError as error:
    raise SystemExit('python inventory wire was not ASCII') from error

def canonical_relative(value):
    if (not value or '\\' in value or value.startswith('/') or value.endswith('/')
            or ':' in value):
        raise SystemExit('python inventory relative path was not canonical')
    parts=value.split('/')
    if any(not part or part in ('.','..') for part in parts):
        raise SystemExit('python inventory relative path contained traversal')
    return parts

expected_directories=set()
expected_files={}
casefolded=set()
for line in inventory_text[:-1].split('\n'):
    fields=line.split('\t')
    if len(fields) == 2 and fields[0] == 'D':
        relative=fields[1]
        canonical_relative(relative)
        if os.path.normcase(relative) in casefolded:
            raise SystemExit('python inventory contained a duplicate path')
        casefolded.add(os.path.normcase(relative))
        expected_directories.add(relative)
    elif len(fields) == 4 and fields[0] == 'F':
        relative,size_text,digest=fields[1:]
        canonical_relative(relative)
        if (not size_text.isascii() or not size_text.isdecimal()
                or (len(size_text) > 1 and size_text.startswith('0'))
                or len(digest) != 64
                or any(character not in '0123456789abcdef' for character in digest)):
            raise SystemExit('python inventory file record was invalid')
        if os.path.normcase(relative) in casefolded:
            raise SystemExit('python inventory contained a duplicate path')
        casefolded.add(os.path.normcase(relative))
        expected_files[relative]=(int(size_text),digest)
    else:
        raise SystemExit('python inventory record was invalid')
if len(expected_files) != expected_file_count or len(expected_directories) != expected_directory_count:
    raise SystemExit('python inventory count differed')

def normalized_absolute(value):
    return os.path.normcase(os.path.abspath(os.fsdecode(value)))

def is_under(value,root):
    try:
        return os.path.commonpath((value,root)) == root
    except ValueError:
        return False

def relative_key(value):
    return os.path.normcase(value.replace('/',os.sep)).replace('\\','/')

actual_directories=set()
actual_files=set()
for directory,names,files in os.walk(expected_root,topdown=True,followlinks=False):
    directory_absolute=normalized_absolute(directory)
    if directory_absolute != os.path.normcase(os.path.realpath(directory_absolute)):
        raise SystemExit('python runtime directory resolved through a reparse alias')
    for name in names:
        candidate=os.path.join(directory,name)
        absolute=normalized_absolute(candidate)
        if absolute != os.path.normcase(os.path.realpath(absolute)):
            raise SystemExit('python runtime contained a directory reparse point')
        actual_directories.add(relative_key(os.path.relpath(absolute,expected_root)))
    for name in files:
        candidate=os.path.join(directory,name)
        absolute=normalized_absolute(candidate)
        if absolute != os.path.normcase(os.path.realpath(absolute)):
            raise SystemExit('python runtime contained a file reparse point')
        actual_files.add(relative_key(os.path.relpath(absolute,expected_root)))
if (actual_directories != {relative_key(value) for value in expected_directories}
        or actual_files != {relative_key(value) for value in expected_files}):
    raise SystemExit('python runtime namespace differed from retained inventory')
for relative,(expected_size,unused_digest) in expected_files.items():
    candidate=os.path.join(expected_root,*canonical_relative(relative))
    if os.path.getsize(candidate) != expected_size or not os.path.isfile(candidate):
        raise SystemExit('python runtime file authority changed')

review_files=set()
for relative in ('AndroidManifest.xml','README.md','canonicalize_apk.py',
                 'inspect_native_page_host.py','test_native_page_host_package.py',
                 'src/com/techrebbe/supernote/nativepagehost/NativePageHostActivity.java'):
    candidate=normalized_absolute(os.path.join(review_root,*relative.split('/')))
    if (candidate != os.path.normcase(os.path.realpath(candidate))
            or not os.path.isfile(candidate)):
        raise SystemExit('reviewed python source authority changed')
    review_files.add(candidate)
runtime_files={normalized_absolute(os.path.join(expected_root,*relative.split('/')))
               for relative in expected_files}
allowed_files=runtime_files|review_files
protected_roots=(expected_root,review_root)
write_flags=(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND)

# Before replacing the standard path machinery, every non-builtin/frozen module
# must be one of the encoding modules loaded from the retained bootstrap ZIP.
for module_name,module in tuple(sys.modules.items()):
    specification=getattr(module,'__spec__',None)
    origin=getattr(specification,'origin',None)
    if origin in ('built-in','frozen') or (origin is None and module_name == '__main__'):
        continue
    origin_text=os.path.normcase(os.fsdecode(origin)) if origin is not None else ''
    archive_prefix=bootstrap_zip+os.sep
    if (not origin_text.startswith(archive_prefix)
            or not origin_text[len(archive_prefix):].replace('\\','/').startswith('encodings/')):
        raise SystemExit('module loaded before exact import authority was installed')

module_authority={}
def admit_module(name,path,is_package,loader_kind):
    if (not name or any(not segment.isidentifier() for segment in name.split('.'))
            or name in module_authority):
        raise SystemExit('python module authority contained an invalid duplicate')
    module_authority[name]=(path,is_package,loader_kind)

extension_suffixes=tuple(frozen_importlib_external.EXTENSION_SUFFIXES)
for relative in sorted(expected_files):
    path=normalized_absolute(os.path.join(expected_root,*relative.split('/')))
    if relative.startswith('Lib/') and relative.endswith('.py'):
        module_relative=relative[4:-3]
        parts=module_relative.split('/')
        is_package=parts[-1] == '__init__'
        if is_package:
            parts=parts[:-1]
        if parts:
            admit_module('.'.join(parts),path,is_package,'source')
    elif relative.startswith('DLLs/'):
        filename=relative[5:]
        for suffix in extension_suffixes:
            if filename.endswith(suffix):
                admit_module(filename[:-len(suffix)],path,False,'extension')
                break
for name in ('canonicalize_apk','inspect_native_page_host','test_native_page_host_package'):
    admit_module(name,normalized_absolute(os.path.join(review_root,name+'.py')),False,'source')

hashlib_authority=None
class ExactSourceLoader(frozen_importlib_external.SourceFileLoader):
    # Never probe an unauthenticated pyc/package candidate. Compile only the
    # exact retained source path supplied by module_authority.
    def get_code(self,fullname):
        filename=self.get_filename(fullname)
        payload=self.get_data(filename)
        expected=helper_authority.get(os.path.basename(filename))
        if expected is not None:
            if hashlib_authority is None or hashlib_authority.sha256(payload).hexdigest() != expected:
                raise SystemExit('reviewed Python helper bytes differed before compilation')
        return self.source_to_code(payload,filename)

class ExactAuthorityFinder:
    @staticmethod
    def find_spec(fullname,path=None,target=None):
        authority=module_authority.get(fullname)
        if authority is None:
            return None
        filename,is_package,loader_kind=authority
        if loader_kind == 'source':
            loader=ExactSourceLoader(fullname,filename)
        else:
            loader=frozen_importlib_external.ExtensionFileLoader(fullname,filename)
        locations=[os.path.dirname(filename)] if is_package else None
        return frozen_importlib_external.spec_from_file_location(
            fullname,filename,loader=loader,submodule_search_locations=locations)

sys.meta_path=[frozen_importlib.BuiltinImporter,
               frozen_importlib.FrozenImporter,ExactAuthorityFinder]
sys.path=[]
sys.path_hooks=[]
sys.path_importer_cache.clear()

def protected_path(value):
    if isinstance(value,int):
        return None,None,False
    try:
        lexical=normalized_absolute(value)
        resolved=os.path.normcase(os.path.realpath(lexical))
    except (OSError,TypeError,ValueError):
        return None,None,False
    return lexical,resolved,any(is_under(lexical,root) or is_under(resolved,root)
                                for root in protected_roots)

def runtime_audit(event,args):
    if event == 'open' and args:
        lexical,resolved,protected=protected_path(args[0])
        if protected:
            mode=args[1] if len(args) > 1 else None
            flags_value=args[2] if len(args) > 2 else 0
            if (lexical != resolved or lexical not in allowed_files
                    or (isinstance(mode,str) and any(value in mode for value in 'wax+'))
                    or (isinstance(flags_value,int) and flags_value & write_flags)):
                raise RuntimeError('unreviewed python runtime/review-root open rejected')
    elif event == 'import':
        if sys.path != [] or sys.path_hooks != []:
            raise RuntimeError('python import path authority changed')
        if len(args) > 1 and args[1]:
            lexical,resolved,protected=protected_path(args[1])
            if protected and (lexical != resolved or lexical not in allowed_files):
                raise RuntimeError('unreviewed python import origin rejected')
    elif event in ('os.mkdir','os.remove','os.rmdir','os.rename','os.symlink','os.link'):
        for value in args:
            lexical,resolved,protected=protected_path(value)
            if protected:
                raise RuntimeError('python runtime/review-root mutation rejected')

sys.addaudithook(runtime_audit)
# Hashing becomes safe only after the namespace is exact and the audit hook is
# installed. The manifest itself was emitted and held by the parent process.
import hashlib
hashlib_authority=hashlib
if hashlib.sha256(inventory_bytes).hexdigest() != expected_inventory_digest:
    raise SystemExit('python runtime inventory digest differed')
script_name=os.path.basename(script)
script_expected=helper_authority.get(script_name)
if script_expected is None:
    raise SystemExit('reviewed Python entry script was not fixed authority')
with open(script,'rb') as script_stream:
    script_payload=script_stream.read()
if hashlib.sha256(script_payload).hexdigest() != script_expected:
    raise SystemExit('reviewed Python entry script bytes differed before compilation')
import runpy
if runpy.__spec__.origin != 'frozen':
    raise SystemExit('runpy was not frozen runtime authority')
sys._native_page_host_import_authority=(expected_root,expected_inventory_digest,
                                        expected_file_count,expected_directory_count)
sys._native_page_host_powershell_authority=(
    powershell5_path,powershell5_digest,powershell7_path,powershell7_digest)
sys.argv=[script]+target_args
runpy.run_path(script,run_name='__main__')
'@

$reviewedPythonHelperSha256=[ordered]@{
    'canonicalize_apk.py'='0303060d5cdf2035163c2ee94ab2ec58c35b3dfb7b85bcd19f6ba51d3b56573d'
    'inspect_native_page_host.py'='54e6901b7265fc67b26ced15e2aa05d3207d49eca29a987bdbb08ae82ae17321'
    'test_native_page_host_package.py'='275f1400653db1f770b65911e108f0cc9cd07db182769f4ef53207e38fa80195'
}
$reviewedPythonBootstrapSha256='8cbfdac4d9f45a7b6f7d65b4cd23f0b7eb041d337e60cf82b12aada6ddbe4195'

function Assert-ReviewedPythonHelperAuthority() {
    $bootstrapBytes=[Text.UTF8Encoding]::new($false).GetBytes($pythonIsolatedBootstrap)
    $bootstrapHash=Get-BytesSha256 $bootstrapBytes
    if ($bootstrapHash -cne $reviewedPythonBootstrapSha256) {
        throw "Reviewed Python bootstrap differs from fixed authority: $bootstrapHash"
    }
    $paths=[ordered]@{
        'canonicalize_apk.py'=$canonicalizer
        'inspect_native_page_host.py'=$inspector
        'test_native_page_host_package.py'=$packageTests
    }
    if ($paths.Count -ne $reviewedPythonHelperSha256.Count) {
        throw 'Reviewed Python helper authority inventory differed'
    }
    foreach ($name in $reviewedPythonHelperSha256.Keys) {
        $path=$paths[$name]
        if ($null -eq $path -or -not $script:retainedByPath.ContainsKey($path) `
                -or (Get-RetainedHash $path) -cne $reviewedPythonHelperSha256[$name]) {
            throw "Reviewed Python helper differs from fixed authority: $name"
        }
    }
}

function Invoke-PythonHelperAuthorityMutationSelfTest() {
    # Exercise the actual pre-execution gate with changed retained bytes. These
    # private fixtures never enter Python, so even their explicit hostile code
    # is rejected before the first interpreter launch.
    foreach ($entry in @(
            [PSCustomObject]@{Name='canonicalizer';Path=$canonicalizer},
            [PSCustomObject]@{Name='inspector';Path=$inspector},
            [PSCustomObject]@{Name='packageTests';Path=$packageTests})) {
        $candidate=Join-Path $snapshotRoot ('helper-mutation/' + $entry.Name + '.py')
        $candidate=Write-LockedSnapshot $candidate ([Text.Encoding]::ASCII.GetBytes(
            "raise RuntimeError('unreviewed helper must never execute')`n"))
        $rejected=$false
        try {
            Set-Variable -Scope Script -Name $entry.Name -Value $candidate
            try { Assert-ReviewedPythonHelperAuthority }
            catch { $rejected=$true }
        } finally { Set-Variable -Scope Script -Name $entry.Name -Value $entry.Path }
        if (-not $rejected) { throw 'Changed retained Python helper admitted before launch' }
    }
    $originalBootstrap=$script:pythonIsolatedBootstrap
    $rejected=$false
    try {
        $script:pythonIsolatedBootstrap += "`nraise RuntimeError('unreviewed bootstrap')"
        try { Assert-ReviewedPythonHelperAuthority }
        catch { $rejected=$true }
    } finally { $script:pythonIsolatedBootstrap=$originalBootstrap }
    if (-not $rejected) { throw 'Changed inline Python bootstrap admitted before launch' }
    Assert-ReviewedPythonHelperAuthority
}

function Get-ReviewedPythonArguments([string]$script,[string[]]$arguments) {
    $reviewRoot=Split-Path -Parent $script
    return @('-I','-S','-B','-c',$pythonIsolatedBootstrap,$reviewedPython,
        $pythonRuntimeRootSnapshot,
        $pythonRuntimeLibSnapshot,$pythonRuntimeDllSnapshot,$reviewRoot,
        $pythonRuntimeInventoryPath,$reviewedPythonRuntimeInventorySha256,
        ([string]$reviewedPythonRuntimeFileCount),
        ([string]$reviewedPythonRuntimeDirectoryCount),$script:reviewedPythonHelperWire,
        $powershell5Reviewed,$toolHashes.powershell5Launcher,
        $powershell7Reviewed,$toolHashes.powershell7Launcher,$script) `
        + @($arguments)
}

function Invoke-ReviewedPython([string]$script,[string[]]$arguments,[string]$label) {
    Assert-ReviewedPythonRuntimeAuthority
    Assert-ReviewedPythonHelperAuthority
    $pythonArguments=Get-ReviewedPythonArguments $script $arguments
    try {
        & $reviewedPython @pythonArguments
        if ($LASTEXITCODE -ne 0) { throw "$label failed" }
    } finally {
        Assert-ReviewedPythonHelperAuthority
        Assert-ReviewedPythonRuntimeAuthority
    }
}

function Invoke-ReviewedPythonCaptured([string]$script,[string[]]$arguments,
        [string]$label,[int]$maxOutputBytes) {
    Assert-ReviewedPythonRuntimeAuthority
    Assert-ReviewedPythonHelperAuthority
    $pythonArguments=Get-ReviewedPythonArguments $script $arguments
    $start=New-Object Diagnostics.ProcessStartInfo
    $start.FileName=$reviewedPython
    $start.Arguments=(($pythonArguments | ForEach-Object {
        ConvertTo-WindowsNativeArgument $_ }) -join ' ')
    $start.UseShellExecute=$false
    $start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true
    $start.RedirectStandardOutput=$true
    $start.RedirectStandardError=$true
    $process=New-Object Diagnostics.Process
    $process.StartInfo=$start
    $stdout=New-Object IO.MemoryStream
    $stderr=New-Object IO.MemoryStream
    try {
        if (-not $process.Start()) { throw "$label process did not start" }
        $process.StandardInput.Close()
        $stdoutCopy=$process.StandardOutput.BaseStream.CopyToAsync($stdout)
        $stderrCopy=$process.StandardError.BaseStream.CopyToAsync($stderr)
        $process.WaitForExit()
        $stdoutCopy.Wait()
        $stderrCopy.Wait()
        $stdoutBytes=$stdout.ToArray()
        $stderrBytes=$stderr.ToArray()
        if ($stdoutBytes.Length -gt $maxOutputBytes -or $stderrBytes.Length -gt 4MB) {
            throw "$label output exceeded its bound"
        }
        if ($process.ExitCode -ne 0 -or $stderrBytes.Length -ne 0) {
            $detail='nonzero exit or unexpected stderr'
            if ($stderrBytes.Length -gt 0) {
                try { $detail=[Text.UTF8Encoding]::new($false,$true).GetString($stderrBytes) }
                catch { $detail='non-UTF-8 stderr' }
            }
            throw "$label failed: $detail"
        }
        $canonical=ConvertTo-CanonicalEvidenceUtf8 $stdoutBytes $label
        if ([Convert]::ToBase64String($canonical) -cne
                [Convert]::ToBase64String($stdoutBytes)) {
            throw "$label did not emit canonical UTF-8/LF bytes"
        }
        return ,$stdoutBytes
    } finally {
        $stdout.Dispose()
        $stderr.Dispose()
        $process.Dispose()
        Assert-ReviewedPythonHelperAuthority
        Assert-ReviewedPythonRuntimeAuthority
    }
}

function Invoke-JavapCanonicalEvidence([string[]]$arguments,[string]$label) {
    $start=New-Object Diagnostics.ProcessStartInfo
    $start.FileName=$javap
    $start.Arguments=(($arguments | ForEach-Object { ConvertTo-WindowsNativeArgument $_ }) -join ' ')
    $start.UseShellExecute=$false
    $start.CreateNoWindow=$true
    $start.RedirectStandardInput=$true
    $start.RedirectStandardOutput=$true
    $start.RedirectStandardError=$true
    $process=New-Object Diagnostics.Process
    $process.StartInfo=$start
    $stdout=New-Object IO.MemoryStream
    $stderr=New-Object IO.MemoryStream
    try {
        if (-not $process.Start()) { throw "$label process did not start" }
        $process.StandardInput.Close()
        $stdoutCopy=$process.StandardOutput.BaseStream.CopyToAsync($stdout)
        $stderrCopy=$process.StandardError.BaseStream.CopyToAsync($stderr)
        $process.WaitForExit()
        $stdoutCopy.Wait()
        $stderrCopy.Wait()
        $stdoutBytes=$stdout.ToArray()
        $stderrBytes=$stderr.ToArray()
        if ($stdoutBytes.Length -gt 4MB -or $stderrBytes.Length -gt 4MB) {
            throw "$label output exceeded its bound"
        }
        if ($process.ExitCode -ne 0) {
            $detail='nonzero exit'
            if ($stderrBytes.Length -gt 0) {
                try { $detail=[Text.UTF8Encoding]::new($false,$true).GetString($stderrBytes) }
                catch { $detail='non-UTF-8 stderr' }
            }
            throw "$label failed: $detail"
        }
        if ($stderrBytes.Length -ne 0) { throw "$label produced unexpected stderr" }
        return ,(ConvertTo-CanonicalEvidenceUtf8 $stdoutBytes $label)
    } finally {
        $stdout.Dispose()
        $stderr.Dispose()
        $process.Dispose()
    }
}

$activitySource=Copy-LockedSnapshot $activitySource 'native-page-host/src/com/techrebbe/supernote/nativepagehost/NativePageHostActivity.java'
$lifecycleSource=Copy-LockedSnapshot $lifecycleSource 'java/com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle.java'
$layoutSource=Copy-LockedSnapshot $layoutSource 'java/com/techrebbe/supernote/viewportprobe/DisplayProbeLayout.java'
$manifest=Copy-LockedSnapshot $manifest 'native-page-host/AndroidManifest.xml'
$lifecycleTest=Copy-LockedSnapshot $lifecycleTest 'test/NativePageHostLifecycleTest.java'
$canonicalizer=Copy-LockedSnapshot $canonicalizer 'native-page-host/canonicalize_apk.py'
$inspector=Copy-LockedSnapshot $inspector 'native-page-host/inspect_native_page_host.py'
$packageTests=Copy-LockedSnapshot $packageTests 'native-page-host/test_native_page_host_package.py'
$hostReadme=Copy-LockedSnapshot $hostReadme 'native-page-host/README.md'
$buildScriptSnapshot=Copy-LockedSnapshot $buildScriptSource 'build-native-page-host.ps1'
if ([Text.UTF8Encoding]::new($false,$true).GetString(
        (Read-RetainedBytes $buildScriptSnapshot)) -cne $parsedBuildPolicyText) {
    throw 'Retained build policy differs from the caller-reviewed parsed root'
}
$powershell5Reviewed=Copy-LockedPythonRuntimeFile $powershell5Source `
    'powershell-engines/windows-powershell-5.1/powershell.exe'
$powershell7Reviewed=$powershell7
if ((Get-RetainedHash $powershell5Reviewed) -cne $toolHashes.powershell5Launcher) {
    throw 'Private Windows PowerShell 5.1 launcher differs from reviewed authority'
}
$script:reviewedPythonHelperWire=(($reviewedPythonHelperSha256.Keys | ForEach-Object {
    $_ + '=' + $reviewedPythonHelperSha256[$_]
}) -join ';')
Assert-ReviewedPythonHelperAuthority
Invoke-PythonHelperAuthorityMutationSelfTest

# Reviewed Python code never imports from the mutable installed runtime tree.
# Copy the exact allowlisted stdlib/extension inventory into the private retained
# authority, reject reparse points, and authenticate names, sizes, and contents.
$pythonRuntimeFiles=Get-ReviewedPythonRuntimeFiles $pythonRoot $pythonLib $pythonDlls
foreach ($runtimeFile in $pythonRuntimeFiles) {
    Copy-LockedPythonRuntimeFile $runtimeFile.Source `
        ('python-runtime/' + $runtimeFile.Relative) | Out-Null
}
$pythonBootstrapZip=Join-Path $pythonRuntimeRootSnapshot 'python-bootstrap.zip'
$pythonBootstrapZip=Write-LockedSnapshot $pythonBootstrapZip `
    (New-PythonBootstrapZipBytes)
$pythonPathAuthority=Join-Path $pythonRuntimeRootSnapshot 'python312._pth'
$pythonPathAuthority=Write-LockedSnapshot $pythonPathAuthority `
    ([Text.Encoding]::ASCII.GetBytes("python-bootstrap.zip`n"))
Assert-ReviewedPythonRuntimeAuthority
Assert-ReviewedPythonHelperAuthority
Invoke-PythonRuntimeAuthorityMutationSelfTest
Assert-ReviewedPythonRuntimeAuthority
Assert-ReviewedPythonHelperAuthority
$pythonRuntimeInventoryPath=Join-Path $snapshotRoot 'python-runtime-inventory-v1.txt'
$pythonRuntimeInventoryPath=Write-LockedSnapshot $pythonRuntimeInventoryPath `
    $script:reviewedPythonRuntimeInventoryWire

# The original runtime is never executed, and --version would exit before the
# authenticated bootstrap. Every reviewed invocation verifies the exact private
# sys.version_info tuple; this fixed label records that enforced contract.
$pythonVersion='Python 3.12.14'

# Reviewed, noncircular compiler-output authority. These fixed values bind raw
# javac/D8/APK outputs to exact retained Java/manifest/test inputs before any raw
# path is reopened or copied. Updating source requires an explicit reviewed
# authority refresh; the build never learns expected hashes from its own output.
$reviewedSourceSha256=[ordered]@{
    activity='6a1183d3e134fe4a71788d572bb951265baf66c6a6d80f6adc59e75356be8242'
    lifecycle='ec5bb0136ec9b1ace86cd29efe45b7854645113ab3f09235af213bafd9b4e953'
    layout='3a343c107ff4ce4ffdaa92005e2af5a950aec9e3658071e7a5b10296f86c90ec'
    manifest='eb2a9c41b7000dd381cf88458fd7d42dd309e7b1e281070f62e50f6d9198462a'
    lifecycleTest='af862012cc140517273352b5b412591124804280825c6fb1672483fa8862cfaa'
}
$reviewedProductionClassSha256=[ordered]@{
    'com/techrebbe/supernote/nativepagehost/NativePageHostActivity.class'='eea7dbd939b87988c8f9bb846b7b26e9638d6eb8dc2916e401a5ea3e0621e075'
    'com/techrebbe/supernote/nativepagehost/NativePageHostActivity$1.class'='0ae3ba58f8a4742e556f582e7a6b4ca03d04b14af375a4c925523c068dc1047b'
    'com/techrebbe/supernote/nativepagehost/NativePageHostActivity$2.class'='f16e0bfae5bf1aa87f97f829ec4a919a366b3fb6e47bfbae11a1900c9913f55e'
    'com/techrebbe/supernote/nativepagehost/NativePageHostActivity$CommandEnvelope.class'='9e0314e9321ce8082d9dce0bd4311c06b0a1eda12d7b79a31a1839eff8a27461'
    'com/techrebbe/supernote/viewportprobe/DisplayProbeLayout.class'='3cc57303ed38aca6e98774296bed4c6a481762f17b87fa704d0a6f06390a30dc'
    'com/techrebbe/supernote/viewportprobe/DisplayProbeLayout$Placement.class'='19b573f1df309daaaa3688a234c147007c1dc20eb0c13fde6cc991ba8b9033f4'
    'com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle.class'='d24dc72c36bbe93de035fb29faae09a9989430d4522ab6087a1042daa28e01a3'
    'com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult.class'='60ff0e47db6ba128a617562be4e580252a05192bfca7b9f8b3d84386ec3c08e1'
    'com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$ForeignTaskIdentity.class'='c9d65fabd9985dd4d6c0d0d98ec593405158f286292b5900ae3f5a0225560d0c'
    'com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$FrameResult.class'='77acab1e5dfdbc5a571be657de424ebedb3d28f8d43aedb6e995bc71dd47afd8'
    'com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State.class'='f015dea20db899e378df5daa9ac093dea167368c86b0e75d344e9cdaa70c9aee'
}
$reviewedTestClassSha256=[ordered]@{
    'NativePageHostLifecycleTest.class'='932bef7a231ee4d1a24ca2a53348c083486df75b71c51a9a4d336ba4390bd515'
    'com/techrebbe/supernote/viewportprobe/DisplayProbeLayout.class'='3cc57303ed38aca6e98774296bed4c6a481762f17b87fa704d0a6f06390a30dc'
    'com/techrebbe/supernote/viewportprobe/DisplayProbeLayout$Placement.class'='19b573f1df309daaaa3688a234c147007c1dc20eb0c13fde6cc991ba8b9033f4'
    'com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle.class'='d24dc72c36bbe93de035fb29faae09a9989430d4522ab6087a1042daa28e01a3'
    'com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$CommandResult.class'='60ff0e47db6ba128a617562be4e580252a05192bfca7b9f8b3d84386ec3c08e1'
    'com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$ForeignTaskIdentity.class'='c9d65fabd9985dd4d6c0d0d98ec593405158f286292b5900ae3f5a0225560d0c'
    'com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$FrameResult.class'='77acab1e5dfdbc5a571be657de424ebedb3d28f8d43aedb6e995bc71dd47afd8'
    'com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle$State.class'='f015dea20db899e378df5daa9ac093dea167368c86b0e75d344e9cdaa70c9aee'
}
$reviewedDexSha256='15d24cef8f4c70cf167ab6e93ac817fc2e85af4bfca6bb392e2535dc04863ab6'
$reviewedApkSha256='670c755fabb00df87c6b6714c3dc8b878aa22e3190d95585b24adce295756178'

function Assert-ReviewedSourceAuthority() {
    $actual=[ordered]@{
        activity=Get-RetainedHash $activitySource
        lifecycle=Get-RetainedHash $lifecycleSource
        layout=Get-RetainedHash $layoutSource
        manifest=Get-RetainedHash $manifest
        lifecycleTest=Get-RetainedHash $lifecycleTest
    }
    foreach ($name in $reviewedSourceSha256.Keys) {
        if ($actual[$name] -cne $reviewedSourceSha256[$name]) {
            throw "Retained compiler input differs from reviewed output authority: $name"
        }
    }
}

function Assert-ReviewedFileSet([string]$root,[System.Collections.IDictionary]$expected,
        [string]$label,[bool]$retained=$false) {
    $actual=@{}
    foreach ($file in @(Get-ChildItem -LiteralPath $root -Recurse -File | Sort-Object FullName)) {
        $relative=$file.FullName.Substring($root.Length + 1).Replace([char]92,[char]47)
        if ($actual.ContainsKey($relative)) { throw "$label duplicate path: $relative" }
        $actual[$relative]=if ($retained) { Get-RetainedHash $file.FullName } else {
            (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    if ($actual.Count -ne $expected.Count) { throw "$label inventory count differed" }
    foreach ($relative in $expected.Keys) {
        if (-not $actual.ContainsKey($relative) -or $actual[$relative] -cne $expected[$relative]) {
            throw "$label fixed authority differed: $relative"
        }
    }
}

Assert-ReviewedSourceAuthority

$toolchainAuthorityPath=Join-Path $snapshotRoot 'native-page-host-toolchain-v1.json'
$toolchainAuthority=[ordered]@{
    schema='native-page-host-toolchain-v1'; jdk='17'; androidPlatform='android-35'
    buildTools='35.0.0'; python=$pythonVersion
    pythonRuntimeAuthority='private-retained-namespace-audit-v2'
    pythonFlags='-I -S -B'
    pythonRuntimeFileCount=$reviewedPythonRuntimeFileCount
    pythonRuntimeDirectoryCount=$reviewedPythonRuntimeDirectoryCount
    pythonRuntimeRecordCount=$reviewedPythonRuntimeRecordCount
    pythonRuntimeInventorySha256=$reviewedPythonRuntimeInventorySha256
    pythonHelperSha256=$reviewedPythonHelperSha256
    pythonBootstrapSha256=$reviewedPythonBootstrapSha256
    powershellEvidenceAuthority='fixed-launchers-retained-policy-platform-runtime-trusted-v1'
    sha256=$toolHashes
} | ConvertTo-Json -Depth 4 -Compress
$toolchainAuthorityBytes=[Text.UTF8Encoding]::new($false).GetBytes($toolchainAuthority + "`n")
$toolchainAuthorityPath=Write-LockedSnapshot $toolchainAuthorityPath $toolchainAuthorityBytes

$expectedHostSources=@($activitySource)
$discoveredHostSources=@(Get-ChildItem -LiteralPath (Join-Path $snapshotRoot 'native-page-host/src') -Recurse -File -Filter '*.java' |
    ForEach-Object FullName)
$sourceDifference=@(Compare-Object ($expectedHostSources | Sort-Object) ($discoveredHostSources | Sort-Object))
if ($sourceDifference.Count -ne 0) {
    throw 'Native-page-host Java inventory differs from the exact one-file allowlist'
}

# Run the pure state/layout seam and adversarial source/package tests before
# producing either build. Android callback/task behavior remains hardware-only.
$testRoot=Join-Path $probeRoot ('build/native-page-host-tests-' + [guid]::NewGuid().ToString('N'))
$testClasses=Join-Path $testRoot 'classes'
New-Item -ItemType Directory -Path $testClasses | Out-Null
& $javac -encoding UTF-8 --release 8 -d $testClasses `
    $layoutSource $lifecycleSource $lifecycleTest
if ($LASTEXITCODE -ne 0) {throw 'Native page host lifecycle/layout compilation failed'}
Assert-ReviewedFileSet $testClasses $reviewedTestClassSha256 'raw lifecycle test classes'
$retainedTestClasses=Join-Path $snapshotRoot 'generated/tests/classes'
foreach ($testClass in @(Get-ChildItem -LiteralPath $testClasses -Recurse -File -Filter '*.class')) {
    $relative=$testClass.FullName.Substring($testClasses.Length + 1)
    Copy-LockedSnapshot $testClass.FullName ("generated/tests/classes/$relative") | Out-Null
}
Assert-ReviewedFileSet $retainedTestClasses $reviewedTestClassSha256 `
    'retained lifecycle test classes' $true
& $java -cp $retainedTestClasses NativePageHostLifecycleTest
if ($LASTEXITCODE -ne 0) {throw 'Native page host lifecycle/layout tests failed'}
$priorLocation=Get-Location
try {
    Set-Location -LiteralPath (Split-Path -Parent $packageTests)
    Invoke-ReviewedPython $packageTests @() 'Native page host source/package tests'
} finally { Set-Location -LiteralPath $priorLocation }

# A fresh retained generation for every invocation; never delete previous
# results or evidence. Two independent compile/package passes must be identical.

function Build-One([string]$name) {
    $one=Join-Path $out $name
    $rawRoot=Join-Path $snapshotRoot ("raw/$name")
    $classesRaw=Join-Path $rawRoot 'classes'
    $dexRaw=Join-Path $rawRoot 'dex'
    $evidence=Join-Path $one 'evidence'
    New-Item -ItemType Directory -Path $classesRaw,$dexRaw,$evidence | Out-Null
    & $javac -encoding UTF-8 --release 8 -classpath $androidJar -d $classesRaw `
        $activitySource $lifecycleSource $layoutSource
    if ($LASTEXITCODE -ne 0) {throw "Native page host compilation failed ($name)"}
    Assert-ReviewedFileSet $classesRaw $reviewedProductionClassSha256 `
        "raw production classes ($name)"
    $rawClassFiles=@(Get-ChildItem -LiteralPath $classesRaw -Recurse -File -Filter '*.class' |
        Sort-Object FullName)
    if ($rawClassFiles.Count -lt 4) {throw "Native page host class inventory is incomplete ($name)"}
    $classes=Join-Path $snapshotRoot ("generated/$name/classes")
    $classFiles=@()
    foreach ($classFile in $rawClassFiles) {
        $relative=$classFile.FullName.Substring($classesRaw.Length + 1)
        $classFiles += Copy-LockedSnapshot $classFile.FullName ("generated/$name/classes/$relative")
    }
    Assert-ReviewedFileSet $classes $reviewedProductionClassSha256 `
        "retained production classes ($name)" $true
    $activityBytecodeBytes=Invoke-JavapCanonicalEvidence @(
        '-J-Dfile.encoding=UTF-8','-classpath',$classes,'-c','-p',
        'com.techrebbe.supernote.nativepagehost.NativePageHostActivity') `
        "Native page host bytecode inspection ($name)"
    $activityBytecode=Write-LockedSnapshot `
        (Join-Path $snapshotRoot "generated/$name/NativePageHostActivity.javap.txt") `
        $activityBytecodeBytes
    $lifecycleBytecodeBytes=Invoke-JavapCanonicalEvidence @(
        '-J-Dfile.encoding=UTF-8','-classpath',$classes,'-c','-p',
        'com.techrebbe.supernote.viewportprobe.NativePageHostLifecycle') `
        "Native page host lifecycle bytecode inspection ($name)"
    $lifecycleBytecode=Write-LockedSnapshot `
        (Join-Path $snapshotRoot "generated/$name/NativePageHostLifecycle.javap.txt") `
        $lifecycleBytecodeBytes
    $layoutBytecodeBytes=Invoke-JavapCanonicalEvidence @(
        '-J-Dfile.encoding=UTF-8','-classpath',$classes,'-c','-p',
        'com.techrebbe.supernote.viewportprobe.DisplayProbeLayout',
        'com.techrebbe.supernote.viewportprobe.DisplayProbeLayout$Placement') `
        "Display layout bytecode inspection ($name)"
    $layoutBytecode=Write-LockedSnapshot `
        (Join-Path $snapshotRoot "generated/$name/DisplayProbeLayout.javap.txt") `
        $layoutBytecodeBytes
    & $d8 --min-api 30 --lib $androidJar --output $dexRaw @classFiles
    if ($LASTEXITCODE -ne 0) {throw "Native page host DEX compilation failed ($name)"}
    Assert-PinnedHash (Join-Path $dexRaw 'classes.dex') $reviewedDexSha256 `
        "raw reviewed DEX ($name)" | Out-Null
    $dexPath=Copy-LockedSnapshot (Join-Path $dexRaw 'classes.dex') `
        "generated/$name/classes.dex"
    if ((Get-RetainedHash $dexPath) -cne $reviewedDexSha256) {
        throw "Retained reviewed DEX differed ($name)"
    }
    $baseApkRaw=Join-Path $rawRoot 'manifest-base.raw.apk'
    & $aapt package -f -M $manifest -I $androidJar -F $baseApkRaw
    if ($LASTEXITCODE -ne 0) {throw "Native page host manifest packaging failed ($name)"}
    $baseApk=Copy-LockedSnapshot $baseApkRaw "generated/$name/manifest-base.apk"
    $canonicalRaw=Join-Path $rawRoot 'canonical-unaligned.raw.apk'
    Invoke-ReviewedPython $canonicalizer @('--base-apk',$baseApk,'--dex',$dexPath,
        '--output',$canonicalRaw) "Native page host canonical packaging ($name)"
    $canonical=Copy-LockedSnapshot $canonicalRaw "generated/$name/canonical-unaligned.apk"
    $alignedRaw=Join-Path $rawRoot 'native-page-host-unsigned.raw.apk'
    & $zipalign -p 4 $canonical $alignedRaw
    if ($LASTEXITCODE -ne 0) {throw "Native page host alignment failed ($name)"}
    Assert-PinnedHash $alignedRaw $reviewedApkSha256 "raw reviewed APK ($name)" | Out-Null
    $aligned=Join-Path $one 'native-page-host-unsigned.apk'
    $aligned=Copy-ToRetainedAuthority $alignedRaw $aligned $artifactLocks
    if ((Get-RetainedHash $aligned) -cne $reviewedApkSha256) {
        throw "Retained reviewed APK differed ($name)"
    }
    & $zipalign -c 4 $aligned
    if ($LASTEXITCODE -ne 0) {throw "Native page host alignment verification failed ($name)"}
    $evidenceBundleBytes=Invoke-ReviewedPythonCaptured $inspector @(
        '--apk',$aligned,'--aapt',$aapt,
        '--aapt-sha256',$toolHashes.aapt,'--expected-dex',$dexPath,
        '--toolchain-authority',$toolchainAuthorityPath,'--manifest',$manifest,
        '--activity-source',$activitySource,'--lifecycle-source',$lifecycleSource,
        '--layout-source',$layoutSource,'--lifecycle-test',$lifecycleTest,
        '--canonicalizer',$canonicalizer,'--package-tests',$packageTests,
        '--readme',$hostReadme,'--build-script',$buildScriptSnapshot,
        '--activity-bytecode',$activityBytecode,'--lifecycle-bytecode',$lifecycleBytecode,
        '--layout-bytecode',$layoutBytecode
    ) "Native page host package inspection ($name)" 8MB
    try {
        $evidenceBundleText=[Text.UTF8Encoding]::new($false,$true).GetString(
            $evidenceBundleBytes)
        $evidenceBundle=$evidenceBundleText | ConvertFrom-Json
    } catch { throw "Native page host evidence bundle was not strict JSON ($name)" }
    $evidenceNames=@('permissions.txt','badging.txt','manifest-xmltree.txt',
        'apk-descriptor-snapshot.json','activity-bytecode.txt','lifecycle-bytecode.txt',
        'layout-bytecode.txt','package-authority.json')
    if ($evidenceBundle.schema -cne 'native-page-host-evidence-bundle-v1' `
            -or @($evidenceBundle.PSObject.Properties).Count -ne 3 `
            -or @($evidenceBundle.files.PSObject.Properties).Count -ne $evidenceNames.Count) {
        throw "Native page host evidence bundle topology differed ($name)"
    }
    foreach ($evidenceName in $evidenceNames) {
        $record=$evidenceBundle.files.$evidenceName
        if ($null -eq $record -or @($record.PSObject.Properties).Count -ne 3 `
                -or $record.sha256 -notmatch '^[0-9a-f]{64}$' `
                -or -not (($record.size -is [int]) -or ($record.size -is [long])) `
                -or $record.size -lt 1 `
                -or $record.size -gt 8MB) {
            throw "Native page host evidence record differed ($name/$evidenceName)"
        }
        try { $payload=[Convert]::FromBase64String([string]$record.base64) }
        catch { throw "Native page host evidence base64 was invalid ($name/$evidenceName)" }
        if ($payload.Length -ne $record.size `
                -or (Get-BytesSha256 $payload) -cne $record.sha256) {
            throw "Native page host evidence digest differed ($name/$evidenceName)"
        }
        Write-ToRetainedAuthority (Join-Path $evidence $evidenceName) `
            $payload $artifactLocks | Out-Null
    }
    if ((Get-RetainedHash (Join-Path $evidence 'package-authority.json')) `
            -cne $evidenceBundle.authoritySha256) {
        throw "Native page host bundled authority digest differed ($name)"
    }
    $authorityPath=Join-Path $evidence 'package-authority.json'
    $apkSha=Get-RetainedHash $aligned
    $dexSha=Get-RetainedHash $dexPath
    if ($apkSha -cne $reviewedApkSha256 -or $dexSha -cne $reviewedDexSha256) {
        throw "Retained fixed output authority differed ($name)"
    }
    $authority=[Text.Encoding]::UTF8.GetString(
        (Read-RetainedBytes $authorityPath)) | ConvertFrom-Json
    $permissionsSha=Get-RetainedHash (Join-Path $evidence 'permissions.txt')
    $badgingSha=Get-RetainedHash (Join-Path $evidence 'badging.txt')
    $xmltreeSha=Get-RetainedHash (Join-Path $evidence 'manifest-xmltree.txt')
    $descriptorSha=Get-RetainedHash (Join-Path $evidence 'apk-descriptor-snapshot.json')
    $activityEvidenceSha=Get-RetainedHash (Join-Path $evidence 'activity-bytecode.txt')
    $lifecycleEvidenceSha=Get-RetainedHash (Join-Path $evidence 'lifecycle-bytecode.txt')
    $layoutEvidenceSha=Get-RetainedHash (Join-Path $evidence 'layout-bytecode.txt')
    $toolchainAuthoritySha=Get-RetainedHash $toolchainAuthorityPath
    $sourceAuthority=[ordered]@{
        'native-page-host/AndroidManifest.xml'=Get-RetainedHash $manifest
        'native-page-host/src/com/techrebbe/supernote/nativepagehost/NativePageHostActivity.java'=Get-RetainedHash $activitySource
        'java/com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle.java'=Get-RetainedHash $lifecycleSource
        'java/com/techrebbe/supernote/viewportprobe/DisplayProbeLayout.java'=Get-RetainedHash $layoutSource
        'test/NativePageHostLifecycleTest.java'=Get-RetainedHash $lifecycleTest
        'native-page-host/canonicalize_apk.py'=Get-RetainedHash $canonicalizer
        'native-page-host/inspect_native_page_host.py'=Get-RetainedHash $inspector
        'native-page-host/test_native_page_host_package.py'=Get-RetainedHash $packageTests
        'native-page-host/README.md'=Get-RetainedHash $hostReadme
        'build-native-page-host.ps1'=Get-RetainedHash $buildScriptSnapshot
    }
    $sourceAuthorityMismatch=$false
    foreach ($sourceName in $sourceAuthority.Keys) {
        if ($authority.sources.$sourceName -cne $sourceAuthority[$sourceName]) {
            $sourceAuthorityMismatch=$true
        }
    }
    if (@($authority.sources.PSObject.Properties).Count -ne ($sourceAuthority.Count + 3)) {
        $sourceAuthorityMismatch=$true
    }
    if (($authority.schema -cne 'native-page-host-package-v2') -or
            ($authority.apkSha256 -cne $apkSha) -or
            ($authority.dexSha256 -cne $dexSha) -or
            ($authority.reviewedDexSha256 -cne $dexSha) -or
            ($authority.packagedDexExactReviewedMatch -ne $true) -or
            ($authority.aaptSha256 -cne $toolHashes.aapt) -or
            ($authority.toolchainAuthoritySha256 -cne $toolchainAuthoritySha) -or
            ($authority.permissionsSha256 -cne $permissionsSha) -or
            ($authority.badgingSha256 -cne $badgingSha) -or
            ($authority.manifestXmltreeSha256 -cne $xmltreeSha) -or
            ($authority.descriptorSnapshotSha256 -cne $descriptorSha) -or
            ($authority.sources.'native-page-host/evidence/NativePageHostActivity.javap.txt' `
                -cne $activityEvidenceSha) -or
            ($authority.sources.'native-page-host/evidence/NativePageHostLifecycle.javap.txt' `
                -cne $lifecycleEvidenceSha) -or
            ($authority.sources.'native-page-host/evidence/DisplayProbeLayout.javap.txt' `
                -cne $layoutEvidenceSha) -or $sourceAuthorityMismatch) {
        throw "Final artifacts differ from package-authority.json ($name)"
    }
    return [PSCustomObject]@{
        Name=$name
        Apk=$aligned
        Dex=$dexPath
        Authority=$authorityPath
        ApkSha256=$apkSha
        DexSha256=$dexSha
    }
}

$priorJavaHome=$env:JAVA_HOME
try {
    $env:JAVA_HOME=$Jdk
    $first=Build-One 'first'
    $second=Build-One 'second'
} finally {
    $env:JAVA_HOME=$priorJavaHome
}

if ($first.ApkSha256 -ne $second.ApkSha256) {
    throw 'Independent native page host APK builds were not byte-identical'
}
if ($first.DexSha256 -ne $second.DexSha256) {
    throw 'Independent native page host DEX builds were not byte-identical'
}
$firstAuthority=Read-RetainedBytes $first.Authority
$secondAuthority=Read-RetainedBytes $second.Authority
if ($firstAuthority.Length -ne $secondAuthority.Length -or
        [Convert]::ToBase64String($firstAuthority) -cne [Convert]::ToBase64String($secondAuthority)) {
    throw 'Independent native page host package authorities were not byte-identical'
}

# Recheck every retained tool path after both builds. The retained handles make
# replacement impossible; these comparisons also catch unexpected in-place drift.
if (((Assert-PinnedHash $androidJar $toolHashes.androidJar 'final android.jar') -cne $toolHashes.androidJar) -or
        ((Assert-PinnedHash $java $toolHashes.java 'final java.exe') -cne $toolHashes.java) -or
        ((Assert-PinnedHash $javac $toolHashes.javac 'final javac.exe') -cne $toolHashes.javac) -or
        ((Assert-PinnedHash $javap $toolHashes.javap 'final javap.exe') -cne $toolHashes.javap) -or
        ((Assert-PinnedHash $jdkRelease $toolHashes.jdkRelease 'final JDK release') -cne $toolHashes.jdkRelease) -or
        ((Assert-PinnedHash $jdkModules $toolHashes.jdkModules 'final JDK modules') -cne $toolHashes.jdkModules) -or
        ((Assert-PinnedHash $jvmDll $toolHashes.jvm 'final jvm.dll') -cne $toolHashes.jvm) -or
        ((Assert-PinnedHash $Python $toolHashes.python 'final python.exe') -cne $toolHashes.python) -or
        ((Assert-PinnedHash $pythonDll $toolHashes.pythonDll 'final python312.dll') -cne $toolHashes.pythonDll) -or
        ((Assert-PinnedHash $d8 $toolHashes.d8Bat 'final d8.bat') -cne $toolHashes.d8Bat) -or
        ((Assert-PinnedHash $d8Jar $toolHashes.d8Jar 'final d8.jar') -cne $toolHashes.d8Jar) -or
        ((Assert-PinnedHash $aapt $toolHashes.aapt 'final aapt.exe') -cne $toolHashes.aapt) -or
        ((Assert-PinnedHash $zipalign $toolHashes.zipalign 'final zipalign.exe') -cne $toolHashes.zipalign) -or
        ((Assert-PinnedHash $powershell5Source $toolHashes.powershell5Launcher 'final Windows PowerShell 5.1 launcher') -cne $toolHashes.powershell5Launcher) -or
        ((Assert-PinnedHash $powershell7 $toolHashes.powershell7Launcher 'final PowerShell 7 launcher') -cne $toolHashes.powershell7Launcher)) {
    throw 'Retained toolchain authority changed across the build'
}
Assert-ReviewedPythonRuntimeAuthority
Assert-ReviewedPythonHelperAuthority

$summary='NATIVE_PAGE_HOST_DETERMINISTIC apkSha256=' + $first.ApkSha256 + ' dexSha256=' + $first.DexSha256
Write-Output $summary
Write-Output 'UNSIGNED NATIVE-PAGE VISUAL-ONLY APK. Not installable, not a reader/pen gate.'
Write-Output $first.Apk
} finally {
    if ($null -ne $artifactLocks) {
        foreach ($handle in $artifactLocks) { $handle.Dispose() }
    }
    if ($null -ne $snapshotLocks) {
        foreach ($handle in $snapshotLocks) { $handle.Dispose() }
    }
    foreach ($handle in $toolLocks) { $handle.Dispose() }
}
