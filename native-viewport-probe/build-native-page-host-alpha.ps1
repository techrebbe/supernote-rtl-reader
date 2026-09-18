[CmdletBinding()]
param(
    [string]$Jdk = $(
        if ($env:RTL_READER_BUILD_JDK) {
            $env:RTL_READER_BUILD_JDK
        } else {
            'C:\Program Files\Java\jdk-17'
        }
    ),
    [string]$AndroidSdk = $(
        if ($env:ANDROID_SDK_ROOT) {
            $env:ANDROID_SDK_ROOT
        } elseif ($env:ANDROID_HOME) {
            $env:ANDROID_HOME
        } else {
            Join-Path $env:LOCALAPPDATA 'Android\Sdk'
        }
    ),
    [string]$Python = $(Join-Path ([Environment]::GetFolderPath('UserProfile')) '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'),
    [string]$IdentityDirectory = $(Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'SupernoteAlpha\NativePageHost'),
    [string]$OutputDirectory = '',
    [string]$UnsignedApk = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSBoundParameters.ContainsKey('OutputDirectory')) {
    if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
        throw 'Alpha output directory may not be explicitly empty.'
    }
} else {
    # PSScriptRoot is not reliably populated while a script parameter default
    # expression is being bound by Windows PowerShell. Resolve the default only
    # after parameter binding, when this script's location is authoritative.
    $OutputDirectory = Join-Path $PSScriptRoot 'build\native-page-host-alpha'
}

$packageName = 'com.techrebbe.supernote.nativepagehost'
$versionCode = 2
$versionName = '0.0.2-native-page-visual-only'
$keyAlias = 'nativepagehostalpha'
$buildTools = Join-Path $AndroidSdk 'build-tools\35.0.0'
$aapt = Join-Path $buildTools 'aapt.exe'
$apksignerJar = Join-Path $buildTools 'lib\apksigner.jar'
$zipalign = Join-Path $buildTools 'zipalign.exe'
$java = Join-Path $Jdk 'bin\java.exe'
$keytool = Join-Path $Jdk 'bin\keytool.exe'
$authoritativeBuild = Join-Path $PSScriptRoot 'build-native-page-host.ps1'
$windowsPowerShell = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
$powerShell7 = Join-Path (Split-Path -Parent (Split-Path -Parent $Python)) 'native\powershell\pwsh.exe'
$tar = 'C:\Windows\System32\tar.exe'
$gitCommand = Get-Command git.exe -ErrorAction Stop
$git = $gitCommand.Source
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$reviewedCheckpoint = '2eeadd701d25dfeaf978108c358326e8edfaf87d'
$reviewedUnsignedApkSha256 = '670c755fabb00df87c6b6714c3dc8b878aa22e3190d95585b24adce295756178'
$reviewedUnsignedAuthoritySha256 = '94783276471ad4797b9a4ebf2200ae7adfd1ce1fe6ad888e2b5df09b403cb647'
$reviewedDexSha256 = '15d24cef8f4c70cf167ab6e93ac817fc2e85af4bfca6bb392e2535dc04863ab6'
$reviewedSignerCertSha256 = 'd3f9ce76640125df1037e4536b680e29684da5ae7c171147f3206e26c7e568b4'
$reviewedSignedApkSha256 = '3798c204360db82941db7516e774517b273a51e025cce4848a642a5de61c6a03'
$javaSha256 = '9da06bd6c880c0c8d1a63e3716f8ef7996f146c41e6d339e4eafc93df28392f9'
$keytoolSha256 = '5caa8a6a7aa9f1372a089af21ef94b0fcb27462200ef58203211455241c16406'
$apksignerJarSha256 = '00ef9948f843fe395d2440ae3ef41405b8040a6d5d46493bd1902ac0ee6deae7'
$aaptSha256 = 'db0ba2050b8f6b37185d2ba458d6e25b565aefa3f3b96040adf0a82c3469ce3c'
$zipalignSha256 = 'aa2475ce201962b871fb8daec020da03fd6292c9c1f422cd0fe2e39b20d4f673'
$utf8NoBom = [Text.UTF8Encoding]::new($false)

function Get-Sha256([string]$LiteralPath) {
    return (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-RegularFile([string]$LiteralPath, [string]$Label) {
    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
        throw "$Label is missing: $LiteralPath"
    }
    $item = Get-Item -LiteralPath $LiteralPath -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label may not be a reparse point: $LiteralPath"
    }
}

function Assert-PinnedFile([string]$LiteralPath, [string]$ExpectedSha256, [string]$Label) {
    Assert-RegularFile $LiteralPath $Label
    $actual = Get-Sha256 $LiteralPath
    if ($actual -cne $ExpectedSha256) {
        throw "$Label differs from its fixed SHA-256 authority."
    }
}

function Assert-NoReparseComponents([string]$LiteralPath, [string]$Label) {
    $full = [IO.Path]::GetFullPath($LiteralPath)
    $root = [IO.Path]::GetPathRoot($full)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw "$Label is not an absolute local path."
    }
    $current = $root
    if (Test-Path -LiteralPath $current) {
        $rootItem = Get-Item -LiteralPath $current -Force
        if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label has a reparse-point path root."
        }
    }
    $relative = $full.Substring($root.Length)
    foreach ($component in @($relative -split '[\\/]' | Where-Object { $_.Length -gt 0 })) {
        $current = Join-Path $current $component
        if (-not (Test-Path -LiteralPath $current)) {
            break
        }
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "$Label contains a reparse point: $current"
        }
    }
    return $full
}

function Test-ContainedPath([string]$Candidate, [string]$Root) {
    $candidateFull = [IO.Path]::GetFullPath($Candidate)
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd([char[]]@('\', '/'))
    if ($candidateFull.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    $rootPrefix = $rootFull + [IO.Path]::DirectorySeparatorChar
    return $candidateFull.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)
}

function Read-UnsignedAuthority([string]$ApkPath) {
    $resolved = [IO.Path]::GetFullPath($ApkPath)
    Assert-RegularFile $resolved 'Authoritative unsigned APK'
    $buildRoot = Join-Path $PSScriptRoot 'build'
    if (-not (Test-ContainedPath $resolved $buildRoot)) {
        throw 'Unsigned APK is not beneath the native-page-host authoritative build root.'
    }
    $artifactDirectory = Split-Path -Parent $resolved
    $generationDirectory = Split-Path -Parent $artifactDirectory
    if ((Split-Path -Leaf $resolved) -cne 'native-page-host-unsigned.apk' -or
            (Split-Path -Leaf $artifactDirectory) -notin @('first', 'second') -or
            (Split-Path -Leaf $generationDirectory) -notmatch '^native-page-host-[0-9a-f]{32}$') {
        throw 'Unsigned APK is not an exact first/second authoritative build artifact.'
    }
    $authorityPath = Join-Path $artifactDirectory 'evidence\package-authority.json'
    Assert-RegularFile $authorityPath 'Unsigned package authority'
    try {
        $authority = [IO.File]::ReadAllText($authorityPath, [Text.Encoding]::UTF8) |
            ConvertFrom-Json
    } catch {
        throw 'Unsigned package authority is not valid JSON.'
    }
    $apkSha256 = Get-Sha256 $resolved
    if ($authority.schema -cne 'native-page-host-package-v2' -or
            $authority.package -cne $packageName -or
            [int]$authority.versionCode -ne $versionCode -or
            $authority.versionName -cne $versionName -or
            $authority.visualOnly -ne $true -or
            $authority.packagedDexExactReviewedMatch -ne $true -or
            $authority.apkSha256 -cne $apkSha256 -or
            $authority.dexSha256 -cne $authority.reviewedDexSha256 -or
            $authority.dexSha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'Unsigned APK differs from its reviewed package authority.'
    }
    return [PSCustomObject]@{
        Apk = $resolved
        ApkSha256 = $apkSha256
        Authority = [IO.Path]::GetFullPath($authorityPath)
        AuthoritySha256 = Get-Sha256 $authorityPath
        DexSha256 = [string]$authority.dexSha256
    }
}

function Invoke-WithoutJavaInjection(
        [scriptblock]$Action,
        [object[]]$ActionArguments = @()) {
    $removed = @{}
    $names = @(
        'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS',
        'JDK_JAVAC_OPTIONS', 'JAVA_OPTIONS', 'CLASSPATH'
    )
    foreach ($entry in [Environment]::GetEnvironmentVariables('Process').GetEnumerator()) {
        $name = [string]$entry.Key
        if ($names -ccontains $name.ToUpperInvariant()) {
            $removed[$name] = [string]$entry.Value
            Remove-Item -LiteralPath ('Env:\' + $name)
        }
    }
    try {
        return & $Action @ActionArguments
    } finally {
        foreach ($name in $removed.Keys) {
            [Environment]::SetEnvironmentVariable($name, $removed[$name], 'Process')
        }
    }
}

function Invoke-WithSecretEnvironment([string]$Secret, [scriptblock]$Action) {
    $variableName = 'NPH_ALPHA_PASS_' + [Guid]::NewGuid().ToString('N')
    [Environment]::SetEnvironmentVariable($variableName, $Secret, 'Process')
    try {
        return Invoke-WithoutJavaInjection -Action $Action -ActionArguments @($variableName)
    } finally {
        Remove-Item -LiteralPath ('Env:\' + $variableName) -ErrorAction SilentlyContinue
    }
}

function Unprotect-LocalSecret([string]$Protected) {
    $secure = ConvertTo-SecureString $Protected
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Export-CertificateSha256([string]$Keystore, [string]$Password, [string]$TemporaryDirectory) {
    $certificate = Join-Path $TemporaryDirectory ('native-page-host-alpha-' + [Guid]::NewGuid().ToString('N') + '.der')
    try {
        Invoke-WithSecretEnvironment $Password {
            param($passwordVariable)
            $arguments = @(
                '-exportcert', '-keystore', $Keystore, '-storetype', 'PKCS12',
                '-storepass:env', $passwordVariable, '-alias', $keyAlias,
                '-file', $certificate
            )
            $savedErrorActionPreference = $ErrorActionPreference
            try {
                # keytool reports its successful export notice on stderr.
                # Capture it without allowing Windows PowerShell to promote the
                # notice into a terminating ErrorRecord; the exit code remains
                # the authority for success.
                $ErrorActionPreference = 'Continue'
                $output = @(& $keytool @arguments 2>&1)
                $keytoolExitCode = $LASTEXITCODE
            } finally {
                $ErrorActionPreference = $savedErrorActionPreference
            }
            if ($keytoolExitCode -ne 0) {
                throw "Local alpha certificate export failed with exit code $keytoolExitCode."
            }
        } | Out-Null
        Assert-RegularFile $certificate 'Exported local alpha certificate'
        return Get-Sha256 $certificate
    } finally {
        if (Test-Path -LiteralPath $certificate -PathType Leaf) {
            Remove-Item -LiteralPath $certificate -Force
        }
    }
}

function Read-PinnedLocalAlphaIdentity([string]$Directory) {
    $identityFull = [IO.Path]::GetFullPath($Directory)
    $repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    if (Test-ContainedPath $identityFull $repositoryRoot) {
        throw 'The pinned local signing identity may not be stored anywhere in the repository.'
    }
    Assert-NoReparseComponents $identityFull 'Pinned local alpha identity path' | Out-Null
    if (-not (Test-Path -LiteralPath $identityFull -PathType Container)) {
        throw 'The fixed local alpha signing identity is missing; it may not be regenerated or rotated automatically.'
    }

    $keystorePath = Join-Path $identityFull 'native-page-host-alpha.p12'
    $credentialPath = Join-Path $identityFull 'password.dpapi'
    $identityPath = Join-Path $identityFull 'identity.json'
    foreach ($required in @($keystorePath, $credentialPath, $identityPath)) {
        Assert-NoReparseComponents $required 'Pinned local alpha identity file path' | Out-Null
        Assert-RegularFile $required 'Complete pinned local alpha identity file'
    }
    $allowedNames = @('native-page-host-alpha.p12', 'password.dpapi', 'identity.json')
    $entries = @(Get-ChildItem -LiteralPath $identityFull -Force)
    if (@($entries | Where-Object {
                $_.PSIsContainer -or
                ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
                $_.Name -notin $allowedNames
            }).Count -ne 0 -or $entries.Count -ne $allowedNames.Count) {
        throw 'Pinned local alpha identity directory contains unexpected entries.'
    }

    $protected = [IO.File]::ReadAllText($credentialPath, [Text.Encoding]::UTF8).Trim()
    if ($protected -notmatch '^[0-9A-Fa-f]+$') {
        throw 'Local alpha credential envelope is malformed.'
    }
    try {
        $identity = [IO.File]::ReadAllText($identityPath, [Text.Encoding]::UTF8) |
            ConvertFrom-Json
    } catch {
        throw 'Local alpha identity record is not valid JSON.'
    }
    if ($identity.schema -cne 'native-page-host-local-alpha-identity-v1' -or
            $identity.package -cne $packageName -or
            $identity.alias -cne $keyAlias -or
            $identity.purpose -cne 'local-disposable-alpha-only' -or
            $identity.certificateSha256 -cne $reviewedSignerCertSha256) {
        throw 'Local alpha identity record differs from the fixed signer authority.'
    }

    $password = Unprotect-LocalSecret $protected
    try {
        $actualCertificateSha256 = Export-CertificateSha256 $keystorePath $password ([IO.Path]::GetTempPath())
        if ($actualCertificateSha256 -cne $reviewedSignerCertSha256) {
            throw 'Local alpha keystore differs from the fixed signer authority.'
        }
        return [PSCustomObject]@{
            Keystore = $keystorePath
            Password = $password
            CertificateSha256 = $actualCertificateSha256
        }
    } catch {
        $password = $null
        throw
    }
}

function Get-ApkSignerSha256([string]$ApkPath) {
    $verification = @(Invoke-WithoutJavaInjection {
        $lines = @(& $java -jar $apksignerJar verify --verbose --print-certs $ApkPath 2>&1 |
            ForEach-Object { [string]$_ })
        $exitCode = $LASTEXITCODE
        if ($exitCode -ne 0) {
            throw "Signed alpha APK verification failed with exit code $exitCode."
        }
        return $lines
    })
    $signerCount = @($verification | Where-Object { $_ -ceq 'Number of signers: 1' }).Count
    $certificateMatches = @($verification | ForEach-Object {
        if ($_ -cmatch '^Signer #1 certificate SHA-256 digest: ([0-9a-f]{64})$') {
            $Matches[1]
        }
    })
    if ($signerCount -ne 1 -or $certificateMatches.Count -ne 1) {
        throw 'Signed alpha APK does not have exactly one canonical signer.'
    }
    return $certificateMatches[0]
}

function Assert-ApkIdentity([string]$ApkPath) {
    $badging = @(& $aapt dump badging $ApkPath 2>&1 | ForEach-Object { [string]$_ })
    $badgingExitCode = $LASTEXITCODE
    if ($badgingExitCode -ne 0) {
        throw "Signed alpha APK badging inspection failed with exit code $badgingExitCode."
    }
    $matches = @($badging | ForEach-Object {
        if ($_ -cmatch "^package: name='([^']+)' versionCode='([0-9]+)' versionName='([^']+)'(?: |$)") {
            [PSCustomObject]@{
                Package = $Matches[1]
                Code = [int]$Matches[2]
                Name = $Matches[3]
            }
        }
    })
    if ($matches.Count -ne 1 -or $matches[0].Package -cne $packageName -or
            $matches[0].Code -ne $versionCode -or $matches[0].Name -cne $versionName) {
        throw 'Signed alpha APK package/version identity changed.'
    }
}

function Get-ClassesDexSha256([string]$ApkPath) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($ApkPath)
    try {
        $entries = @($archive.Entries | Where-Object { $_.FullName -ceq 'classes.dex' })
        if ($entries.Count -ne 1) {
            throw 'APK must contain exactly one classes.dex.'
        }
        $stream = $entries[0].Open()
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            return ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant()
        } finally {
            $sha.Dispose()
            $stream.Dispose()
        }
    } finally {
        $archive.Dispose()
    }
}

function Publish-Atomic([string]$TemporaryPath, [string]$DestinationPath) {
    if (Test-Path -LiteralPath $DestinationPath -PathType Leaf) {
        Assert-RegularFile $DestinationPath 'Existing alpha publication target'
        $backupPath = $DestinationPath + '.replaced-' + [Guid]::NewGuid().ToString('N') + '.bak'
        try {
            [IO.File]::Replace($TemporaryPath, $DestinationPath, $backupPath)
        } finally {
            if (Test-Path -LiteralPath $backupPath -PathType Leaf) {
                Remove-Item -LiteralPath $backupPath -Force
            }
        }
    } else {
        [IO.File]::Move($TemporaryPath, $DestinationPath)
    }
}

function Remove-PrivateMaterialization([string]$Directory) {
    $full = [IO.Path]::GetFullPath($Directory)
    $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
        [char[]]@('\', '/')) + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($temporaryRoot, [StringComparison]::OrdinalIgnoreCase) -or
            (Split-Path -Leaf $full) -notmatch '^native-page-host-alpha-source-[0-9a-f]{32}$') {
        throw 'Refusing to remove an unrecognized source materialization path.'
    }
    if (Test-Path -LiteralPath $full -PathType Container) {
        Remove-Item -LiteralPath $full -Recurse -Force
    }
}

$identityFullPreflight = [IO.Path]::GetFullPath($IdentityDirectory)
if (Test-ContainedPath $identityFullPreflight $repositoryRoot) {
    throw 'The pinned local signing identity may not be stored anywhere in the repository.'
}
Assert-NoReparseComponents $identityFullPreflight 'Pinned local alpha identity path' | Out-Null
$outputFull = [IO.Path]::GetFullPath($OutputDirectory)
$ignoredOutputRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'build'))
if ($outputFull.Equals($ignoredOutputRoot, [StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-ContainedPath $outputFull $ignoredOutputRoot)) {
    throw 'Alpha output directory must be a child of the ignored native-page-host build root.'
}
Assert-NoReparseComponents $outputFull 'Alpha output path' | Out-Null

foreach ($required in @(
        $authoritativeBuild, $aapt, $apksignerJar, $zipalign, $java, $keytool,
        $windowsPowerShell, $powerShell7, $git, $tar)) {
    Assert-RegularFile $required 'Required alpha build tool'
}
Assert-PinnedFile $java $javaSha256 'Pinned java.exe'
Assert-PinnedFile $keytool $keytoolSha256 'Pinned keytool.exe'
Assert-PinnedFile $apksignerJar $apksignerJarSha256 'Pinned apksigner.jar'
Assert-PinnedFile $aapt $aaptSha256 'Pinned aapt.exe'
Assert-PinnedFile $zipalign $zipalignSha256 'Pinned zipalign.exe'

if ([string]::IsNullOrWhiteSpace($UnsignedApk)) {
    foreach ($required in @($Jdk, $AndroidSdk, $Python)) {
        if ([string]::IsNullOrWhiteSpace($required)) {
            throw 'JDK, Android SDK, and pinned Python paths are required for an authoritative build.'
        }
    }
    $removedEnvironment = @{}
    $jvmInjectionNames = @(
        'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS',
        'JDK_JAVAC_OPTIONS', 'JAVA_OPTIONS', 'CLASSPATH'
    )
    foreach ($entry in [Environment]::GetEnvironmentVariables('Process').GetEnumerator()) {
        $name = [string]$entry.Key
        $value = [string]$entry.Value
        if ($value.Length -gt 0 -and
                ($jvmInjectionNames -ccontains $name.ToUpperInvariant() -or
                 $name.StartsWith('PYTHON', [StringComparison]::OrdinalIgnoreCase))) {
            $removedEnvironment[$name] = $value
            Remove-Item -LiteralPath ('Env:\' + $name)
        }
    }
    $materialization = Join-Path ([IO.Path]::GetTempPath()) (
        'native-page-host-alpha-source-' + [Guid]::NewGuid().ToString('N'))
    try {
        $sourceRoot = Join-Path $materialization 'source'
        [IO.Directory]::CreateDirectory($sourceRoot) | Out-Null
        $archive = Join-Path $materialization 'reviewed-source.tar'
        $reviewedInputs = @(
            'native-viewport-probe/build-native-page-host.ps1',
            'native-viewport-probe/native-page-host/AndroidManifest.xml',
            'native-viewport-probe/native-page-host/README.md',
            'native-viewport-probe/native-page-host/canonicalize_apk.py',
            'native-viewport-probe/native-page-host/inspect_native_page_host.py',
            'native-viewport-probe/native-page-host/test_native_page_host_package.py',
            'native-viewport-probe/native-page-host/src/com/techrebbe/supernote/nativepagehost/NativePageHostActivity.java',
            'native-viewport-probe/java/com/techrebbe/supernote/viewportprobe/NativePageHostLifecycle.java',
            'native-viewport-probe/java/com/techrebbe/supernote/viewportprobe/DisplayProbeLayout.java',
            'native-viewport-probe/test/NativePageHostLifecycleTest.java'
        )
        $archiveArguments = @(
            '-C', $repositoryRoot, '-c', 'core.autocrlf=false',
            'archive', '--format=tar',
            ('--output=' + $archive), $reviewedCheckpoint, '--'
        ) + $reviewedInputs
        $archiveOutput = @(& $git @archiveArguments 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "Reviewed source archive failed with exit code $LASTEXITCODE."
        }
        $extractOutput = @(& $tar -xf $archive -C $sourceRoot 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw "Reviewed source extraction failed with exit code $LASTEXITCODE."
        }
        $snapshotBuild = Join-Path $sourceRoot 'native-viewport-probe\build-native-page-host.ps1'
        Assert-RegularFile $snapshotBuild 'Materialized authoritative build'
        $buildArguments = @(
            '-NoProfile', '-NonInteractive', '-NoLogo', '-ExecutionPolicy', 'Bypass',
            '-File', $snapshotBuild,
            '-Jdk', $Jdk,
            '-AndroidSdk', $AndroidSdk,
            '-Python', $Python
        )
        # Windows PowerShell promotes a native child's stderr records to
        # ErrorRecord instances.  The authoritative build writes successful
        # unittest progress to stderr, so the script-wide Stop preference must
        # not terminate this capture before we can inspect the real exit code.
        $savedErrorActionPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $buildOutput = @(& $powerShell7 @buildArguments 2>&1 |
                ForEach-Object { [string]$_ })
            $buildExitCode = $LASTEXITCODE
        } finally {
            $ErrorActionPreference = $savedErrorActionPreference
        }
        foreach ($line in $buildOutput) {
            Write-Host $line
        }
        if ($buildExitCode -ne 0) {
            throw "Authoritative native-page-host build failed with exit code $buildExitCode."
        }
        $nonempty = @($buildOutput | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        if ($nonempty.Count -lt 1) {
            throw 'Authoritative native-page-host build returned no artifact path.'
        }
        $snapshotApk = [IO.Path]::GetFullPath($nonempty[-1].Trim())
        $snapshotBuildRoot = Join-Path $sourceRoot 'native-viewport-probe\build'
        if (-not (Test-ContainedPath $snapshotApk $snapshotBuildRoot)) {
            throw 'Authoritative build returned an artifact outside its private source root.'
        }
        $snapshotGeneration = Split-Path -Parent (Split-Path -Parent $snapshotApk)
        if ((Split-Path -Leaf $snapshotGeneration) -notmatch '^native-page-host-[0-9a-f]{32}$') {
            throw 'Authoritative build returned an unexpected generation path.'
        }
        $workspaceBuildRoot = Join-Path $PSScriptRoot 'build'
        Assert-NoReparseComponents $workspaceBuildRoot 'Authoritative workspace build path' | Out-Null
        [IO.Directory]::CreateDirectory($workspaceBuildRoot) | Out-Null
        Assert-NoReparseComponents $workspaceBuildRoot 'Authoritative workspace build path' | Out-Null
        $workspaceGeneration = Join-Path $workspaceBuildRoot (Split-Path -Leaf $snapshotGeneration)
        if (Test-Path -LiteralPath $workspaceGeneration) {
            throw 'Authoritative generation path unexpectedly already exists.'
        }
        [IO.Directory]::Move($snapshotGeneration, $workspaceGeneration)
        $UnsignedApk = Join-Path $workspaceGeneration 'first\native-page-host-unsigned.apk'
    } finally {
        foreach ($name in $removedEnvironment.Keys) {
            [Environment]::SetEnvironmentVariable($name, $removedEnvironment[$name], 'Process')
        }
        Remove-PrivateMaterialization $materialization
    }
}

$unsigned = Read-UnsignedAuthority $UnsignedApk
$unsignedCheckpointMismatch = ($unsigned.ApkSha256 -cne $reviewedUnsignedApkSha256 -or
    $unsigned.AuthoritySha256 -cne $reviewedUnsignedAuthoritySha256 -or
    $unsigned.DexSha256 -cne $reviewedDexSha256)
if ($unsignedCheckpointMismatch) {
    throw 'Unsigned artifact differs from the frozen alpha checkpoint authority.'
}
$unsignedHashBeforeSigning = Get-Sha256 $unsigned.Apk
$identity = Read-PinnedLocalAlphaIdentity $IdentityDirectory
try {
    Assert-NoReparseComponents $outputFull 'Alpha output path' | Out-Null
    New-Item -ItemType Directory -Path $outputFull -Force | Out-Null
    Assert-NoReparseComponents $outputFull 'Alpha output path' | Out-Null
    $temporaryApk = Join-Path $outputFull ('native-page-host-alpha-' + [Guid]::NewGuid().ToString('N') + '.apk.tmp')
    $temporaryMetadata = Join-Path $outputFull ('native-page-host-alpha-' + [Guid]::NewGuid().ToString('N') + '.json.tmp')
    $finalApk = Join-Path $outputFull 'native-page-host-alpha.apk'
    $finalMetadata = Join-Path $outputFull 'native-page-host-alpha.json'
    try {
        Invoke-WithSecretEnvironment $identity.Password {
            param($passwordVariable)
            $arguments = @(
                '-jar', $apksignerJar, 'sign',
                '--ks', $identity.Keystore, '--ks-key-alias', $keyAlias,
                '--ks-pass', "env:$passwordVariable",
                '--key-pass', "env:$passwordVariable",
                '--v4-signing-enabled', 'false',
                '--out', $temporaryApk, $unsigned.Apk
            )
            $output = @(& $java @arguments 2>&1)
            if ($LASTEXITCODE -ne 0) {
                throw "Local alpha APK signing failed with exit code $LASTEXITCODE."
            }
        } | Out-Null
        Assert-RegularFile $temporaryApk 'Signed alpha APK candidate'
        & $zipalign -c 4 $temporaryApk | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'Signed alpha APK is not zip-aligned.'
        }
        $signerSha256 = Get-ApkSignerSha256 $temporaryApk
        if ($signerSha256 -cne $identity.CertificateSha256 -or
                $signerSha256 -cne $reviewedSignerCertSha256) {
            throw 'Signed alpha APK does not match the fixed signer authority.'
        }
        Assert-ApkIdentity $temporaryApk
        if ((Get-ClassesDexSha256 $temporaryApk) -cne $unsigned.DexSha256) {
            throw 'Signing changed the reviewed classes.dex authority.'
        }
        if ((Get-Sha256 $unsigned.Apk) -cne $unsignedHashBeforeSigning) {
            throw 'Signing mutated the reviewed unsigned APK.'
        }
        $signedSha256 = Get-Sha256 $temporaryApk
        if ($signedSha256 -cne $reviewedSignedApkSha256) {
            throw 'Signed alpha APK differs from the fixed byte authority.'
        }
        $metadata = [ordered]@{
            schema = 'native-page-host-local-alpha-apk-v1'
            package = $packageName
            versionCode = $versionCode
            versionName = $versionName
            signedApkPath = 'native-page-host-alpha.apk'
            signedApkSha256 = $signedSha256
            signerCertSha256 = $signerSha256
            reviewedUnsignedApkSha256 = $unsigned.ApkSha256
            reviewedUnsignedAuthoritySha256 = $unsigned.AuthoritySha256
            dexSha256 = $unsigned.DexSha256
            checkpoint = $reviewedCheckpoint
            diagnosticOnly = $true
            reproducibleUnsignedAuthorityPreserved = $true
            formalReleaseArtifact = $false
        } | ConvertTo-Json -Compress
        [IO.File]::WriteAllText($temporaryMetadata, $metadata + [char]10, $utf8NoBom)
        Publish-Atomic $temporaryApk $finalApk
        Publish-Atomic $temporaryMetadata $finalMetadata
    } finally {
        foreach ($temporary in @($temporaryApk, $temporaryMetadata)) {
            if (Test-Path -LiteralPath $temporary -PathType Leaf) {
                Remove-Item -LiteralPath $temporary -Force
            }
        }
    }
} finally {
    $identity.Password = $null
}

if ((Get-Sha256 $finalApk) -cne $signedSha256) {
    throw 'Published alpha APK differs from the verified signed candidate.'
}
Write-Output (
    'NATIVE_PAGE_HOST_ALPHA_READY package=' + $packageName +
    ' versionCode=' + $versionCode +
    ' signedApkSha256=' + $signedSha256 +
    ' signerSha256=' + $signerSha256)
Write-Output $finalApk
Write-Output $finalMetadata
