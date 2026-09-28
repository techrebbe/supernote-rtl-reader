[CmdletBinding()]
param(
    [string]$Jdk = $env:JAVA_HOME,
    [string]$AndroidSdk = $(if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT }
        else { $env:ANDROID_HOME })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Jdk) -or [string]::IsNullOrWhiteSpace($AndroidSdk)) {
    throw 'Pass -Jdk and -AndroidSdk for the offline Android Port compile test.'
}
$javac = Join-Path $Jdk 'bin\javac.exe'
$java = Join-Path $Jdk 'bin\java.exe'
$androidJar = Join-Path $AndroidSdk 'platforms\android-30\android.jar'
foreach ($required in @($javac, $java, $androidJar)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required compile input missing: $required"
    }
}
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$portPackage = Join-Path $PSScriptRoot 'lease-port-src\com\techrebbe\supernote\disposableleasehost'
$generation = Join-Path $PSScriptRoot ('build\port-test-' + [Guid]::NewGuid().ToString('N'))
$classes = Join-Path $generation 'classes'
New-Item -ItemType Directory -Path $classes -ErrorAction Stop | Out-Null
$sources = @(
    (Join-Path $repo 'java\com\techrebbe\supernote\viewportprobe\TargetOwnedVisualLeaseCore.java'),
    (Join-Path $portPackage 'LeasePaintPassLedger.java'),
    (Join-Path $portPackage 'LeaseEvidenceMutationLedger.java'),
    (Join-Path $portPackage 'AndroidLeasePaintRoot.java'),
    (Join-Path $portPackage 'AndroidLeaseVisualView.java'),
    (Join-Path $portPackage 'AndroidLeasePort.java'),
    (Join-Path $PSScriptRoot 'tests\LeasePaintPassLedgerTest.java'),
    (Join-Path $PSScriptRoot 'tests\LeaseEvidenceMutationLedgerTest.java')
)
& $javac -encoding UTF-8 --release 8 -classpath $androidJar -d $classes @sources
if ($LASTEXITCODE -ne 0) { throw 'Disposable Android Port compilation failed.' }
& $java -classpath $classes com.techrebbe.supernote.disposableleasehost.LeasePaintPassLedgerTest
if ($LASTEXITCODE -ne 0) { throw 'Paint pass contract test failed.' }
& $java -classpath $classes com.techrebbe.supernote.disposableleasehost.LeaseEvidenceMutationLedgerTest
if ($LASTEXITCODE -ne 0) { throw 'Evidence mutation contract test failed.' }
Write-Output 'LEASE_PORT_COMPILE_PASS (offline only; no APK install or device operation)'
