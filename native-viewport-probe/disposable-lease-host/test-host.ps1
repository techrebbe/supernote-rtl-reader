[CmdletBinding()]
param([string]$Jdk = $env:JAVA_HOME)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Jdk)) { throw 'Pass -Jdk or set JAVA_HOME.' }
$javac = Join-Path $Jdk 'bin\javac.exe'
$java = Join-Path $Jdk 'bin\java.exe'
foreach ($path in @($javac, $java)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing JDK tool: $path" }
}
$root = $PSScriptRoot
$package = Join-Path $root 'src\com\techrebbe\supernote\disposableleasehost'
$generation = Join-Path $root ('build\host-test-' + [Guid]::NewGuid().ToString('N'))
$classes = Join-Path $generation 'classes'
New-Item -ItemType Directory -Path $classes -ErrorAction Stop | Out-Null
$sources = @(
    (Join-Path $package 'ProbeContract.java'),
    (Join-Path $package 'ProbeModel.java'),
    (Join-Path $package 'EventRing.java'),
    (Join-Path $package 'LeaseSlot.java'),
    (Join-Path $package 'ActivityAdmission.java'),
    (Join-Path $package 'PaintEpoch.java'),
    (Join-Path $package 'CoverGate.java'),
    (Join-Path $package 'ProbeLedger.java'),
    (Join-Path $root 'tests\HostContractTest.java')
)
& $javac -encoding UTF-8 --release 8 -d $classes @sources
if ($LASTEXITCODE -ne 0) { throw 'Pure-Java host contract compilation failed.' }
& $java -cp $classes com.techrebbe.supernote.disposableleasehost.HostContractTest `
    (Join-Path $root 'AndroidManifest.xml') (Join-Path $package 'ProbeActivity.java')
if ($LASTEXITCODE -ne 0) { throw 'Host contract test failed.' }
