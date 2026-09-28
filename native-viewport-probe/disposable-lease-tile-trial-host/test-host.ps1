[CmdletBinding()]
param([string]$Jdk = $env:JAVA_HOME)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Jdk)) { throw 'Pass -Jdk or set JAVA_HOME.' }
$javac = Join-Path $Jdk 'bin\javac.exe'
$java = Join-Path $Jdk 'bin\java.exe'
foreach ($path in @($javac, $java)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing JDK tool: $path"
    }
}
$root = $PSScriptRoot
$package = Join-Path $root 'src\com\techrebbe\supernote\leasetiletrial'
$generation = Join-Path $root ('build\host-test-' + [Guid]::NewGuid().ToString('N'))
$classes = Join-Path $generation 'classes'
New-Item -ItemType Directory -Path $classes -ErrorAction Stop | Out-Null
& $javac -encoding UTF-8 --release 8 -d $classes `
    (Join-Path $package 'TileTrialEvidence.java') `
    (Join-Path $root 'tests\TileTrialEvidenceTest.java')
if ($LASTEXITCODE -ne 0) { throw 'Tile trial host-test compilation failed.' }
& $java -cp $classes com.techrebbe.supernote.leasetiletrial.TileTrialEvidenceTest `
    (Join-Path $root 'AndroidManifest.xml') `
    (Join-Path $package 'TileTrialActivity.java') `
    (Join-Path $package 'TileTrialProvider.java') `
    (Join-Path $package 'TileTrialState.java')
if ($LASTEXITCODE -ne 0) { throw 'Tile trial host tests failed.' }
