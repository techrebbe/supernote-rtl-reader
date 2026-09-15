param(
    [Parameter(Mandatory=$true)][string]$Python,
    [string]$Before,
    [string]$After,
    [string]$FramedBefore,
    [string]$FramedAfter,
    [Parameter(Mandatory=$true)]
    [ValidateSet('unchanged','one-addition')][string]$Expect,
    [Parameter(Mandatory=$true)][string]$ExpectedSourceSha256,
    [switch]$ExpectJavaGolden
)
$ErrorActionPreference='Stop'
$arguments=@()
if ($PSBoundParameters.ContainsKey('Before')) {
    $arguments+=$Before
}
if ($PSBoundParameters.ContainsKey('After')) {
    $arguments+=$After
}
if ($PSBoundParameters.ContainsKey('FramedBefore')) {
    $arguments+=@('--framed-before', $FramedBefore)
}
if ($PSBoundParameters.ContainsKey('FramedAfter')) {
    $arguments+=@('--framed-after', $FramedAfter)
}
$arguments+=@('--expect', $Expect,
    '--expected-source-sha256', $ExpectedSourceSha256)
if ($ExpectJavaGolden) {
    $arguments+='--expect-java-golden'
}
& (Join-Path $PSScriptRoot 'invoke-authenticated-production.ps1') `
    -Python $Python -Mode ink-oracle -CommandArguments $arguments
exit $LASTEXITCODE
