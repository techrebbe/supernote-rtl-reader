Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'path-guard.ps1')

$root = $PSScriptRoot
$generation = New-IgnoredBuildGeneration $root 'guard-test-'
$null = Assert-IgnoredBuildPath (Join-Path $generation 'future.json') $root
$escaped = [IO.Path]::GetFullPath((Join-Path $root 'outside.json'))
try {
    $null = Assert-IgnoredBuildPath $escaped $root
    throw 'Lexical escape unexpectedly passed.'
} catch {
    if ($_.Exception.Message -ceq 'Lexical escape unexpectedly passed.') { throw }
}

# The junction and its target stay in this unique ignored generation. No cleanup
# targets or deletes anything outside it, and failed junction creation is reported.
$target = Join-Path $generation 'target'
$link = Join-Path $generation 'junction'
New-Item -ItemType Directory -Path $target -ErrorAction Stop | Out-Null
$junctionAvailable = $true
try {
    New-Item -ItemType Junction -Path $link -Target $target -ErrorAction Stop | Out-Null
} catch {
    $junctionAvailable = $false
}
if ($junctionAvailable) {
    $item = Get-Item -LiteralPath $link -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
        throw 'Junction test object was not marked as a reparse point.'
    }
    try {
        $null = Assert-IgnoredBuildPath (Join-Path $link 'future.json') $root
        throw 'Junction unexpectedly passed the output-path guard.'
    } catch {
        if ($_.Exception.Message -ceq 'Junction unexpectedly passed the output-path guard.') {
            throw
        }
    }
    Write-Output 'PASS ignored-build lexical and junction guard'
} else {
    Write-Output 'PASS ignored-build lexical guard; junction creation unavailable in sandbox'
}
