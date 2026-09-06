param(
    [Parameter(Mandatory=$true)][string]$Ndk,
    [string]$HostCc = 'gcc'
)
$ErrorActionPreference = 'Stop'
$clang = Join-Path $Ndk 'toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android30-clang.cmd'
if (!(Test-Path -LiteralPath $clang)) { throw 'Android AArch64 API30 compiler unavailable' }
$hostCompiler = (Get-Command $HostCc -ErrorAction Stop).Source
$out = Join-Path $PSScriptRoot ('build/isolation-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $out | Out-Null
foreach ($test in @('isolation_core_test', 'isolation_filter_test')) {
    $source = Join-Path $PSScriptRoot ('native/' + $test + '.c')
    $binary = Join-Path $out ($test + '.exe')
    & $hostCompiler -std=c11 -O2 -Wall -Wextra -Werror -pedantic $source -o $binary
    if ($LASTEXITCODE -ne 0) { throw ('Host test compilation failed: ' + $test) }
    & $binary
    if ($LASTEXITCODE -ne 0) { throw ('Host test failed: ' + $test) }
}
foreach ($entry in @('isolation_core_test', 'isolation_filter_test', 'isolation_probe')) {
    & $clang -std=c11 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror -fPIE -pie '-Wl,-z,relro,-z,now' (Join-Path $PSScriptRoot ('native/' + $entry + '.c')) -o (Join-Path $out $entry)
    if ($LASTEXITCODE -ne 0) { throw ('Android compilation failed: ' + $entry) }
}
Write-Output $out
Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $out 'isolation_probe')
Write-Output 'HOST TESTED / ANDROID BUILT ONLY. Independent exact-source review required before any device run. No firmware loader or native-writer admission.'
