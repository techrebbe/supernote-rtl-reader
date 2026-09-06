param([Parameter(Mandatory=$true)][string]$Ndk)
$ErrorActionPreference='Stop'
$clang=Join-Path $Ndk 'toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android30-clang.cmd'
if(!(Test-Path -LiteralPath $clang)){throw 'Pinned Android AArch64 API 30 compiler unavailable'}
$out=Join-Path $PSScriptRoot ('build/pen-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $out | Out-Null
foreach($entry in @(@('pen_device_probe.c','pen-device-probe'),@('pen_grab_core_test.c','pen-grab-core-test'))) {
    & $clang -std=c11 -D_GNU_SOURCE -O2 -Wall -Wextra -Werror -fPIE -pie '-Wl,-z,relro,-z,now' (Join-Path $PSScriptRoot ('native/'+$entry[0])) -o (Join-Path $out $entry[1])
    if($LASTEXITCODE -ne 0){throw ('Native probe compile failed: '+$entry[0])}
}
Write-Output $out
Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $out 'pen-device-probe'),(Join-Path $out 'pen-grab-core-test')
Write-Output 'BUILT ONLY. Exact-source review required before any device run. No held pen barrier or Document viewport readiness.'
