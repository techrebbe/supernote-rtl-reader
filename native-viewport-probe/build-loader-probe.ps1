param([Parameter(Mandatory=$true)][string]$Ndk)
$ErrorActionPreference='Stop'
$clang=Join-Path $Ndk 'toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android30-clang.cmd'
if (!(Test-Path -LiteralPath $clang)) { throw 'Android compiler unavailable' }
$out=Join-Path $PSScriptRoot ('build/loader-probe-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $out | Out-Null
$fixture=Join-Path $out 'loader-fixture.so'
& $clang -std=c11 -O2 -Wall -Wextra -Werror -fPIC -shared '-Wl,-z,relro,-z,now' (Join-Path $PSScriptRoot 'native/loader_fixture.c') -o $fixture
if ($LASTEXITCODE -ne 0) { throw 'Authored fixture compilation failed' }
$fixtureBytes=[System.IO.File]::ReadAllBytes($fixture)
if ($fixtureBytes.Length -eq 0 -or $fixtureBytes.Length -gt 131072) { throw 'Fixture byte budget exceeded' }
$header=[System.Text.StringBuilder]::new()
[void]$header.AppendLine('/* Generated from the authored constructor fixture; no firmware. */')
[void]$header.AppendLine('static const unsigned char loader_fixture_blob[] = {')
for ($offset=0; $offset -lt $fixtureBytes.Length; $offset+=16) {
    $last=[Math]::Min($offset+15,$fixtureBytes.Length-1)
    $values=for ($index=$offset; $index -le $last; $index++) { '0x{0:x2}' -f $fixtureBytes[$index] }
    [void]$header.AppendLine(($values -join ',') + ',')
}
[void]$header.AppendLine('};')
[void]$header.AppendLine('static const size_t loader_fixture_blob_size = sizeof(loader_fixture_blob);')
[System.IO.File]::WriteAllText((Join-Path $out 'loader_fixture_blob.h'),$header.ToString(),[System.Text.UTF8Encoding]::new($false))
$source=Join-Path $PSScriptRoot 'native/loader_android_probe.c'
$binary=Join-Path $out 'loader-android-probe'
& $clang -std=c11 -O2 -Wall -Wextra -Werror -fPIE -pie '-Wl,-z,relro,-z,now' -I $out $source -ldl -o $binary
if ($LASTEXITCODE -ne 0) { throw 'Android fixture-only loader compilation failed' }
& $clang --analyze -std=c11 -Wall -Wextra -Werror -I $out $source -o (Join-Path $out 'loader-analysis.plist')
if ($LASTEXITCODE -ne 0) { throw 'Android loader static analysis failed' }
Write-Output $out
Get-FileHash -Algorithm SHA256 -LiteralPath $fixture,$binary
Write-Output 'BUILD ONLY. Embedded authored fixture, not Supernote firmware. Independent integrated exact-source review and owned-device preflight required before execution.'
