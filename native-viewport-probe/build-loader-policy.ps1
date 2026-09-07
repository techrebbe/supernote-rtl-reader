param(
    [Parameter(Mandatory=$true)][string]$Ndk,
    [string]$HostCc='gcc'
)
$ErrorActionPreference='Stop'
$compiler=Join-Path $Ndk 'toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android30-clang.cmd'
if (!(Test-Path -LiteralPath $compiler)) { throw 'Android compiler unavailable' }
$hostCompiler=(Get-Command $HostCc -ErrorAction Stop).Source
$output=Join-Path $PSScriptRoot ('build/loader-policy-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $output | Out-Null
$source=Join-Path $PSScriptRoot 'native/loader_filter_test.c'
& $hostCompiler -std=c11 -O2 -Wall -Wextra -Werror -pedantic $source -o (Join-Path $output 'loader-filter-test.exe')
if ($LASTEXITCODE -ne 0) { throw 'Host policy test compilation failed' }
& (Join-Path $output 'loader-filter-test.exe')
if ($LASTEXITCODE -ne 0) { throw 'Host policy tests failed' }
$reportSource=Join-Path $PSScriptRoot 'native/loader_report_test.c'
& $hostCompiler -std=c11 -O2 -Wall -Wextra -Werror -pedantic $reportSource -o (Join-Path $output 'loader-report-test.exe')
if ($LASTEXITCODE -ne 0) { throw 'Report protocol test compilation failed' }
& (Join-Path $output 'loader-report-test.exe')
if ($LASTEXITCODE -ne 0) { throw 'Report protocol tests failed' }
& $compiler -std=c11 -O2 -Wall -Wextra -Werror -pedantic -fPIE -pie '-Wl,-z,relro,-z,now' $source -o (Join-Path $output 'loader-filter-test')
if ($LASTEXITCODE -ne 0) { throw 'Android policy interpreter compilation failed' }
& $compiler --analyze -std=c11 -Wall -Wextra -Werror $source -o (Join-Path $output 'loader-filter-analysis.plist')
if ($LASTEXITCODE -ne 0) { throw 'Android policy static analysis failed' }
Write-Output $output
Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $output 'loader-filter-test')
Write-Output 'HOST POLICY TEST ONLY. These binaries interpret BPF and reports; they do not install a filter or load firmware. The separate Android fixture loader is not a native engine.'
