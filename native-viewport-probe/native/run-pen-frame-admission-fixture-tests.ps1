$ErrorActionPreference = 'Stop'

# Host-only model test; never connects to ADB or installs anything.
$compiler = (Get-Command gcc -ErrorAction Stop).Source
$model = Join-Path $PSScriptRoot 'pen_frame_admission_fixture.c'
$tests = Join-Path $PSScriptRoot 'pen_frame_admission_fixture_test.c'
$temporaryDirectory = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$executable = Join-Path $temporaryDirectory ('pen-frame-admission-fixture-' + [guid]::NewGuid().ToString('N') + '.exe')

try {
    & $compiler -std=c11 -O2 -Wall -Wextra -Werror -pedantic $model $tests -o $executable
    if ($LASTEXITCODE -ne 0) { throw 'Host fixture compilation failed.' }
    & $executable
    if ($LASTEXITCODE -ne 0) { throw 'Host fixture assertions failed.' }
} finally {
    if (Test-Path -LiteralPath $executable -PathType Leaf) {
        Remove-Item -LiteralPath $executable -Force
    }
}
