$ErrorActionPreference = 'Stop'

$projectRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$testRoot = Join-Path $projectRoot 'build/tests'
if (-not $testRoot.StartsWith(
        $projectRoot,
        [System.StringComparison]::OrdinalIgnoreCase
    )) {
    throw "Refusing to clean test directory outside project: $testRoot"
}
if (Test-Path -LiteralPath $testRoot) {
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $testRoot | Out-Null

& javac `
    -source 8 `
    -target 8 `
    -encoding UTF-8 `
    -d $testRoot `
    (Join-Path $projectRoot `
        'src/com/techrebbe/supernote/virtualspread/VirtualSpreadNavigation.java') `
    (Join-Path $projectRoot `
        'src/com/techrebbe/supernote/virtualspread/VirtualSpreadLinkAuthority.java') `
    (Join-Path $projectRoot `
        'src/com/techrebbe/supernote/virtualspread/NativeViewportAuthority.java') `
    (Join-Path $projectRoot `
        'src/com/techrebbe/supernote/virtualspread/NativeViewportGenerationFence.java') `
    (Join-Path $projectRoot 'tests/VirtualSpreadLinkAuthorityTest.java') `
    (Join-Path $projectRoot 'tests/NativeViewportAuthorityTest.java') `
    (Join-Path $projectRoot `
        'tests/NativeViewportGenerationFenceTest.java') `
    (Join-Path $projectRoot 'tests/VirtualSpreadNavigationTest.java') `
    (Join-Path $projectRoot `
        'tests/VirtualSpreadNavigationExhaustiveTest.java')
if ($LASTEXITCODE -ne 0) {
    throw "navigation test compilation failed with exit code $LASTEXITCODE"
}

& java -cp $testRoot VirtualSpreadLinkAuthorityTest
if ($LASTEXITCODE -ne 0) {
    throw "link-authority tests failed with exit code $LASTEXITCODE"
}

& java -cp $testRoot VirtualSpreadNavigationTest
if ($LASTEXITCODE -ne 0) {
    throw "navigation tests failed with exit code $LASTEXITCODE"
}

& java -cp $testRoot VirtualSpreadNavigationExhaustiveTest
if ($LASTEXITCODE -ne 0) {
    throw "exhaustive navigation tests failed with exit code $LASTEXITCODE"
}

& java -cp $testRoot NativeViewportAuthorityTest
if ($LASTEXITCODE -ne 0) {
    throw "native viewport authority tests failed with exit code $LASTEXITCODE"
}

& java -cp $testRoot NativeViewportGenerationFenceTest
if ($LASTEXITCODE -ne 0) {
    throw "native viewport generation-fence tests failed with exit code $LASTEXITCODE"
}

& python (Join-Path $projectRoot 'tests/check_scope.py')
if ($LASTEXITCODE -ne 0) {
    throw "hook scope checks failed with exit code $LASTEXITCODE"
}
