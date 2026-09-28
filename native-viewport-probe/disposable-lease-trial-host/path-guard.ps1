Set-StrictMode -Version Latest

function Assert-IgnoredBuildPath([string]$Candidate, [string]$HostRoot) {
    if ([string]::IsNullOrWhiteSpace($Candidate) -or
            [string]::IsNullOrWhiteSpace($HostRoot)) {
        throw 'Disposable build path and host root are required.'
    }
    $root = [IO.Path]::GetFullPath($HostRoot)
    $build = [IO.Path]::GetFullPath((Join-Path $root 'build'))
    $target = [IO.Path]::GetFullPath($Candidate)
    $separator = [string][IO.Path]::DirectorySeparatorChar
    if (-not ($target.Equals($build, [StringComparison]::OrdinalIgnoreCase) -or
            $target.StartsWith($build + $separator,
                [StringComparison]::OrdinalIgnoreCase))) {
        throw "Path is outside this host's ignored build directory: $target"
    }
    # Check every existing lexical component, including host/project ancestors.
    # A missing output leaf is permitted; an existing junction in its ancestry is not.
    $cursor = $target
    while ($true) {
        $item = Get-Item -LiteralPath $cursor -Force -ErrorAction SilentlyContinue
        if ($null -ne $item -and
                ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing reparse point in disposable output path: $cursor"
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ([string]::IsNullOrEmpty($parent) -or $parent -ceq $cursor) { break }
        $cursor = $parent
    }
    return $target
}

function New-IgnoredBuildGeneration([string]$HostRoot, [string]$Prefix) {
    if ($Prefix -cnotmatch '^[a-z][a-z0-9-]*$') {
        throw 'Invalid disposable generation prefix.'
    }
    $build = Join-Path $HostRoot 'build'
    $null = Assert-IgnoredBuildPath $build $HostRoot
    if (-not (Test-Path -LiteralPath $build -PathType Container)) {
        New-Item -ItemType Directory -Path $build -ErrorAction Stop | Out-Null
    }
    $null = Assert-IgnoredBuildPath $build $HostRoot
    $generation = Join-Path $build ($Prefix + [Guid]::NewGuid().ToString('N'))
    $null = Assert-IgnoredBuildPath $generation $HostRoot
    New-Item -ItemType Directory -Path $generation -ErrorAction Stop | Out-Null
    $null = Assert-IgnoredBuildPath $generation $HostRoot
    return $generation
}
