param([Parameter(Mandatory=$true)][string]$OutputDirectory,[string]$GitHubCli='C:\Program Files\GitHub CLI\gh.exe')
$ErrorActionPreference='Stop'
$lock=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'pdfium.lock.json') -Raw | ConvertFrom-Json
if($lock.publisher -cne 'bblanchon/pdfium-binaries' -or $lock.tag -cne 'chromium/8100' -or $lock.publisherCommit -cne '5b4d6b2ede1c1b0e17f5dc7b996c42d68d534ca8'){throw 'Unexpected reviewed publisher identity'}
if(Test-Path -LiteralPath $OutputDirectory){throw 'Fresh dependency directory required; never overwrite preserved assets'}
$out=[IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $out -ErrorAction Stop | Out-Null
$names=@('pdfium-win-x64.tgz','pdfium-android-arm.tgz','pdfium-android-arm64.tgz','pdfium-attestation.json')
foreach($name in $names){
    $target=Join-Path $out $name
    Invoke-WebRequest -Uri ('https://github.com/bblanchon/pdfium-binaries/releases/download/chromium/8100/'+$name) -OutFile $target -ErrorAction Stop
    if((Get-Item -LiteralPath $target).Length -ne $lock.assets.$name.size -or (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant() -cne $lock.assets.$name.sha256){throw ('Asset hash/size mismatch: '+$name)}
}
foreach($name in $names[0..2]){
    $archive=Join-Path $out $name
    & $GitHubCli attestation verify $archive --bundle (Join-Path $out 'pdfium-attestation.json') --repo $lock.publisher --signer-workflow $lock.signerWorkflow --source-digest $lock.publisherCommit --signer-digest $lock.publisherCommit --deny-self-hosted-runners
    if($LASTEXITCODE -ne 0){throw ('Signed build provenance rejected: '+$name)}
    $members=@(& tar.exe -tf $archive)
    if($LASTEXITCODE -ne 0 -or $members.Count -eq 0 -or $members.Count -gt 1000){throw 'Archive inventory bound'}
    foreach($member in $members){if($member -match '(^[/\\]|(^|/)\.\.(/|$)|\\|:|\x00)'){throw 'Unsafe archive path'}}
    $types=@(& tar.exe -tvf $archive)
    if($LASTEXITCODE -ne 0 -or @($types|Where-Object{$_ -notmatch '^[-d]'}).Count -ne 0){throw 'Archive links/special entries rejected'}
    $target=Join-Path $out $name.Replace('pdfium-','').Replace('.tgz','')
    New-Item -ItemType Directory -Path $target -ErrorAction Stop | Out-Null
    & tar.exe -xzf $archive -C $target
    if($LASTEXITCODE -ne 0){throw 'Extraction failed'}
}
foreach($binary in $lock.extractedBinaries.PSObject.Properties){
    if((Get-FileHash -LiteralPath (Join-Path $out $binary.Name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $binary.Value){throw 'Extracted binary hash mismatch'}
}
Write-Output 'Pinned hosted publisher/source/signer/archives/binaries verified. No install scripts or device action.'
