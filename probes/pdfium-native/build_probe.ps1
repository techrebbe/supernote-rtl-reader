param(
    [Parameter(Mandatory=$true)][string]$EngineRoot,
    [Parameter(Mandatory=$true)][string]$Fixture,
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [string]$AndroidSdk='C:\Users\mmkap\AppData\Local\Android\Sdk',
    [string]$JavaHome='C:\Program Files\Eclipse Adoptium\jdk-17.0.17.10-hotspot',
    [Parameter(Mandatory=$true)][string]$PythonExecutable,
    [Parameter(Mandatory=$true)][string]$Keystore,
    [Parameter(Mandatory=$true)][string]$ExpectedSignerSha256,
    [Parameter(Mandatory=$true)][string]$SourceCommit
)
$ErrorActionPreference='Stop'
$source=$PSScriptRoot
$lock=Get-Content -LiteralPath (Join-Path $source 'pdfium.lock.json') -Raw | ConvertFrom-Json
if($ExpectedSignerSha256 -cnotmatch '^[0-9a-f]{64}$' -or $ExpectedSignerSha256 -cne $lock.diagnosticSignerSha256){throw 'Use the exact pinned diagnostic signer; this is not an RTL Reader upgrade'}
if($SourceCommit -cnotmatch '^[0-9a-f]{40}$'){throw 'Exact source commit required (candidate must be built from its clean archive)'}
$engine=(Resolve-Path -LiteralPath $EngineRoot).Path
$fixturePath=(Resolve-Path -LiteralPath $Fixture).Path
if((Get-FileHash -Algorithm SHA256 -LiteralPath $fixturePath).Hash.ToLowerInvariant() -cne '7cf9de8fa7ed91f7746ac44f62aa63e0641f757f330cf7d83efec7584b213905'){throw 'Only exact disposable fixture allowed'}
foreach($name in @('pdfium-android-arm.tgz','pdfium-android-arm64.tgz','pdfium-attestation.json')){
    if((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $engine $name)).Hash.ToLowerInvariant() -cne $lock.assets.$name.sha256){throw 'Pinned archive/provenance drift'}
}
foreach($name in @('android-arm/lib/libpdfium.so','android-arm64/lib/libpdfium.so')){
    if((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $engine $name)).Hash.ToLowerInvariant() -cne $lock.extractedBinaries.$name){throw 'Pinned extracted native binary drift'}
}
foreach($name in @('android-arm','android-arm64')){
    $flags=Get-Content -LiteralPath (Join-Path $engine "$name/args.gn") -Raw
    if($flags -notmatch '(?m)^pdf_enable_v8 = false\r?$' -or $flags -notmatch '(?m)^pdf_enable_xfa = false\r?$' -or $flags -notmatch '(?m)^default_min_sdk_version = 23\r?$'){throw 'Unsupported native build configuration'}
}
if(Test-Path -LiteralPath $OutputDirectory){throw 'Fresh output directory required; preserve earlier builds'}
$out=[IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $out -ErrorAction Stop | Out-Null
$authenticated=Join-Path $out 'authenticated-engine'
& $PythonExecutable (Join-Path $source 'package_inputs.py') prepare --engine $engine --output $authenticated
if($LASTEXITCODE -ne 0){throw 'Fresh authenticated compiler inputs rejected'}
$engine=$authenticated
$assets=Join-Path $out 'assets';$classes=Join-Path $out 'classes';$dex=Join-Path $out 'dex';$libs=Join-Path $out 'lib';$notices=Join-Path $out 'notices';$compilerTmp=Join-Path $out 'compiler-tmp'
foreach($dir in @($assets,$classes,$dex,$libs,$notices,$compilerTmp)){New-Item -ItemType Directory -Path $dir -ErrorAction Stop | Out-Null}
Copy-Item -LiteralPath $fixturePath -Destination (Join-Path $assets 'fixture.pdf')
# Full actual native dependency notices, not only the wrapper's declared license.
Copy-Item -LiteralPath (Join-Path $engine 'android-arm/LICENSE') -Destination (Join-Path $notices 'PDFium-LICENSE')
Copy-Item -LiteralPath (Join-Path $engine 'android-arm/licenses') -Destination (Join-Path $notices 'licenses') -Recurse
$env:TEMP=$compilerTmp;$env:TMP=$compilerTmp
$tools=Join-Path $AndroidSdk 'build-tools\35.0.0';$platform=Join-Path $AndroidSdk 'platforms\android-35\android.jar'
$ndk=Join-Path $AndroidSdk 'ndk\27.0.12077973\toolchains\llvm\prebuilt\windows-x86_64\bin'
foreach($abi in @(@{name='armeabi-v7a';target='armv7a-linux-androideabi23';vendor='android-arm'},@{name='arm64-v8a';target='aarch64-linux-android23';vendor='android-arm64'})){
    $vendor=Join-Path $engine $abi.vendor;$target=Join-Path $libs $abi.name
    New-Item -ItemType Directory -Path $target -ErrorAction Stop | Out-Null
    & (Join-Path $ndk 'clang++.exe') ('--target='+$abi.target) -std=c++17 -O2 -fPIC -shared -static-libstdc++ -fvisibility=hidden -Wall -Wextra -Werror ('-I'+(Join-Path $vendor 'include')) (Join-Path $source 'native_core.cpp') ('-L'+(Join-Path $vendor 'lib')) -lpdfium '-Wl,--no-undefined' '-Wl,-z,max-page-size=16384' -o (Join-Path $target 'librtlpdfiumprobe.so')
    if($LASTEXITCODE -ne 0){throw ('Native compile failed '+$abi.name)}
    Copy-Item -LiteralPath (Join-Path $vendor 'lib/libpdfium.so') -Destination (Join-Path $target 'libpdfium.so')
}
$env:JAVA_HOME=$JavaHome;$env:PATH=(Join-Path $JavaHome 'bin')+';'+$env:PATH
& (Join-Path $JavaHome 'bin\javac.exe') -encoding UTF-8 -source 8 -target 8 -Xlint:all -classpath $platform -d $classes (Join-Path $source 'NativeCore.java') (Join-Path $source 'ProbeActivity.java') (Join-Path $source 'Interaction.java') (Join-Path $source 'EngineQueue.java') (Join-Path $source 'RenderBudget.java')
if($LASTEXITCODE -ne 0){throw 'Java compile failed'}
$compiled=@(Get-ChildItem -LiteralPath $classes -Filter '*.class' -Recurse | ForEach-Object FullName)
& (Join-Path $tools 'd8.bat') --lib $platform --min-api 23 --output $dex $compiled
if($LASTEXITCODE -ne 0){throw 'DEX compile failed'}
$unsigned=Join-Path $out 'probe-unsigned.apk';$aligned=Join-Path $out 'probe-aligned.apk';$apk=Join-Path $out 'RTL-PDFium-Probe-exp2.apk'
& (Join-Path $tools 'aapt2.exe') link -o $unsigned --manifest (Join-Path $source 'AndroidManifest.xml') -I $platform -A $assets
if($LASTEXITCODE -ne 0){throw 'Android package link failed'}
& (Join-Path $JavaHome 'bin\jar.exe') uf $unsigned -C $out lib -C $out notices -C $dex classes.dex
if($LASTEXITCODE -ne 0){throw 'Package assembly failed'}
$normalized=Join-Path $out 'probe-unsigned-normalized.apk'
$normalizer=Join-Path $source '..\..\scripts\normalize_apk_zip.py'
& $PythonExecutable $normalizer $unsigned $normalized
if($LASTEXITCODE -ne 0){throw 'Canonical APK normalization failed'}
& (Join-Path $tools 'zipalign.exe') -f -p 4 $normalized $aligned
if($LASTEXITCODE -ne 0){throw 'Alignment failed'}
& (Join-Path $tools 'apksigner.bat') sign --ks $Keystore --ks-key-alias androiddebugkey --ks-pass pass:android --key-pass pass:android --out $apk $aligned
if($LASTEXITCODE -ne 0){throw 'Package signing failed'}
$verification=& (Join-Path $tools 'apksigner.bat') verify --verbose --print-certs $apk
if($LASTEXITCODE -ne 0 -or ($verification -join "`n") -notmatch '(?m)^Number of signers: 1\r?$' -or ($verification -join "`n") -notmatch ('(?im)^Signer #1 certificate SHA-256 digest: '+[regex]::Escape($ExpectedSignerSha256)+'\r?$')){throw 'Expected exact signing identity not verified'}
& (Join-Path $tools 'aapt2.exe') dump badging $apk
if($LASTEXITCODE -ne 0){throw 'Package identity check failed'}
$receipt=Join-Path $out 'build-receipt.json'
& $PythonExecutable (Join-Path $source 'package_inputs.py') receipt --apk $apk --commit $SourceCommit --output $receipt
if($LASTEXITCODE -ne 0){throw 'Source/payload receipt failed'}
& $PythonExecutable (Join-Path $source 'verify_package.py') --apk $apk --engine $engine --aapt (Join-Path $tools 'aapt2.exe') --receipt $receipt --expected-commit $SourceCommit
if($LASTEXITCODE -ne 0){throw 'Complete package verification rejected'}
Get-FileHash -LiteralPath $apk -Algorithm SHA256 | Select-Object Path,Hash
Write-Output 'Diagnostic only; no device connection/install performed.'
