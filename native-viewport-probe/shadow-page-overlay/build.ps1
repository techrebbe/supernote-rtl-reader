param(
    [Parameter(Mandatory=$true)][string]$Jdk,
    [Parameter(Mandatory=$true)][string]$AndroidSdk
)

$ErrorActionPreference='Stop'
$root=$PSScriptRoot
$androidJar=Join-Path $AndroidSdk 'platforms/android-35/android.jar'
$buildTools=Join-Path $AndroidSdk 'build-tools/35.0.0'
$javac=Join-Path $Jdk 'bin/javac.exe'
$jar=Join-Path $Jdk 'bin/jar.exe'
$d8=Join-Path $buildTools 'd8.bat'
$aapt=Join-Path $buildTools 'aapt.exe'
$zipalign=Join-Path $buildTools 'zipalign.exe'
$manifest=Join-Path $root 'AndroidManifest.xml'
$sourceRoot=Join-Path $root 'src'
$sources=@(
    (Join-Path $sourceRoot 'com/techrebbe/supernote/shadowpageoverlay/ShadowPageGeometry.java'),
    (Join-Path $sourceRoot 'com/techrebbe/supernote/shadowpageoverlay/ShadowOverlayGeneration.java'),
    (Join-Path $sourceRoot 'com/techrebbe/supernote/shadowpageoverlay/ShadowPageOverlayService.java')
)
foreach ($required in @($androidJar,$javac,$jar,$d8,$aapt,$zipalign,$manifest) + $sources) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required shadow-overlay build input missing: $required"
    }
}
$actualSources=@(Get-ChildItem -LiteralPath $sourceRoot -Recurse -File -Filter '*.java' |
    ForEach-Object FullName)
if (@(Compare-Object ($sources | Sort-Object) ($actualSources | Sort-Object)).Count -ne 0) {
    throw 'Shadow-overlay Java inventory differs from the exact three-source allowlist'
}

# Read-only build authority; this fixture is never copied into the APK or changed.
# A future separately authorized host gate seeds one app-private copy from it.
# The Service opens only that private path and hashes its opened FD.
$fixture=(Resolve-Path -LiteralPath (Join-Path $root `
    '../../../../output/pdf/RTL_DISPLAY0_CAPTURE_20260927.pdf') -ErrorAction Stop).Path
$expectedFixtureSha256='28b126627dd5966e8975ae1bf48385d65e1f8189e8aa32ddc0eab778904859c9'
$expectedFixtureBytes=2419L
$fixtureInfo=Get-Item -LiteralPath $fixture
if ($fixtureInfo.Length -ne $expectedFixtureBytes -or
        (Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant() -cne
        $expectedFixtureSha256) {
    throw 'Disposable fixture differs from the build-pinned bytes'
}
$serviceText=Get-Content -LiteralPath $sources[2] -Raw
if (-not $serviceText.Contains($expectedFixtureSha256) -or
        -not $serviceText.Contains('new File(getFilesDir(), FIXTURE_FILENAME)') -or
        -not $serviceText.Contains('RTL_DISPLAY0_CAPTURE_20260927.pdf')) {
    throw 'Runtime FD authority differs from build-pinned fixture'
}

$manifestText=Get-Content -LiteralPath $manifest -Raw
[xml]$manifestXml=$manifestText
$manifestChildren=@($manifestXml.DocumentElement.ChildNodes |
    Where-Object NodeType -eq ([Xml.XmlNodeType]::Element) |
    ForEach-Object LocalName)
$expectedManifestChildren=@('application','uses-permission','uses-sdk')
$sortedManifestChildren=@($manifestChildren | Sort-Object)
$manifestDifference=@(Compare-Object -ReferenceObject $expectedManifestChildren -DifferenceObject $sortedManifestChildren)
if ($manifestDifference.Count -ne 0) {
    throw 'Manifest top-level inventory changed from the narrow Service package'
}
$permissions=@($manifestXml.SelectNodes("//*[local-name()='uses-permission']"))
if ($permissions.Count -ne 1 -or
        $permissions[0].GetAttribute('name','http://schemas.android.com/apk/res/android') -cne
        'android.permission.SYSTEM_ALERT_WINDOW') {
    throw 'Manifest permission scope changed from overlay-only'
}
$application=@($manifestXml.SelectNodes("//*[local-name()='application']"))[0]
$appChildren=@($application.ChildNodes |
    Where-Object NodeType -eq ([Xml.XmlNodeType]::Element))
if ($appChildren.Count -ne 1 -or $appChildren[0].LocalName -cne 'service' -or
        $application.GetAttribute('debuggable','http://schemas.android.com/apk/res/android') -cne 'true' -or
        $application.GetAttribute('allowBackup','http://schemas.android.com/apk/res/android') -cne 'false') {
    throw 'Manifest component scope changed from one Service'
}
$service=@($manifestXml.SelectNodes("//*[local-name()='service']"))[0]
if ($service.GetAttribute('exported','http://schemas.android.com/apk/res/android') -cne 'true' -or
        $service.GetAttribute('permission','http://schemas.android.com/apk/res/android') -cne
        'android.permission.DUMP') {
    throw 'Service must be shell-permission gated for this disposable probe'
}

# Each offline build gets a new directory. No install, launch, signing, AppOps,
# stock-app operation, or fixture staging is performed here.
$out=Join-Path $root ('build/shadow-' + [guid]::NewGuid().ToString('N'))
$classes=Join-Path $out 'classes'
$dex=Join-Path $out 'dex'
New-Item -ItemType Directory -Path $classes,$dex | Out-Null
& $javac -encoding UTF-8 --release 8 -classpath $androidJar -d $classes @sources
if ($LASTEXITCODE -ne 0) { throw 'Shadow-overlay Java compilation failed' }
$classJar=Join-Path $out 'classes.jar'
& $jar --create --file $classJar -C $classes .
if ($LASTEXITCODE -ne 0) { throw 'Shadow-overlay Java packaging failed' }
$priorJavaHome=$env:JAVA_HOME
try {
    $env:JAVA_HOME=$Jdk
    & $d8 --min-api 30 --lib $androidJar --output $dex $classJar
    if ($LASTEXITCODE -ne 0) { throw 'Shadow-overlay DEX compilation failed' }
} finally { $env:JAVA_HOME=$priorJavaHome }
$raw=Join-Path $out 'shadow-raw.apk'
& $aapt package -f -M $manifest -I $androidJar -F $raw
if ($LASTEXITCODE -ne 0) { throw 'Shadow-overlay manifest packaging failed' }
& $jar --update --file $raw -C $dex classes.dex
if ($LASTEXITCODE -ne 0) { throw 'Shadow-overlay DEX packaging failed' }
$unsigned=Join-Path $out 'shadow-unsigned.apk'
& $zipalign -p 4 $raw $unsigned
if ($LASTEXITCODE -ne 0) { throw 'Shadow-overlay alignment failed' }
& $zipalign -c 4 $unsigned
if ($LASTEXITCODE -ne 0) { throw 'Shadow-overlay alignment verification failed' }
$entries=@(& $jar --list --file $unsigned)
$sortedEntries=@($entries | Sort-Object)
$entryDifference=@(Compare-Object -ReferenceObject @('AndroidManifest.xml','classes.dex') -DifferenceObject $sortedEntries)
if ($LASTEXITCODE -ne 0 -or $entryDifference.Count -ne 0) {
    throw 'Packaged APK contains more than manifest and DEX'
}
$packagedPermissions=@(& $aapt dump permissions $unsigned)
if ($LASTEXITCODE -ne 0 -or $packagedPermissions.Count -ne 2 -or
        $packagedPermissions[0] -cne 'package: com.techrebbe.supernote.shadowpageoverlay' -or
        $packagedPermissions[1] -cne "uses-permission: name='android.permission.SYSTEM_ALERT_WINDOW'") {
    throw 'Packaged APK permission scope changed'
}
Write-Output 'UNSIGNED, OFFLINE, VISUAL-ONLY APK; NO HARDWARE ADMISSION OR INSTALL.'
Write-Output $unsigned
