[CmdletBinding()]
param(
    [string]$Jdk = $env:JAVA_HOME,
    [string]$AndroidSdk = $(if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT }
        else { $env:ANDROID_HOME })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Jdk)) { throw 'Pass -Jdk or set JAVA_HOME.' }
if ([string]::IsNullOrWhiteSpace($AndroidSdk)) {
    throw 'Pass -AndroidSdk or set ANDROID_SDK_ROOT/ANDROID_HOME.'
}
$root = $PSScriptRoot
$java = Join-Path $Jdk 'bin\java.exe'
$javac = Join-Path $Jdk 'bin\javac.exe'
$jar = Join-Path $Jdk 'bin\jar.exe'
$tools = Join-Path $AndroidSdk 'build-tools\35.0.0'
$aapt = Join-Path $tools 'aapt.exe'
$d8 = Join-Path $tools 'd8.bat'
$zipalign = Join-Path $tools 'zipalign.exe'
$androidJar = Join-Path $AndroidSdk 'platforms\android-30\android.jar'
foreach ($path in @($java, $javac, $jar, $aapt, $d8, $zipalign, $androidJar)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing build tool: $path" }
}

& (Join-Path $root 'test-host.ps1') -Jdk $Jdk
if ($LASTEXITCODE -ne 0) { throw 'Host contract tests failed.' }

# Every build has a new directory; no prior result or evidence is overwritten.
$generation = Join-Path $root ('build\apk-' + [Guid]::NewGuid().ToString('N'))
$classes = Join-Path $generation 'classes'
$dex = Join-Path $generation 'dex'
New-Item -ItemType Directory -Path $classes -ErrorAction Stop | Out-Null
New-Item -ItemType Directory -Path $dex -ErrorAction Stop | Out-Null
$sourceRoot = Join-Path $root 'src'
$sources = @(Get-ChildItem -LiteralPath $sourceRoot -Recurse -File -Filter '*.java' |
    Sort-Object FullName | ForEach-Object { $_.FullName })
if ($sources.Count -lt 5) { throw 'Incomplete disposable host Java source set.' }
& $javac -encoding UTF-8 --release 8 -classpath $androidJar -d $classes @sources
if ($LASTEXITCODE -ne 0) { throw 'Android host compilation failed.' }
$classFiles = @(Get-ChildItem -LiteralPath $classes -Recurse -File -Filter '*.class')
if ($classFiles.Count -eq 0) { throw 'No compiled Android classes.' }
$classesJar = Join-Path $generation 'classes.jar'
& $jar --create --file $classesJar -C $classes .
if ($LASTEXITCODE -ne 0) { throw 'Class archiving failed.' }
& $d8 --min-api 30 --lib $androidJar --output $dex $classesJar
if ($LASTEXITCODE -ne 0) { throw 'Dex compilation failed.' }
$dexFile = Join-Path $dex 'classes.dex'
if (-not (Test-Path -LiteralPath $dexFile -PathType Leaf)) { throw 'No classes.dex.' }
$baseApk = Join-Path $generation 'base.apk'
$manifest = Join-Path $root 'AndroidManifest.xml'
& $aapt package -f -M $manifest -I $androidJar -F $baseApk
if ($LASTEXITCODE -ne 0) { throw 'Manifest packaging failed.' }
Push-Location -LiteralPath $dex
try {
    & $aapt add $baseApk 'classes.dex'
    if ($LASTEXITCODE -ne 0) { throw 'Dex packaging failed.' }
} finally { Pop-Location }
$apk = Join-Path $generation 'disposable-lease-host-unsigned.apk'
& $zipalign -f -p 4 $baseApk $apk
if ($LASTEXITCODE -ne 0) { throw 'APK alignment failed.' }
& $zipalign -c 4 $apk
if ($LASTEXITCODE -ne 0) { throw 'APK alignment verification failed.' }
$badging = @(& $aapt dump badging $apk)
if ($LASTEXITCODE -ne 0 -or -not ($badging -match "package: name='com.techrebbe.supernote.disposableleasehost'")) {
    throw 'Unexpected APK package identity.'
}
$digest = (Get-FileHash -LiteralPath $apk -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Output "APK=$apk"
Write-Output "APK_SHA256=$digest"
Write-Output 'APK_IS_UNSIGNED=true'
