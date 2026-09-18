#!/usr/bin/env python3
"""Behavioral checks for the fixed local native-page-host alpha helpers."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BUILD = ROOT / "build-native-page-host-alpha.ps1"
INSTALL = ROOT / "install-native-page-host-alpha.ps1"
RUN = ROOT / "run-native-page-alpha.ps1"
DOC = ROOT / "NATIVE_PAGE_HOST_ALPHA_BUILD.md"
ARTIFACT_ROOT = ROOT / "build" / "native-page-host-alpha"
SIGNED_APK = ARTIFACT_ROOT / "native-page-host-alpha.apk"
METADATA = ARTIFACT_ROOT / "native-page-host-alpha.json"
PWSH_NEXT_TO_RUNTIME = (
    Path(sys.executable).resolve().parent.parent / "native" / "powershell" / "pwsh.exe"
)
PWSH_IN_PROFILE = (
    Path.home() / ".cache" / "codex-runtimes" / "codex-primary-runtime"
    / "dependencies" / "native" / "powershell" / "pwsh.exe"
)
PWSH = next(
    (candidate for candidate in (PWSH_NEXT_TO_RUNTIME, PWSH_IN_PROFILE)
     if candidate.is_file()),
    Path(shutil.which("pwsh") or "pwsh"),
)

PACKAGE = "com.techrebbe.supernote.nativepagehost"
VERSION_CODE = 2
VERSION_NAME = "0.0.2-native-page-visual-only"
CHECKPOINT = "2eeadd701d25dfeaf978108c358326e8edfaf87d"
SIGNED_SHA256 = "3798c204360db82941db7516e774517b273a51e025cce4848a642a5de61c6a03"
SIGNER_SHA256 = "d3f9ce76640125df1037e4536b680e29684da5ae7c171147f3206e26c7e568b4"
UNSIGNED_SHA256 = "670c755fabb00df87c6b6714c3dc8b878aa22e3190d95585b24adce295756178"
AUTHORITY_SHA256 = "94783276471ad4797b9a4ebf2200ae7adfd1ce1fe6ad888e2b5df09b403cb647"
DEX_SHA256 = "15d24cef8f4c70cf167ab6e93ac817fc2e85af4bfca6bb392e2535dc04863ab6"
SERIAL = "SN078C10015092"
MODEL = "Supernote Nomad"
SDK = "30"
FINGERPRINT = (
    "Supernote/Supernote/Supernote:11/RQ2A.210505.003/"
    "eng.supern.20260616.100032:user/release-keys"
)
METADATA_FIELDS = {
    "schema",
    "package",
    "versionCode",
    "versionName",
    "signedApkPath",
    "signedApkSha256",
    "signerCertSha256",
    "reviewedUnsignedApkSha256",
    "reviewedUnsignedAuthoritySha256",
    "dexSha256",
    "checkpoint",
    "diagnosticOnly",
    "reproducibleUnsignedAuthorityPreserved",
    "formalReleaseArtifact",
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def ps_literal(value: Path | str) -> str:
    return "'" + str(value).replace("'", "''") + "'"


def run_pwsh(script: str, *, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(PWSH),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        cwd=ROOT,
        env=os.environ.copy(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )


def newest_unsigned_apk() -> Path | None:
    candidates: list[Path] = []
    build_root = ROOT / "build"
    if not build_root.is_dir():
        return None
    for generation in build_root.iterdir():
        if not generation.is_dir() or not re.fullmatch(
            r"native-page-host-[0-9a-f]{32}", generation.name
        ):
            continue
        candidate = generation / "first" / "native-page-host-unsigned.apk"
        authority = generation / "first" / "evidence" / "package-authority.json"
        if candidate.is_file() and authority.is_file():
            candidates.append(candidate)
    return max(candidates, key=lambda path: path.stat().st_mtime_ns) if candidates else None


class AlphaHelperParseAndPolicyTests(unittest.TestCase):
    def test_powershell_helpers_parse_without_errors(self) -> None:
        for path in (BUILD, INSTALL, RUN):
            script = (
                "$errors=$null;"
                "[System.Management.Automation.Language.Parser]::ParseFile("
                f"{ps_literal(path)},[ref]$null,[ref]$errors)|Out-Null;"
                "if(@($errors).Count-ne 0){$errors|Out-String|Write-Output;exit 9}"
            )
            result = run_pwsh(script)
            self.assertEqual(result.returncode, 0, result.stdout)

    def test_script_relative_defaults_are_resolved_after_parameter_binding(self) -> None:
        script = (
            "$bad=@();"
            f"foreach($path in @({ps_literal(BUILD)},{ps_literal(INSTALL)},{ps_literal(RUN)})){{"
            "$tokens=$null;$errors=$null;"
            "$ast=[System.Management.Automation.Language.Parser]::ParseFile("
            "$path,[ref]$tokens,[ref]$errors);"
            "if(@($errors).Count-ne 0){throw ('parse failed: '+$path)};"
            "$bad+=@($ast.ParamBlock.Parameters|Where-Object{"
            "$null-ne$_.DefaultValue-and"
            "$_.DefaultValue.Extent.Text-match '\\$PSScriptRoot'}|"
            "ForEach-Object{$path+':'+$_.Name.VariablePath.UserPath})"
            "};"
            "if($bad.Count-ne 0){throw ('early PSScriptRoot defaults: '+($bad-join ','))};"
            "Write-Output 'POST_BINDING_DEFAULTS_PASS'"
        )
        result = run_pwsh(script)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("POST_BINDING_DEFAULTS_PASS", result.stdout)

        build = BUILD.read_text(encoding="utf-8")
        install = INSTALL.read_text(encoding="utf-8")
        self.assertIn(
            "$OutputDirectory = Join-Path $PSScriptRoot "
            "'build\\native-page-host-alpha'",
            build,
        )
        self.assertIn("$PSBoundParameters.ContainsKey('OutputDirectory')", build)
        self.assertIn("$PSBoundParameters.ContainsKey('Apk')", install)
        self.assertIn("$PSBoundParameters.ContainsKey('Metadata')", install)
        self.assertIn("$Apk = Join-Path $PSScriptRoot", install)
        self.assertIn("$Metadata = Join-Path $PSScriptRoot", install)

    def test_explicit_empty_script_relative_paths_fail_closed(self) -> None:
        build_script = (
            f"try{{& {ps_literal(BUILD)} -OutputDirectory '';exit 30}}"
            "catch{Write-Output $_.Exception.Message;exit 17}"
        )
        build_result = run_pwsh(build_script)
        self.assertEqual(build_result.returncode, 17, build_result.stdout)
        self.assertIn(
            "Alpha output directory may not be explicitly empty.",
            build_result.stdout,
        )

        install_script = (
            "$path=[IO.Path]::GetTempFileName();"
            "$lock=[IO.File]::Open($path,[IO.FileMode]::Open,"
            "[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);"
            "$message='';try{"
            f"& {ps_literal(INSTALL)} -Serial {SERIAL} -SessionLock $lock -Apk '';"
            "$message='unexpected acceptance'"
            "}catch{$message=$_.Exception.Message}finally{"
            "$lock.Dispose();Remove-Item -LiteralPath $path -Force};"
            "Write-Output $message;"
            "if($message-cne 'Apk may not be explicitly empty.'){exit 18}"
        )
        install_result = run_pwsh(install_script)
        self.assertEqual(install_result.returncode, 0, install_result.stdout)
        self.assertIn("Apk may not be explicitly empty.", install_result.stdout)

    def test_fixed_authorities_are_not_caller_overrides(self) -> None:
        build = BUILD.read_text(encoding="utf-8")
        install = INSTALL.read_text(encoding="utf-8")
        for source in (build, install):
            for authority in (
                SIGNED_SHA256,
                SIGNER_SHA256,
                UNSIGNED_SHA256,
                AUTHORITY_SHA256,
                DEX_SHA256,
                PACKAGE,
                VERSION_NAME,
            ):
                self.assertIn(authority, source)
        self.assertNotIn("ExpectedSignerSha256", build)
        self.assertIn("$identity.Code -ne $versionCode", install)
        self.assertIn("$dexSha256 -cne $reviewedDexSha256", install)

    def test_signing_uses_pinned_java_jar_without_cmd_boundary(self) -> None:
        for source in (
            BUILD.read_text(encoding="utf-8"),
            INSTALL.read_text(encoding="utf-8"),
        ):
            lowered = source.lower()
            self.assertNotIn("apksigner.bat", lowered)
            self.assertNotIn("cmd.exe", lowered)
            self.assertIn("lib\\apksigner.jar", source)
            self.assertIn("& $java -jar $apksignerJar", source)
            self.assertIn(
                "00ef9948f843fe395d2440ae3ef41405b8040a6d5d46493bd1902ac0ee6deae7",
                source,
            )

    def test_device_and_lock_policy_is_exact(self) -> None:
        source = INSTALL.read_text(encoding="utf-8")
        for marker in (SERIAL, MODEL, SDK, FINGERPRINT):
            self.assertIn(marker, source)
        self.assertIn("[IO.FileStream]$SessionLock", source)
        self.assertIn("Alpha session lock is not held exclusively", source)
        self.assertIn("Assert-NoReparseComponents", source)
        self.assertIn("NativePageHostLocks", source)
        for forbidden in ("'uninstall'", "'pm', 'clear'", "'install', '-d'", "'-t'"):
            self.assertNotIn(forbidden, source)

    def test_real_nomad_pm_path_absence_dialect_and_contradictions(self) -> None:
        script = (
            "$tokens=$null;$errors=$null;"
            "$ast=[System.Management.Automation.Language.Parser]::ParseFile("
            f"{ps_literal(INSTALL)},[ref]$tokens,[ref]$errors);"
            "$definitions=@($ast.FindAll({param($node)"
            "$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and "
            "$node.Name -ceq 'Resolve-InstalledBasePathResult'},$true));"
            "if(@($errors).Count-ne 0 -or $definitions.Count-ne 1){exit 30};"
            "Invoke-Expression $definitions[0].Extent.Text;"
            "$absent=@(Resolve-InstalledBasePathResult -ExitCode 1 -Output ([string[]]@()));"
            "if($absent.Count-ne 0){exit 31};"
            "$valid='/data/app/~~ABC123/com.techrebbe.supernote.nativepagehost-XYZ_1/base.apk';"
            "$present=Resolve-InstalledBasePathResult -ExitCode 0 "
            "-Output ([string[]]@('package:'+$valid));"
            "if($present-cne $valid){exit 32};"
            "function Assert-Rejected([int]$Code,[string[]]$Lines,[string]$Label){"
            "$accepted=$false;try{$null=Resolve-InstalledBasePathResult "
            "-ExitCode $Code -Output $Lines;$accepted=$true}catch{};"
            "if($accepted){throw ('unexpectedly admitted '+$Label)}};"
            "$cases=@("
            "[pscustomobject]@{Code=1;Lines=[string[]]@('');Label='empty line'},"
            "[pscustomobject]@{Code=1;Lines=[string[]]@('not found');Label='exit-one text'},"
            "[pscustomobject]@{Code=1;Lines=[string[]]@('package:'+$valid);Label='exit-one path'},"
            "[pscustomobject]@{Code=2;Lines=[string[]]@();Label='exit greater than one'},"
            "[pscustomobject]@{Code=0;Lines=[string[]]@();Label='success without path'},"
            "[pscustomobject]@{Code=0;Lines=[string[]]@('not found');Label='malformed text'},"
            "[pscustomobject]@{Code=0;Lines=[string[]]@('package:'+$valid,'extra');Label='extra line'},"
            "[pscustomobject]@{Code=0;Lines=[string[]]@(('package:'+$valid)+[char]10);Label='terminal LF'},"
            "[pscustomobject]@{Code=0;Lines=[string[]]@('package:/data//base.apk');Label='empty component'},"
            "[pscustomobject]@{Code=0;Lines=[string[]]@('package:/data/../base.apk');Label='traversal'}"
            ");foreach($case in $cases){Assert-Rejected $case.Code $case.Lines $case.Label};"
            "Write-Output 'PM_PATH_POLICY_PASS'"
        )
        result = run_pwsh(script)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("PM_PATH_POLICY_PASS", result.stdout)

    def test_identity_and_output_junction_ancestors_fail_before_build(self) -> None:
        script = (
            "$tag=[Guid]::NewGuid().ToString('N');"
            "$temp=Join-Path ([IO.Path]::GetTempPath()) ('nph-alpha-path-test-'+$tag);"
            f"$buildRoot=Join-Path {ps_literal(ROOT)} 'build';"
            "$identityTarget=Join-Path $temp 'identity-target';"
            "$outputTarget=Join-Path $temp 'output-target';"
            "$identityLink=Join-Path $temp 'identity-link';"
            "$outputLink=Join-Path $buildRoot ('path-test-'+$tag);"
            "$identityMessage='';$outputMessage='';"
            "try{"
            "New-Item -ItemType Directory -Path $identityTarget,$outputTarget,$buildRoot -Force|Out-Null;"
            "New-Item -ItemType Junction -Path $identityLink -Target $identityTarget|Out-Null;"
            "New-Item -ItemType Junction -Path $outputLink -Target $outputTarget|Out-Null;"
            f"try{{& {ps_literal(BUILD)} -IdentityDirectory $identityLink "
            f"-Python {ps_literal(Path(sys.executable))} "
            "-UnsignedApk (Join-Path $temp 'missing.apk')}"
            "catch{$identityMessage=$_.Exception.Message};"
            f"try{{& {ps_literal(BUILD)} -OutputDirectory (Join-Path $outputLink 'child') "
            f"-Python {ps_literal(Path(sys.executable))} "
            "-UnsignedApk (Join-Path $temp 'missing.apk')}"
            "catch{$outputMessage=$_.Exception.Message}"
            "}finally{"
            "if(Test-Path -LiteralPath $identityLink){Remove-Item -LiteralPath $identityLink -Force};"
            "if(Test-Path -LiteralPath $outputLink){Remove-Item -LiteralPath $outputLink -Force};"
            "if((Split-Path -Leaf $temp)-match '^nph-alpha-path-test-[0-9a-f]{32}$' -and "
            "(Test-Path -LiteralPath $temp)){[IO.Directory]::Delete($temp,$true)}"
            "};"
            "Write-Output ('IDENTITY='+$identityMessage);"
            "Write-Output ('OUTPUT='+$outputMessage);"
            "if(-not $identityMessage.Contains('reparse') -or "
            "-not $outputMessage.Contains('reparse')){exit 23}"
        )
        result = run_pwsh(script)
        if "Access to the path" in result.stdout or "privilege" in result.stdout:
            self.skipTest("junction or Android SDK access is unavailable")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("IDENTITY=", result.stdout)
        self.assertIn("OUTPUT=", result.stdout)


@unittest.skipUnless(SIGNED_APK.is_file() and METADATA.is_file(), "build alpha first")
class PublishedAlphaBehaviorTests(unittest.TestCase):
    def test_published_apk_and_embedded_dex_match_fixed_authority(self) -> None:
        self.assertEqual(sha256(SIGNED_APK), SIGNED_SHA256)
        with zipfile.ZipFile(SIGNED_APK) as archive:
            names = [item.filename for item in archive.infolist()]
            self.assertEqual(names.count("classes.dex"), 1)
            self.assertEqual(
                hashlib.sha256(archive.read("classes.dex")).hexdigest(), DEX_SHA256
            )

    def test_metadata_is_exactly_fixed_and_not_self_authorizing(self) -> None:
        record = json.loads(METADATA.read_text(encoding="utf-8"))
        self.assertEqual(set(record), METADATA_FIELDS)
        self.assertEqual(record["schema"], "native-page-host-local-alpha-apk-v1")
        self.assertEqual(record["package"], PACKAGE)
        self.assertEqual(record["versionCode"], VERSION_CODE)
        self.assertEqual(record["versionName"], VERSION_NAME)
        self.assertEqual(record["signedApkPath"], SIGNED_APK.name)
        self.assertEqual(record["signedApkSha256"], SIGNED_SHA256)
        self.assertEqual(record["signerCertSha256"], SIGNER_SHA256)
        self.assertEqual(record["reviewedUnsignedApkSha256"], UNSIGNED_SHA256)
        self.assertEqual(record["reviewedUnsignedAuthoritySha256"], AUTHORITY_SHA256)
        self.assertEqual(record["dexSha256"], DEX_SHA256)
        self.assertEqual(record["checkpoint"], CHECKPOINT)
        self.assertIs(record["diagnosticOnly"], True)
        self.assertIs(record["reproducibleUnsignedAuthorityPreserved"], True)
        self.assertIs(record["formalReleaseArtifact"], False)

    def test_installer_rejects_nonexclusive_session_handle_before_adb(self) -> None:
        lock_path = (
            Path(os.environ["LOCALAPPDATA"])
            / "SupernoteAlpha"
            / "NativePageHostLocks"
            / SERIAL
            / "session.lock"
        )
        script = (
            f"$lockPath={ps_literal(lock_path)};"
            "$parent=Split-Path -Parent $lockPath;"
            "New-Item -ItemType Directory -Path $parent -Force|Out-Null;"
            "$lock=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,"
            "[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite);"
            "try{"
            f"& {ps_literal(INSTALL)} -Serial {SERIAL} -SessionLock $lock "
            f"-Apk {ps_literal(SIGNED_APK)} -Metadata {ps_literal(METADATA)};"
            "exit 0"
            "}catch{Write-Output $_.Exception.Message;exit 17}"
            "finally{$lock.Dispose()}"
        )
        result = run_pwsh(script)
        if "Access to the path" in result.stdout:
            self.skipTest("Android SDK is outside this test sandbox")
        self.assertEqual(result.returncode, 17, result.stdout)
        self.assertIn("session lock is not held exclusively", result.stdout)

    def test_hostile_java_options_cannot_change_short_signing_path(self) -> None:
        unsigned = newest_unsigned_apk()
        if unsigned is None:
            self.skipTest("no authoritative unsigned generation is present")
        script = (
            "$env:JAVA_TOOL_OPTIONS='-XX:AlphaTestMustBeScrubbed';"
            "$env:_JAVA_OPTIONS='-XX:AlphaTestMustBeScrubbed';"
            f"& {ps_literal(BUILD)} -Python {ps_literal(Path(sys.executable))} "
            f"-UnsignedApk {ps_literal(unsigned)};"
            "if($LASTEXITCODE-ne 0){exit $LASTEXITCODE};"
            "if($env:JAVA_TOOL_OPTIONS-cne '-XX:AlphaTestMustBeScrubbed'){exit 18};"
            "if($env:_JAVA_OPTIONS-cne '-XX:AlphaTestMustBeScrubbed'){exit 19}"
        )
        result = run_pwsh(script)
        if "Access to the path" in result.stdout:
            self.skipTest("Android SDK is outside this test sandbox")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn(f"signedApkSha256={SIGNED_SHA256}", result.stdout)
        self.assertEqual(sha256(SIGNED_APK), SIGNED_SHA256)


class AlphaDocumentationTests(unittest.TestCase):
    def test_documentation_keeps_alpha_outside_release_authority(self) -> None:
        source = DOC.read_text(encoding="utf-8")
        for marker in (
            "build/native-page-host-alpha/native-page-host-alpha.apk",
            "does not change",
            "not a release artifact",
            "never uninstalls",
            "exact device rollback",
            SIGNED_SHA256,
            SIGNER_SHA256,
            SERIAL,
            "session lock",
            "exit code `1`",
            "zero output lines",
        ):
            self.assertIn(marker, source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
