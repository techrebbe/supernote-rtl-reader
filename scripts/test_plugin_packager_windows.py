#!/usr/bin/env python3
"""Executable regressions for the pinned packager's Windows replay boundaries.

No build, device, network, or source-package mutation. Optionally pass the
reviewed template tgz with --template to test every marker against its bytes.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

import materialize_plugin_template as template
import patch_plugin_packager as packager


NEW_MARKERS = (
    packager.UPSTREAM_NATIVE_CODE_PATH_UPDATE,
    packager.UPSTREAM_ICON_PATH_UPDATE,
    packager.UPSTREAM_AUTOLINK_OUTPUT_FILTER,
)
ALL_MARKERS = (
    *NEW_MARKERS,
    packager.APK_COPY_FUNCTION_MARKER,
    packager.UPSTREAM_APK_SELECTION,
    packager.UPSTREAM_PACKAGE_SCAN,
    packager.UPSTREAM_PACKAGE_UPDATE,
    packager.UPSTREAM_SOFT_NATIVE_BUILD,
)
EXCLUDED = (
    "com.facebook.react.shell.MainReactPackage",
    "com.ratta.supernote.note.plugincore.PluginPackage",
    "com.ratta.supernote.pluginlib.PluginPackage",
)
TEMPLATE_TGZ: Path | None = None


def bash_executable() -> str | None:
    if os.name == "nt":
        for variable in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"):
            directory = os.environ.get(variable)
            if directory:
                candidate = Path(directory) / "Git/bin/bash.exe"
                if candidate.is_file():
                    return str(candidate)
        return None
    return shutil.which("bash")


class WindowsPackagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rtl-packager-windows-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def run_bash(self, source: str, *, environment=None):
        bash = bash_executable()
        if not bash:
            self.skipTest("Bash is unavailable; executable packager test not run")
        script = self.directory / "trial.sh"
        script.write_text(source, encoding="utf-8", newline="\n")
        env = dict(os.environ)
        env.update(environment or {})
        return subprocess.run(
            [bash, "--noprofile", "--norc", script.as_posix()],
            env=env, capture_output=True, check=False, timeout=20,
        )

    def minimal_upstream(self):
        return "#!/usr/bin/env bash\n" + "\n".join(ALL_MARKERS)

    def test_new_marker_missing_duplicate_and_drift_fail_closed(self):
        original = self.minimal_upstream()
        for marker in NEW_MARKERS:
            for change in ("", marker + marker, marker.replace(" ", "  ", 1)):
                with self.subTest(marker=marker.splitlines()[0], change=len(change)):
                    with self.assertRaises(SystemExit):
                        packager.patch_text(original.replace(marker, change, 1))

    def test_each_scoped_replacement_is_exact_and_cannot_repatch(self):
        patched = packager.patch_text(self.minimal_upstream())
        for replacement in (
            packager.STRICT_NATIVE_CODE_PATH_UPDATE,
            packager.STRICT_ICON_PATH_UPDATE,
            packager.STRICT_AUTOLINK_OUTPUT_FILTER,
            packager.STRICT_PACKAGE_UPDATE,
        ):
            self.assertEqual(patched.count(replacement), 1)
        self.assertNotIn("tr -d '\\r'", packager.STRICT_AUTOLINK_OUTPUT_FILTER)
        self.assertNotIn("strip", packager.STRICT_AUTOLINK_OUTPUT_FILTER)
        with self.assertRaises(SystemExit):
            packager.patch_text(patched)

    def scanner_publication(self, output: str, *, excludes=EXCLUDED):
        # Exercise the patched Bash line filter and actual exact package-set
        # guard. The fixture replaces only the Python transport output.
        source = """#!/usr/bin/env bash
set -eu
write_color_output() { printf '%s\n' "$1" >&2; }
update_plugin_config_packages() { printf '%s\n' "$3"; }
filter_scanner_output() {
    local pkgs="$SCANNER_OUTPUT"
    local exclude_raw="$EXCLUDES"
""" + packager.STRICT_AUTOLINK_OUTPUT_FILTER + """}
publish() {
    local project_root='unused' gen_dir='unused'
    local expected_react_package="$EXPECTED_PACKAGE"
    local project_react_pkgs="$expected_react_package"
    local autolink_pkgs
    autolink_pkgs="$(filter_scanner_output)"
""" + packager.STRICT_PACKAGE_UPDATE + """}
publish
"""
        return self.run_bash(source, environment={
            "SCANNER_OUTPUT": output,
            "EXCLUDES": "|".join(excludes),
            "EXPECTED_PACKAGE": packager.EXPECTED_PACKAGE,
        })

    def test_lf_crlf_and_terminal_cr_accept_only_exact_known_packages(self):
        packages = (*EXCLUDED, packager.EXPECTED_PACKAGE)
        for newline, final_newline in (("\n", True), ("\r\n", True), ("\r\n", False)):
            with self.subTest(newline=repr(newline), final=final_newline):
                output = newline.join(packages) + (newline if final_newline else "\r")
                result = self.scanner_publication(output)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, (packager.EXPECTED_PACKAGE + "\n").encode())

    def test_unknown_package_and_embedded_or_doubled_cr_are_rejected(self):
        for bad in (
            "com.example.UnreviewedPackage\r\n",
            EXCLUDED[0] + "\r\r\n",
            EXCLUDED[0].replace("MainReact", "Main\rReact") + "\r\n",
            packager.EXPECTED_PACKAGE + "\r\r\n",
            packager.EXPECTED_PACKAGE.replace("PdfRenderer", "Pdf\rRenderer") + "\n",
        ):
            with self.subTest(output=repr(bad)):
                result = self.scanner_publication(bad)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"Unexpected ReactPackage set", result.stderr)

    def test_no_exclusions_still_normalizes_only_one_terminal_cr(self):
        valid = self.scanner_publication(packager.EXPECTED_PACKAGE + "\r\n", excludes=())
        self.assertEqual(valid.returncode, 0, valid.stderr)
        invalid = self.scanner_publication(packager.EXPECTED_PACKAGE + "\r\r\n", excludes=())
        self.assertNotEqual(invalid.returncode, 0)

    def test_native_jq_preserves_both_json_paths_and_caller_exclusions(self):
        if not shutil.which("jq"):
            self.skipTest("Native jq is unavailable; JSON path execution not run")
        config = self.directory / "config.json"
        config.write_text("{}", encoding="utf-8")
        source = """#!/usr/bin/env bash
set -eu
build_generated_config_file="$CONFIG_PATH"
new_apk='app.npk'
icon_file_name='icon.png'
MSYS2_ARG_CONV_EXCL='--preserve-caller-prefix'
""" + packager.STRICT_NATIVE_CODE_PATH_UPDATE + packager.STRICT_ICON_PATH_UPDATE + """
[[ "$MSYS2_ARG_CONV_EXCL" == '--preserve-caller-prefix' ]]
printf '%s\n' "$MSYS2_ARG_CONV_EXCL"
"""
        result = self.run_bash(source, environment={"CONFIG_PATH": config.as_posix()})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"--preserve-caller-prefix\n")
        self.assertEqual(json.loads(config.read_text(encoding="utf-8")), {
            "nativeCodePackage": "/app.npk", "iconPath": "/icon.png",
        })

    def test_native_jq_paths_with_unset_caller_exclusions(self):
        if not shutil.which("jq"):
            self.skipTest("Native jq is unavailable; JSON path execution not run")
        config = self.directory / "unset-config.json"
        config.write_text("{}", encoding="utf-8")
        source = """#!/usr/bin/env bash
set -eu
unset MSYS2_ARG_CONV_EXCL
build_generated_config_file="$CONFIG_PATH"
new_apk='app.npk'
icon_file_name='icon.png'
""" + packager.STRICT_NATIVE_CODE_PATH_UPDATE + packager.STRICT_ICON_PATH_UPDATE + """
[[ ! ${MSYS2_ARG_CONV_EXCL+x} ]]
"""
        result = self.run_bash(source, environment={"CONFIG_PATH": config.as_posix()})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(config.read_text(encoding="utf-8")), {
            "nativeCodePackage": "/app.npk", "iconPath": "/icon.png",
        })

    def test_actual_pinned_template_markers_and_replay_scanner(self):
        if TEMPLATE_TGZ is None:
            self.skipTest("Pass --template for executable pinned-template scanner coverage")
        template.verify_template(TEMPLATE_TGZ)
        with tarfile.open(TEMPLATE_TGZ, "r:gz") as archive:
            members = [item for item in archive.getmembers() if item.name == "package/template/buildPlugin.sh"]
            self.assertEqual(len(members), 1)
            self.assertTrue(members[0].isfile())
            self.assertLess(members[0].size, 100_000)
            stream = archive.extractfile(members[0])
            self.assertIsNotNone(stream)
            original = stream.read().decode("utf-8")
        patched = packager.patch_text(original)
        start = patched.index("get_react_packages_from_autolinking_source() {")
        end = patched.index("# Function: update_plugin_config_packages", start)
        function = patched[start:end]
        package_list = self.directory / "project/android/app/build/generated/autolinking/src/main/java/com/facebook/react/PackageList.java"
        package_list.parent.mkdir(parents=True)
        source_java = "\n".join(
            [*(f"import {name};" for name in (*EXCLUDED, packager.EXPECTED_PACKAGE)),
             "class PackageList { Object[] all = {",
             *(f"new {name.rsplit('.', 1)[1]}()," for name in (*EXCLUDED, packager.EXPECTED_PACKAGE)),
             "}; }"]
        )
        for newline in ("\n", "\r\n"):
            with self.subTest(java_newline=repr(newline)):
                package_list.write_bytes(source_java.replace("\n", newline).encode())
                source = """#!/usr/bin/env bash
set -eu
write_color_output() { printf '%s\n' "$1" >&2; }
python3() { "$PYTHON_EXECUTABLE" "$@"; }
""" + function + """
actual="$(get_react_packages_from_autolinking_source "$PROJECT_ROOT" "$EXCLUDES")"
[[ "$actual" == "$EXPECTED_PACKAGE" ]]
printf '%s\n' "$actual"
"""
                import sys
                result = self.run_bash(source, environment={
                    "PYTHON_EXECUTABLE": Path(sys.executable).as_posix(),
                    "PROJECT_ROOT": (self.directory / "project").as_posix(),
                    "EXCLUDES": "|".join(EXCLUDED),
                    "EXPECTED_PACKAGE": packager.EXPECTED_PACKAGE,
                })
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, (packager.EXPECTED_PACKAGE + "\n").encode())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", type=Path)
    args, remaining = parser.parse_known_args()
    TEMPLATE_TGZ = args.template
    unittest.main(argv=[__file__, *remaining], verbosity=2)
