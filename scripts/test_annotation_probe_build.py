#!/usr/bin/env python3
"""Bounded tests of diagnostic build identity and scoped verifier overrides.

Runs the actual diagnostic prepare/verify orchestration with temporary generated
files and mocked external/materialization boundaries. No npm, shell build,
Android SDK, network, or device is used. Production defaults are never edited.
"""
from __future__ import annotations

import base64
import copy
import gzip
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import build_annotation_preview_probe as build
import verify_annotation_preview_probe as probe_verifier


ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_NAME = '    PACKAGE_NAME="$name"'
DIAGNOSTIC_NAME = '    PACKAGE_NAME="SupernoteRtlInkProbe"'
MARKER = b"v0.0.1-ink-probe"


def snapshot(module, names):
    return {name: (getattr(module, name), copy.deepcopy(getattr(module, name))) for name in names}


def minimal_upstream_script(name_assignment=UPSTREAM_NAME):
    # Actual hardened packager markers, not a copied implementation of patching.
    return "\n".join((
        "#!/usr/bin/env bash", name_assignment,
        build.packager.APK_COPY_FUNCTION_MARKER,
        build.packager.UPSTREAM_APK_SELECTION,
        build.packager.UPSTREAM_PACKAGE_SCAN,
        build.packager.UPSTREAM_PACKAGE_UPDATE,
        build.packager.UPSTREAM_SOFT_NATIVE_BUILD,
    ))


class ProbeBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rtl-annotation-probe-build-test-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.destination = self.directory / "generated"
        self.tarball = self.directory / "unused-pinned-template.tgz"
        self.lock_source = ROOT / "provenance/plugin-template-package-lock.json.gz.b64"
        encoded = "".join(self.lock_source.read_text(encoding="ascii").split())
        self.lock_bytes = gzip.decompress(base64.b64decode(encoded, validate=True))
        root_package = json.loads(self.lock_bytes)["packages"][""]
        self.package_bytes = json.dumps({
            key: root_package[key]
            for key in ("name", "version", "dependencies", "devDependencies", "engines")
        }, sort_keys=True).encode("utf-8")
        # Validate against the actual frozen input before relying on the fixture.
        self.assertEqual(
            build.template.read_and_validate_lock(self.lock_source, self.package_bytes),
            self.lock_bytes,
        )
        self.packager_defaults = snapshot(build.packager, [
            name for name in vars(build.packager)
            if name.startswith("EXPECTED_") or name == "STRICT_PACKAGE"
        ])
        self.template_defaults = snapshot(build.template, [
            name for name in vars(build.template)
            if name.startswith("EXPECTED_") or name in ("PROJECT_NAME", "PACKAGE_NAME")
        ])
        self.verifier_defaults = snapshot(probe_verifier.verifier, [
            name for name in vars(probe_verifier.verifier)
            if name.startswith("EXPECTED_") or name == "expected_runtime_marker"
        ])

    def assert_restored(self, module, values):
        for name, (original, before) in values.items():
            self.assertIs(getattr(module, name), original, name)
            self.assertEqual(getattr(module, name), before, name)

    def assert_build_defaults_restored(self):
        self.assert_restored(build.packager, self.packager_defaults)
        self.assert_restored(build.template, self.template_defaults)

    def assert_frozen_generated_inputs(self):
        self.assertEqual((self.destination / "package.json").read_bytes(), self.package_bytes)
        self.assertEqual((self.destination / "package-lock.json").read_bytes(), self.lock_bytes)

    def materialize_fixture(self, script):
        def materialize(tarball, lock_source, destination):
            self.assertEqual(tarball, self.tarball)
            self.assertEqual(lock_source, self.lock_source)
            self.assertEqual(destination, self.destination)
            self.assertFalse(destination.exists())
            destination.mkdir()
            (destination / "buildPlugin.sh").write_text(script, encoding="utf-8")
            (destination / "package.json").write_bytes(self.package_bytes)
            (destination / "package-lock.json").write_bytes(self.lock_bytes)
        return materialize

    def run_prepare(self, script=None, *, patch_failure=None, install_failure=None):
        if script is None:
            script = minimal_upstream_script()
        with mock.patch.object(build.template, "materialize", side_effect=self.materialize_fixture(script)) as materialize:
            with mock.patch.object(build, "install", side_effect=install_failure) as install:
                with redirect_stdout(io.StringIO()):
                    if patch_failure is None:
                        build.prepare(self.tarball, ROOT, self.destination)
                    else:
                        with mock.patch.object(build.packager, "patch_text", side_effect=patch_failure):
                            build.prepare(self.tarball, ROOT, self.destination)
        materialize.assert_called_once_with(self.tarball, self.lock_source, self.destination)
        install.assert_called_once_with(self.destination, ROOT)

    def verification_inputs(self):
        repo = self.directory / "fixture-repo"
        probe = repo / "probes/annotation-preview"
        probe.mkdir(parents=True)
        (probe / "index.js").write_text("console.log('RTL_READER_OPEN v0.0.1-ink-probe');\n", encoding="utf-8")
        bundle = self.directory / "probe.bundle"
        apk = self.directory / "app.npk"
        package = self.directory / "probe.snplg"
        bundle.write_bytes(b"diagnostic bundle")
        apk.write_bytes(b"diagnostic apk")
        return package, repo, bundle, apk

    def assert_diagnostic_verifier(self, package, root, bundle, apk):
        verifier = probe_verifier.verifier
        self.assertEqual(verifier.EXPECTED_REACT_PACKAGES, ["com.supernotertlinkprobe.PdfRendererPackage"])
        self.assertEqual(verifier.EXPECTED_NATIVE_CLASS_DESCRIPTORS, (
            b"Lcom/supernotertlinkprobe/AnnotationPreviewModule;",
            b"Lcom/supernotertlinkprobe/PdfRendererPackage;",
        ))
        self.assertEqual(verifier.EXPECTED_ANDROID_PACKAGE, "com.supernotertlinkprobe")
        self.assertEqual(verifier.EXPECTED_ANDROID_APPLICATION, "com.supernotertlinkprobe.MainApplication")
        self.assertEqual(verifier.EXPECTED_ANDROID_ACTIVITY, "com.supernotertlinkprobe.MainActivity")
        changed = {
            "EXPECTED_REACT_PACKAGES", "EXPECTED_NATIVE_CLASS_DESCRIPTORS",
            "EXPECTED_ANDROID_PACKAGE", "EXPECTED_ANDROID_APPLICATION", "EXPECTED_ANDROID_ACTIVITY",
            "expected_runtime_marker",
        }
        for name, (_, original) in self.verifier_defaults.items():
            if name not in changed:
                self.assertEqual(getattr(verifier, name), original, f"Unchanged production security contract: {name}")
        self.assertEqual(verifier.expected_runtime_marker(root), MARKER)
        self.assertEqual(bundle, b"diagnostic bundle")
        self.assertEqual(apk, b"diagnostic apk")

    def test_prepare_uses_actual_packager_with_diagnostic_name_and_unchanged_pinned_inputs(self):
        self.run_prepare()
        generated = (self.destination / "buildPlugin.sh").read_text(encoding="utf-8")
        self.assertEqual(generated.count(DIAGNOSTIC_NAME), 1)
        self.assertNotIn(UPSTREAM_NAME, generated)
        self.assertIn('local expected_react_package="com.supernotertlinkprobe.PdfRendererPackage"', generated)
        self.assertIn("android/app/src/main/java/com/supernotertlinkprobe/PdfRendererPackage.kt", generated)
        self.assertIn("android/app/src/main/java/com/supernotertlreader/MainApplication.kt", generated)
        self.assertIn("sign_compacted_apk()", generated)
        self.assertIn(build.packager.EXPECTED_PLUGIN_APK_SIGNER_SHA256, generated)
        self.assert_frozen_generated_inputs()
        self.assert_build_defaults_restored()

    def test_missing_and_duplicate_template_name_assignments_fail_closed(self):
        for assignment in ("", UPSTREAM_NAME + "\n" + UPSTREAM_NAME):
            with self.subTest(assignment=assignment):
                self.destination = self.directory / f"generated-{len(assignment)}"
                with self.assertRaises(SystemExit):
                    self.run_prepare(minimal_upstream_script(assignment))
                self.assert_frozen_generated_inputs()
                self.assert_build_defaults_restored()

    def test_prepare_packager_exceptions_restore_globals_without_changing_pinned_inputs(self):
        for number, error in enumerate((SystemExit("strict failure"), RuntimeError("patch failure"), KeyboardInterrupt())):
            with self.subTest(error=type(error).__name__):
                self.destination = self.directory / f"patch-failure-{number}"
                with self.assertRaises(type(error)):
                    self.run_prepare(patch_failure=error)
                self.assert_frozen_generated_inputs()
                self.assert_build_defaults_restored()

    def test_prepare_install_failure_preserves_defaults_and_dependency_pins(self):
        with self.assertRaisesRegex(RuntimeError, "install failure"):
            self.run_prepare(install_failure=RuntimeError("install failure"))
        self.assert_frozen_generated_inputs()
        self.assert_build_defaults_restored()

    def test_prepare_materialization_failure_never_installs_or_changes_defaults(self):
        with mock.patch.object(build.template, "materialize", side_effect=SystemExit("materialization rejected")):
            with mock.patch.object(build, "install") as install:
                with self.assertRaises(SystemExit):
                    build.prepare(self.tarball, ROOT, self.destination)
        install.assert_not_called()
        self.assertFalse(self.destination.exists())
        self.assert_build_defaults_restored()

    def test_prepare_generated_write_failure_restores_scoped_packager(self):
        original_write = Path.write_text
        count = 0

        def fail_second_script_write(path, content, *args, **kwargs):
            nonlocal count
            if path.name == "buildPlugin.sh":
                count += 1
                if count == 2:
                    raise OSError("generated script write failure")
            return original_write(path, content, *args, **kwargs)

        with mock.patch.object(Path, "write_text", new=fail_second_script_write):
            with self.assertRaisesRegex(OSError, "script write failure"):
                self.run_prepare()
        self.assertEqual(count, 2)
        self.assert_frozen_generated_inputs()
        self.assert_build_defaults_restored()

    def test_verifier_uses_diagnostic_overrides_then_restores_all_production_defaults(self):
        inputs = self.verification_inputs()
        with mock.patch.object(probe_verifier.verifier, "verify", side_effect=self.assert_diagnostic_verifier) as verify:
            probe_verifier.verify(*inputs)
        verify.assert_called_once_with(inputs[0], inputs[1] / "probes/annotation-preview", b"diagnostic bundle", b"diagnostic apk")
        self.assert_restored(probe_verifier.verifier, self.verifier_defaults)

    def test_verifier_failure_restores_globals_even_for_system_exit_and_interrupt(self):
        inputs = self.verification_inputs()
        for error in (SystemExit("rejected diagnostic"), RuntimeError("failed verifier"), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                def fail_after_observation(*args):
                    self.assert_diagnostic_verifier(*args)
                    raise error
                with mock.patch.object(probe_verifier.verifier, "verify", side_effect=fail_after_observation):
                    with self.assertRaises(type(error)):
                        probe_verifier.verify(*inputs)
                self.assert_restored(probe_verifier.verifier, self.verifier_defaults)

    def test_verifier_missing_binary_input_restores_globals_before_lower_verifier(self):
        inputs = self.verification_inputs()
        for index in (2, 3):
            with self.subTest(input=index):
                changed = list(inputs)
                changed[index] = self.directory / f"missing-{index}"
                with mock.patch.object(probe_verifier.verifier, "verify") as verify:
                    with self.assertRaises(FileNotFoundError):
                        probe_verifier.verify(*changed)
                verify.assert_not_called()
                self.assert_restored(probe_verifier.verifier, self.verifier_defaults)

    def test_verifier_rejects_missing_and_duplicate_runtime_markers_then_restores_defaults(self):
        inputs = self.verification_inputs()
        index = inputs[1] / "probes/annotation-preview/index.js"
        for source in ("no marker", "RTL_READER_OPEN first\nRTL_READER_OPEN second\n"):
            with self.subTest(source=source):
                index.write_text(source, encoding="utf-8")
                def exercise_runtime_marker(_package, root, _bundle, _apk):
                    probe_verifier.verifier.expected_runtime_marker(root)
                with mock.patch.object(probe_verifier.verifier, "verify", side_effect=exercise_runtime_marker):
                    with self.assertRaises(SystemExit):
                        probe_verifier.verify(*inputs)
                self.assert_restored(probe_verifier.verifier, self.verifier_defaults)

    def test_two_successful_verifications_do_not_leak_diagnostic_identity(self):
        inputs = self.verification_inputs()
        for _ in range(2):
            with mock.patch.object(probe_verifier.verifier, "verify", side_effect=self.assert_diagnostic_verifier):
                probe_verifier.verify(*inputs)
            self.assert_restored(probe_verifier.verifier, self.verifier_defaults)
            self.assertEqual(probe_verifier.verifier.EXPECTED_ANDROID_PACKAGE, "com.supernotertlreader")


if __name__ == "__main__":
    unittest.main(verbosity=2)
