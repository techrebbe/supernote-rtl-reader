"""Host-only provenance and tamper checks; no device or network access."""
from __future__ import annotations

import hashlib
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import native_page_display0_bundle as bundle
import native_page_display0_one_shot as one_shot


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.real_here = bundle.HERE
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.here = self.root / "probe"
        self.here.mkdir()
        self.lock = self.here / "frida-display0-lock"
        self.lock.mkdir()
        self.install = self.root / "npm"
        self.install.mkdir()
        self.bridge = self.install / "node_modules" / "frida-java-bridge"
        self.bridge.mkdir(parents=True)
        (self.bridge / "lib").mkdir()
        (self.bridge / "package.json").write_bytes(b'{"version":"7.0.13"}\n')
        (self.bridge / "index.js").write_bytes(b"module.exports = 1;\n")
        (self.bridge / "lib" / "helper.js").write_bytes(b"exports.v = 2;\n")
        committed = self.real_here / "frida-display0-lock"
        self.package = (committed / "package.json").read_bytes()
        self.lock_bytes = (committed / "package-lock.json").read_bytes()
        (self.lock / "package.json").write_bytes(self.package)
        (self.lock / "package-lock.json").write_bytes(self.lock_bytes)
        (self.install / "package.json").write_bytes(self.package)
        (self.install / "package-lock.json").write_bytes(self.lock_bytes)
        self.source = (self.real_here / "native_page_display0_identity_observer.js").read_bytes()
        self.source_path = self.here / "native_page_display0_identity_observer.js"
        self.source_path.write_bytes(self.source)
        self.build = self.here / "build"
        self.bundle_bytes = b"(() => { const Java = 1; })();\n"
        self.patcher = patch.multiple(
            bundle,
            HERE=self.here, LOCK=self.lock, INSTALL=self.install,
            SOURCE=self.source_path, BUILD=self.build,
            ENTRYPOINT=self.build / "native_page_display0_identity_entry.js",
            BUNDLE=self.build / "native_page_display0_identity_bundle.js",
            FRIDA_SITE=self.root / "local-python",
            SOURCE_SHA256=sha(self.source), PACKAGE_SHA256=sha(self.package),
            LOCK_SHA256=sha(self.lock_bytes),
            BRIDGE_TREE_SHA256=bundle._tree_sha256(self.bridge),
            BUNDLE_SHA256=sha(self.bundle_bytes),
        )
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def test_committed_pins_match_real_source_and_lock(self):
        self.assertEqual(one_shot.OBSERVER_SHA256, sha(self.source))
        self.assertEqual(bundle.SOURCE_SHA256, sha(self.source))
        self.assertEqual(bundle.PACKAGE_SHA256, sha(self.package))
        self.assertEqual(bundle.LOCK_SHA256, sha(self.lock_bytes))

    def test_deterministic_offline_compile_then_exact_load(self):
        calls = []

        class FakeCompiler:
            def build(self, entrypoint, **kwargs):
                calls.append((entrypoint, kwargs))
                entry = Path(entrypoint).read_bytes()
                self_test.assertEqual(entry, bundle.IMPORT + self_test.source)
                return self_test.bundle_bytes.decode("utf-8")

        self_test = self
        fake_frida = SimpleNamespace(Compiler=FakeCompiler)
        with patch.dict(sys.modules, {"frida": fake_frida}), \
                patch.object(bundle.importlib.metadata, "version",
                             return_value=bundle.FRIDA_VERSION):
            built = bundle.build_verified_bundle()
        self.assertEqual(built, self.bundle_bytes)
        self.assertEqual(bundle.load_verified_bundle(), self.bundle_bytes)
        self.assertEqual(len(calls), 1)
        entrypoint, options = calls[0]
        self.assertEqual(entrypoint, str(bundle.ENTRYPOINT))
        self.assertEqual(options, {
            "project_root": str(bundle.BUILD),
            "output_format": "unescaped", "bundle_format": "iife",
            "type_check": "none", "source_maps": "omitted",
            "compression": "none", "platform": "gum",
        })
        self.assertEqual(bundle._tree_sha256(bundle.BUILD / "node_modules" /
                                             "frida-java-bridge"),
                         bundle.BRIDGE_TREE_SHA256)

    def test_tampered_published_bundle_is_rejected(self):
        self.build.mkdir()
        bundle.BUNDLE.write_bytes(self.bundle_bytes + b"// tampered\n")
        with self.assertRaisesRegex(bundle.BundleError, "^BUNDLE_HASH_MISMATCH$"):
            bundle.load_verified_bundle()

    def test_lock_source_and_installed_tree_tampering_fail_closed(self):
        cases = (
            (self.lock / "package-lock.json", "BUNDLE_LOCK_CHANGED"),
            (self.source_path, "BUNDLE_SOURCE_CHANGED"),
            (self.bridge / "index.js", "BUNDLE_INSTALL_CHANGED"),
        )
        for target, code in cases:
            with self.subTest(target=target.name):
                original = target.read_bytes()
                target.write_bytes(original + b"x")
                try:
                    with self.assertRaisesRegex(bundle.BundleError, "^" + code + "$"):
                        bundle.check_inputs()
                finally:
                    target.write_bytes(original)

    def test_compiler_output_drift_cannot_publish(self):
        class DriftCompiler:
            def build(self, *_args, **_kwargs):
                return "different output"

        with patch.dict(sys.modules, {"frida": SimpleNamespace(Compiler=DriftCompiler)}), \
                patch.object(bundle.importlib.metadata, "version",
                             return_value=bundle.FRIDA_VERSION):
            with self.assertRaisesRegex(bundle.BundleError,
                                        "^BUNDLE_HASH_MISMATCH$"):
                bundle.build_verified_bundle()
        self.assertFalse(bundle.BUNDLE.exists())


if __name__ == "__main__":
    unittest.main()
