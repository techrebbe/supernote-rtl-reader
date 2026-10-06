#!/usr/bin/env python3
"""Actual installer/strict App transforms; offline assembly, not device evidence."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
KEY_CLASSES = ("ReaderKeyRouteCore", "ReaderKeyHost", "ReaderKeyConfiguration",
               "ReaderKeyEvent", "ReaderKeyModule", "ReaderKeyHostManager")
KEY_JS = ("ReaderKeyView", "pageTurnerKeys", "pageTurnerTransport", "readerKeySession")


class WiringTests(unittest.TestCase):
    def test_actual_generated_installer_and_measured_wrapper(self):
        with tempfile.TemporaryDirectory(prefix="rtl-t014-assembly-") as directory:
            project = Path(directory)
            java = project / "android/app/src/main/java/example"
            java.mkdir(parents=True)
            application = java / "MainApplication.kt"
            application.write_text("package example\nclass MainApplication {\n  val packages = PackageList(this).packages.apply {\n  }\n}\n", encoding="utf-8")
            app = project / "App.js"
            app.write_text((ROOT / "overlay/App.js").read_text(encoding="utf-8"), encoding="utf-8")
            subprocess.run([sys.executable, str(ROOT / "scripts/patch_direct_view.py"), str(app)], check=True)
            subprocess.run([sys.executable, str(ROOT / "scripts/install_native.py"), str(project), str(ROOT)], check=True)
            subprocess.run([sys.executable, str(ROOT / "scripts/patch_initial_layout.py"), str(app)], check=True)
            for name in KEY_CLASSES:
                self.assertEqual((java / f"{name}.java").read_text(encoding="utf-8"),
                    (ROOT / f"native/{name}.java.template").read_text(encoding="utf-8").replace("__PACKAGE__", "example"))
            package = (java / "PdfRendererPackage.kt").read_text(encoding="utf-8")
            self.assertEqual(package.count("ReaderKeyModule(reactContext)"), 1)
            self.assertEqual(package.count("ReaderKeyHostManager()"), 1)
            self.assertEqual(application.read_text(encoding="utf-8").count("add(PdfRendererPackage())"), 1)
            generated = app.read_text(encoding="utf-8")
            self.assertEqual(generated.count("<ReaderKeyView"), 1)
            self.assertEqual(generated.count("</ReaderKeyView>"), 1)
            self.assertEqual(generated.count("<NativePdfPageView"), 3)
            self.assertIn("setPageAreaLayout(current =>", generated)
            self.assertIn("{...panResponderRef.current.panHandlers}", generated)
            self.assertIn("currentContext={getReaderKeyContext}", generated)

    def test_required_js_is_explicitly_copied_and_registered(self):
        build = (ROOT / "build.sh").read_text(encoding="utf-8")
        for name in KEY_JS:
            self.assertEqual(build.count(f'cp "$ROOT/overlay/{name}.js" "$PROJECT/{name}.js"'), 1)
        source = (ROOT / "overlay/ReaderKeyView.js").read_text(encoding="utf-8")
        self.assertIn("requireNativeComponent('ReaderKeyHost')", source)
        self.assertIn("module.createRequestNamespace()", source)
        self.assertNotIn("Date.now", source)
        self.assertNotIn("setTimeout", source)
        self.assertNotIn("DeviceEventEmitter", source)


if __name__ == "__main__":
    unittest.main()
