#!/usr/bin/env python3
"""Bounded T006 source/generated-wiring gate; not annotation geometry authority."""

from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WiringTests(unittest.TestCase):
    def test_generated_views_share_token_only_native_layer(self):
        with tempfile.TemporaryDirectory(prefix="rtl-ink-wiring-") as folder:
            app = Path(folder) / "App.js"
            app.write_text((ROOT / "overlay/App.js").read_text(encoding="utf-8"), encoding="utf-8")
            for patch in ("patch_direct_view.py", "patch_initial_layout.py"):
                subprocess.run([sys.executable, str(ROOT / "scripts" / patch), str(app)], check=True)
            generated = app.read_text(encoding="utf-8")
            for side in ("leftPageIndex", "rightPageIndex", "singlePageIndex"):
                self.assertIn(f"savedInkToken={{savedInkTokenFor(display.{side})}}", generated)
            self.assertEqual(generated.count("<NativePdfPageView"), 3)
            self.assertNotIn("source={{uri: savedInk", generated)
            self.assertIn("const previousCleanup = globalThis.RTL_READER_INK_CLEANUP", generated)
            self.assertIn("const result = await controller.dispose();", generated)
            jump = generated[generated.index("const submitJump = () => {"):generated.index("const footerLabel =")]
            self.assertNotIn("pageIndexRef.current =", jump,
                             "Generated Jump must not hide the old page from the synchronous cancellation fence")
            self.assertIn("setPageIndex(target)", jump)

    def test_build_registers_and_copies_all_dependencies(self):
        build = (ROOT / "build.sh").read_text(encoding="utf-8")
        installer = (ROOT / "scripts/install_native.py").read_text(encoding="utf-8")
        package = (ROOT / "native/PdfRendererPackage.kt.template").read_text(encoding="utf-8")
        self.assertIn('cp "$ROOT/overlay/savedInk.js" "$PROJECT/savedInk.js"', build)
        for name in ("SavedInkModule", "SavedInkRegistry", "SavedInkProfiles"):
            self.assertIn(f'("{name}.kt.template", "{name}.kt")', installer)
        self.assertIn('("SavedInkFitGeometry.java.template", "SavedInkFitGeometry.java")', installer)
        self.assertIn("SavedInkModule(reactContext)", package)

    def test_background_cache_does_not_acquire_annotation_authority(self):
        view = (ROOT / "native/PdfPageView.kt.template").read_text(encoding="utf-8")
        start = view.index("private data class RenderKey(")
        end = view.index("class PdfPageView(")
        self.assertNotIn("SavedInkRegistry", view[start:end])
        draw = view[view.index("override fun onDraw(canvas: Canvas)"):]
        self.assertIn("canvas.drawBitmap(bitmap, null, destination, bitmapPaint)", draw)
        self.assertIn("destination", draw[draw.index("canvas.drawBitmap(bitmap"):])
        self.assertIn('name = "savedInkToken"',
                      (ROOT / "native/PdfPageViewManager.kt.template").read_text(encoding="utf-8"))

    def test_candidate_identity_and_ci_gates(self):
        config = json.loads((ROOT / "PluginConfig.json").read_text(encoding="utf-8"))
        self.assertEqual(config["versionName"], "0.4.24-keys-exp2")
        self.assertEqual(config["versionCode"], "53")
        self.assertEqual(config["pluginID"], "snrtl20260726001")
        self.assertIn("RTL_READER_OPEN v0.4.24-keys-exp2-native-reader-v2",
                      (ROOT / "overlay/index.js").read_text(encoding="utf-8"))
        workflow = (ROOT / ".github/workflows/build.yml").read_text(encoding="utf-8")
        for gate in ("test_saved_ink.js", "test_saved_ink_app.js",
                     "test_saved_ink_landscape_app.js", "test_saved_ink_batch.js", "test_saved_ink_wiring.py"):
            self.assertIn(gate, workflow)

    def test_cleanup_acknowledges_exact_main_thread_lease_drain(self):
        registry = (ROOT / "native/SavedInkRegistry.kt.template").read_text(encoding="utf-8")
        module = (ROOT / "native/SavedInkModule.kt.template").read_text(encoding="utf-8")
        self.assertIn("val leases = HashSet<Lease>()", registry)
        self.assertEqual(registry.count("check(Looper.myLooper() == Looper.getMainLooper())"), 2)
        drain = registry[registry.index("fun drainRevoked("):registry.index("private fun reap(")]
        for marker in ("mainHandler.post", "val entry = entries[token]", "entry?.owner == true",
                       "revokedLeases.forEach { it.release() }", "!entries.containsKey(token)"):
            self.assertIn(marker, drain)
        self.assertNotIn("postDelayed", drain)
        discard = module[module.index("fun discard("):module.index("override fun invalidate()")]
        self.assertLess(discard.index("removeOwned(request)"), discard.index("drainRevoked("))
        self.assertLess(discard.index("if (drained)"), discard.index("promise.resolve("))
        self.assertIn("promise.reject(", discard)

    def test_unfinished_sdk_output_is_not_deleted_on_invalidation(self):
        module = (ROOT / "native/SavedInkModule.kt.template").read_text(encoding="utf-8")
        invalidation = module[module.index("override fun invalidate()") :]
        self.assertLess(invalidation.index("if (!request.finished)"), invalidation.index("removeOwned(request)"))
        self.assertIn("return@forEach", invalidation)
        self.assertIn("drainRevoked(request.inkToken)", invalidation)


if __name__ == "__main__":
    unittest.main()
