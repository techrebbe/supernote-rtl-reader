#!/usr/bin/env python3
"""Bounded T008 renderer wiring checks, not Android/hardware registration proof.

Checks the actual template's geometry, source-bound cache/reuse and separate-layer
contracts. Geometry arithmetic has its own executable Java harness; Android's
actual PDF rendering and native ink registration remain hardware gates.
"""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RendererTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.view = (ROOT / "native/PdfPageView.kt.template").read_text(encoding="utf-8")

    def section(self, start, end):
        return self.view[self.view.index(start):self.view.index(end)]

    def test_background_identity_is_source_bound_not_ink_authority(self):
        key = self.section("private data class RenderKey(", "private data class CachedBitmap(")
        self.assertIn("val geometryId: String?", key)
        self.assertIn("val profileStamp: SavedInkProfiles.SourceStamp?", key)
        self.assertIn("val background: SavedInkProfiles.VerifiedBackground?", key)
        make = self.section("private fun makeKey(", "private fun closeRendererLocked()")
        self.assertLess(make.index("SavedInkProfiles.verifyBackground(filePath, pageIndex)"),
                        make.index("key = RenderKey("))
        for field in ("geometryId = background?.id", "profileStamp = background?.stamp",
                      "length = background?.stamp?.length", "modified = background?.stamp?.modified"):
            self.assertIn(field, make)
        engine = self.section("private object PdfDirectRenderEngine", "class PdfPageView(")
        self.assertNotIn("SavedInkRegistry", engine)
        self.assertNotIn("savedInkToken", engine)

    def test_renderer_reuse_includes_full_profile_evidence(self):
        reuse = self.section("private fun ensureRendererLocked(", "private fun renderLocked(")
        for field in ("activePath == key.canonicalPath", "activeLength == key.length",
                      "activeModified == key.modified", "activeGeometryId == key.geometryId",
                      "activeProfileStamp == key.profileStamp"):
            self.assertIn(field, reuse)
        existing = reuse[reuse.index("if (canReuse)"):reuse.index("return Pair(existing!!, true)")]
        self.assertIn("background?.validateDescriptor(checkNotNull(activeDescriptor).fileDescriptor)", existing)
        self.assertIn("background?.validatePath()", existing)
        self.assertIn("closeRendererLocked()", existing)
        self.assertIn("clearCache()", existing)
        open_start = reuse.index("val descriptor =")
        opened = reuse[open_start:reuse.index("activePath =", open_start)]
        self.assertLess(opened.index("background?.validateDescriptor(descriptor.fileDescriptor)"),
                        opened.index("PdfRenderer(descriptor)"))
        self.assertLess(opened.index("background?.validatePath()"), opened.index("PdfRenderer(descriptor)"))
        reset = self.section("private fun closeRendererLocked()", "private fun ensureRendererLocked(")
        self.assertIn("activeGeometryId = null", reset)
        self.assertIn("activeProfileStamp = null", reset)

    def test_profile_has_full_white_canvas_and_uniform_stock_ctm(self):
        render = self.section("private fun renderLocked(", "private fun validateCachedBackground(")
        self.assertIn("renderer.pageCount == 2 && page.width == 612 && page.height == 792", render)
        self.assertIn("val width = geometry?.canvasWidth ?: key.requestedWidth", render)
        self.assertIn("val height = geometry?.canvasHeight ?: max(", render)
        self.assertIn("Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)", render)
        self.assertLess(render.index("bitmap.eraseColor(Color.WHITE)"), render.index("val matrix = Matrix()"))
        self.assertIn("setScale(geometry.ctmScale, geometry.ctmScale)", render)
        self.assertLess(render.index("setScale(geometry.ctmScale, geometry.ctmScale)"),
                        render.index("postTranslate(geometry.offsetX.toFloat(), geometry.offsetY.toFloat())"))
        self.assertIn("geometry.offsetX + geometry.innerWidth", render)
        self.assertIn("geometry.offsetY + geometry.innerHeight", render)
        self.assertIn("page.render(bitmap, innerRect, matrix, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)", render)
        self.assertNotIn("setRectToRect", render)
        self.assertNotIn("geometry.innerWidth.toFloat() /", render)
        self.assertNotIn("geometry.innerHeight.toFloat() /", render)
        self.assertIn("background.validateDescriptor(checkNotNull(activeDescriptor).fileDescriptor)", render)
        self.assertIn("background.validatePath()", render)

    def test_default_transform_is_preserved_and_profile_is_never_trimmed(self):
        render = self.section("private fun renderLocked(", "private fun validateCachedBackground(")
        self.assertIn("key.requestedWidth.toDouble() * page.height.toDouble() / page.width.toDouble()", render)
        self.assertIn("bitmap,\n                    null,\n                    null,", render)
        self.assertIn("if (detectTrimming && background == null) NativeFillTrimming.detect(bitmap) else null", render)
        foreground = self.section("fun renderForeground(", "fun schedulePrefetch(")
        self.assertEqual(foreground.count("if (detectTrimming && request.background == null)"), 2)

    def test_both_cache_hit_paths_validate_and_recycle_invalid_profile(self):
        cached = self.section("private fun validateCachedBackground(", "fun renderForeground(")
        self.assertIn("val background = request.background ?: return", cached)
        self.assertIn("background.validatePath()", cached)
        self.assertIn("cached.pageCount == 2", cached)
        self.assertIn("cached.bitmap.width == geometry.canvasWidth", cached)
        self.assertIn("cached.bitmap.height == geometry.canvasHeight", cached)
        self.assertIn("cached.trimmingRect == null", cached)
        self.assertIn("recycleCached(cached)", cached)
        self.assertIn("throw error", cached)
        foreground = self.section("fun renderForeground(", "fun schedulePrefetch(")
        self.assertEqual(foreground.count("validateCachedBackground(request, cached)"), 2)
        self.assertIn("val result = renderLocked(request, totalStarted, detectTrimming)", foreground)

    def test_prefetch_and_visible_return_retain_original_profile_key(self):
        prefetch = self.section("fun schedulePrefetch(", "class PdfPageView(")
        self.assertIn("makeKey(filePath, pageIndex, requestedWidth)", prefetch)
        self.assertIn("val key = request.key", prefetch)
        self.assertIn("val result = renderLocked(\n                            request,", prefetch)
        self.assertIn("putCached(\n                            key,", prefetch)
        self.assertNotIn("RenderKey(", prefetch)
        visible = self.section("fun returnVisibleBitmap(", "private fun makeKey(")
        self.assertIn("putCached(\n            key,", visible)
        self.assertNotIn("RenderKey(", visible)
        self.assertIn("key = result.key", self.view)
        self.assertIn("previousMetadata.key", self.view)
        self.assertIn("result.key,\n                            result.pageCount", self.view)

    def test_generation_and_foreground_prefetch_priority_fences_remain(self):
        foreground = self.section("fun renderForeground(", "fun schedulePrefetch(")
        self.assertGreaterEqual(foreground.count("if (!isCurrent())"), 5)
        for marker in ("pendingPrefetch.remove(key)", "foregroundDemand.incrementAndGet()",
                       "foregroundDemand.decrementAndGet()", "putCached(key, cached)"):
            self.assertIn(marker, foreground)
        self.assertIn("if (generation != renderGeneration.get())", self.view)
        self.assertIn("if (pending.generation == renderGeneration.get())", self.view)

    def test_overlay_uses_same_destination_clip_and_exact_geometry_id(self):
        draw = self.view[self.view.index("override fun onDraw(canvas: Canvas)"):]
        self.assertEqual(draw.count("canvas.clipRect("), 1)
        self.assertIn("canvas.drawBitmap(bitmap, null, destination, bitmapPaint)", draw)
        self.assertIn("canvas.drawBitmap(ink.bitmap, null, destination, bitmapPaint)", draw)
        self.assertIn("geometryId = key.geometryId", draw)
        self.assertIn("ink.matchesPage(key.canonicalPath, key.pageIndex)", draw)
        self.assertIn("clearSavedInk()", draw)
        self.assertNotIn("Bitmap.createBitmap", draw)


if __name__ == "__main__":
    unittest.main()
