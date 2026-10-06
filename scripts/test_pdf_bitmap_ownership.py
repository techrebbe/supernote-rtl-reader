#!/usr/bin/env python3
"""Execute actual Kotlin cache/drop methods with strict bitmap ownership doubles.

Extracts declarations and methods verbatim from PdfPageView.kt.template. Does not
execute Android rendering, the RN lifecycle, SDK ink or file verification. The
unchanged async callback and generated transient-detach boundary are source
checked, not claimed as runtime/device evidence. Uses the same cached Kotlin
2.0.21/JDK17 toolchain as test_saved_ink_native_profiles.py; no downloads/skip.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from test_saved_ink_native_profiles import compiler_jars, jdk_tools


def section(source: str, start: str, end: str) -> str:
    if source.count(start) != 1 or source.count(end) != 1:
        raise AssertionError(f"Ambiguous actual-source boundary: {start!r}/{end!r}")
    return source[source.index(start):source.index(end)]


def actual_methods(root: Path) -> str:
    source = (root / "native/PdfPageView.kt.template").read_text(encoding="utf-8")
    key = section(source, "private data class RenderKey(", "private data class RenderRequest(")
    cached = section(source, "private data class CachedBitmap(", "private data class DirectRenderResult(")
    metadata = section(source, "private data class VisibleBitmapMetadata(", "private object NativeFillTrimming {")
    cache = section(source, "    private fun recycleCached(", "    private fun makeKey(")
    dispose = section(source, "    fun dispose() {", "    private fun commitSavedInkProps() {")
    replace = section(source, "    private fun replaceBitmap(", "    private fun emitRenderedAfterDraw(")
    limit = next(line for line in source.splitlines() if "private const val CACHE_LIMIT =" in line)
    cache_field = next(line for line in source.splitlines() if "private val bitmapCache =" in line)
    stale = section(source, "                post {\n                    if (generation != renderGeneration.get()) {",
                    "                    val renderedEvent = PendingRenderedEvent(")
    assert "result.key," in stale and "return@post" in stale
    assert "pendingRenderedEvent" not in stale and "replaceBitmap" not in stale
    assert "previousMetadata.key," in replace
    draw = source[source.index("override fun onDraw(canvas: Canvas)"):]
    assert "canvas.drawBitmap(bitmap, null, destination, bitmapPaint)" in draw
    assert "canvas.drawBitmap(ink.bitmap, null, destination, bitmapPaint)" in draw
    assert "Bitmap.createBitmap" not in draw  # Never cache a composited ink image.
    manager = (root / "native/PdfPageViewManager.kt.template").read_text(encoding="utf-8")
    assert "view.dispose()" in manager
    return "\n".join([
        "import java.util.LinkedHashMap\nimport java.util.concurrent.atomic.AtomicLong",
        DOUBLES, key, cached, metadata,
        "private object PdfDirectRenderEngine {\nprivate const val LOG_TAG = \"TEST\"\n" + limit + "\n" + cache_field,
        "private val cacheLock = Any()\nprivate val pendingPrefetch = HashSet<RenderKey>()",
        cache, ENGINE_ACCESS, "}", VIEW_FIELDS, dispose, replace, VIEW_ACCESS, HARNESS,
    ])


DOUBLES = r'''
// Strict doubles: fail if a bitmap has two owners or is recycled twice.
private class Bitmap(val label: String) {
    var isRecycled = false; private set
    var recycleCount = 0; private set
    fun recycle() { check(!isRecycled) { "Double recycle: $label" }; isRecycled = true; recycleCount++ }
}
private class RectF(var left: Float, var top: Float, var right: Float, var bottom: Float) {
    constructor(rect: RectF): this(rect.left, rect.top, rect.right, rect.bottom)
}
private object SavedInkProfiles {
    data class SourceStamp(val device: Long, val inode: Long, val length: Long, val modified: Long)
}
private object SavedInkRegistry {
    class Lease(val bitmap: Bitmap) {
        var releases = 0; private set
        fun release() { check(releases == 0); releases++; bitmap.recycle() }
    }
}
private object Log { fun i(tag: String, message: String) = 0 }
'''

ENGINE_ACCESS = r'''
    fun take(key: RenderKey) = takeCached(key)
    fun reset() = clearCache()
    fun snapshot(): List<CachedBitmap> = synchronized(cacheLock) { bitmapCache.values.toList() }
'''

VIEW_FIELDS = r'''
private class DropHarness {
    private val renderGeneration = AtomicLong(7L)
    private var committedSignature: String? = "rendered"
    private var pendingRenderedEvent: Any? = Any()
    private var savedInkLease: SavedInkRegistry.Lease? = null
    private var savedInkToken: String? = null
    private var pageBitmap: Bitmap? = null
    private var pageBitmapMetadata: VisibleBitmapMetadata? = null
'''

VIEW_ACCESS = r'''
    fun install(bitmap: Bitmap, key: RenderKey?, trim: RectF? = null) {
        replaceBitmap(bitmap, key?.let { VisibleBitmapMetadata(it, 10, trim) })
    }
    fun ink(lease: SavedInkRegistry.Lease) { savedInkLease = lease; savedInkToken = "ink-only" }
    fun visible() = pageBitmap
    fun generation() = renderGeneration.get()
    fun retired() = committedSignature == null && pendingRenderedEvent == null &&
        savedInkToken == null && savedInkLease == null && pageBitmapMetadata == null
    fun invalidProps() = replaceBitmap(null, null, cachePrevious = false)
}
'''

HARNESS = r'''
object PdfBitmapOwnershipTest {
    private var assertions = 0
    private fun expect(value: Boolean, message: String) { assertions++; check(value) { message } }
    private fun key(page: Int = 0) = RenderKey("/test/a.pdf", 100, 7, page, 1404,
        "profile-a", SavedInkProfiles.SourceStamp(1, 101, 100, 7))
    private fun dropTransfersOnce() {
        PdfDirectRenderEngine.reset()
        val bitmap = Bitmap("background"); val ink = Bitmap("ink")
        val lease = SavedInkRegistry.Lease(ink); val view = DropHarness()
        val trim = RectF(2f, 3f, 9f, 12f)
        view.install(bitmap, key(), trim); view.ink(lease)
        view.dispose()
        expect(!bitmap.isRecycled, "Drop must return the pure background, not recycle it")
        expect(view.visible() == null && view.retired(), "Drop retires all view ownership/events/ink")
        expect(view.generation() == 8L, "Drop must invalidate queued callbacks")
        expect(lease.releases == 1 && ink.recycleCount == 1, "Ink lease releases exactly once")
        view.dispose()
        expect(view.generation() == 9L && lease.releases == 1, "Repeated drop retains fences without double release")
        val cached = PdfDirectRenderEngine.take(key()) ?: error("Original key not retained")
        expect(cached.bitmap === bitmap && cached.pageCount == 10, "Exact background ownership transfers")
        trim.left = 999f
        expect(cached.trimmingRect?.left == 2f, "Return copies trim metadata")
        expect(PdfDirectRenderEngine.take(key()) == null, "Taking cache removes its ownership")
        expect(PdfDirectRenderEngine.snapshot().isEmpty(), "Ink must never enter background LRU")
        bitmap.recycle()
    }
    private fun overlappingSameKeyOwnership() {
        PdfDirectRenderEngine.reset()
        val first = Bitmap("first"); val second = Bitmap("second"); val third = Bitmap("third")
        val a = DropHarness(); val b = DropHarness(); val c = DropHarness()
        a.install(first, key()); b.install(second, key()); c.install(third, key())
        a.dispose()
        val taken = PdfDirectRenderEngine.take(key()) ?: error("No first background")
        val display = DropHarness(); display.install(taken.bitmap, key())
        b.dispose(); c.dispose() // Only the cached second may be replaced/recycled.
        expect(!first.isRecycled && display.visible() === first, "Duplicate key must not recycle a displayed bitmap")
        expect(second.recycleCount == 1 && !third.isRecycled, "Replace recycles cache-owned predecessor only")
        expect(PdfDirectRenderEngine.take(key())?.bitmap === third, "Newest cache-owned instance retained")
        third.recycle(); display.dispose()
        expect(PdfDirectRenderEngine.take(key())?.bitmap === first, "Displayed owner can return safely later")
        first.recycle()
    }
    private fun originalIdentity() {
        PdfDirectRenderEngine.reset()
        val original = key(); val bitmap = Bitmap("old-page"); val view = DropHarness()
        view.install(bitmap, original); view.dispose()
        val variants = listOf(original.copy(canonicalPath = "/test/b.pdf"), original.copy(length = 101),
            original.copy(modified = 8), original.copy(pageIndex = 1), original.copy(requestedWidth = 702),
            original.copy(geometryId = "profile-b"), original.copy(profileStamp = original.profileStamp!!.copy(inode = 102)),
            original.copy(profileStamp = original.profileStamp!!.copy(device = 2)),
            original.copy(profileStamp = null), original.copy(geometryId = null))
        for (variant in variants) expect(PdfDirectRenderEngine.take(variant) == null, "Changed identity may not reuse old image: $variant")
        expect(PdfDirectRenderEngine.take(original)?.bitmap === bitmap, "No key reconstructed from changed live state")
        bitmap.recycle()
    }
    private fun boundedEviction() {
        PdfDirectRenderEngine.reset()
        val pages = (0..5).map { Bitmap("page$it") }
        for ((index, bitmap) in pages.withIndex()) {
            val view = DropHarness(); view.install(bitmap, key(index)); view.dispose()
            expect(PdfDirectRenderEngine.snapshot().size <= 4, "Cache bounded to four entries")
        }
        expect(pages[0].recycleCount == 1 && pages[1].recycleCount == 1, "Oldest entries evicted once")
        for (index in 2..5) {
            expect(!pages[index].isRecycled, "Retained entry remains live")
            expect(PdfDirectRenderEngine.take(key(index))?.bitmap === pages[index], "Retained exact page")
            pages[index].recycle()
        }
        expect(PdfDirectRenderEngine.snapshot().isEmpty(), "All taken owners leave LRU")
    }
    private fun conservativeRecycling() {
        PdfDirectRenderEngine.reset()
        val orphan = Bitmap("no-metadata"); val view = DropHarness(); view.install(orphan, null); view.dispose()
        expect(orphan.recycleCount == 1 && PdfDirectRenderEngine.snapshot().isEmpty(), "No invented key for orphan")
        val invalid = Bitmap("invalid-props"); val other = DropHarness(); other.install(invalid, key()); other.invalidProps()
        expect(invalid.recycleCount == 1 && PdfDirectRenderEngine.snapshot().isEmpty(), "Invalid prop recycling unchanged")
        val dead = Bitmap("already-recycled"); dead.recycle()
        PdfDirectRenderEngine.returnVisibleBitmap(key(), 10, dead, null)
        expect(PdfDirectRenderEngine.snapshot().isEmpty(), "Never cache an already-recycled background")
    }
    @JvmStatic fun main(args: Array<String>) {
        dropTransfersOnce(); overlappingSameKeyOwnership(); originalIdentity(); boundedEviction(); conservativeRecycling()
        println("PASS: $assertions actual Kotlin cache/drop assertions; Android/RN lifecycle not executed")
    }
}
'''


MUTATIONS = {
    "old-drop-recycling": ("        replaceBitmap(null, null)\n", "        replaceBitmap(null, null, cachePrevious = false)\n"),
    "take-retains-cache-owner": ("            bitmapCache.remove(key)\n", "            bitmapCache[key]\n"),
    "return-wrong-width": ("                    previousMetadata.key,", "                    previousMetadata.key.copy(requestedWidth = 702),"),
    "drop-retains-ink": ("        clearSavedInk()\n", "        // removed ink release\n"),
    "transfer-retains-view-owner": ("        pageBitmap = next\n", "        // removed ownership retirement\n"),
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, nargs="?", default=Path(__file__).resolve().parents[1])
    parser.add_argument("--jdk-home", type=Path, default=Path(os.environ.get("JAVA_HOME", "C:/Program Files/Java/jdk-17")))
    parser.add_argument("--gradle-cache", type=Path, default=Path.home() / ".gradle/caches/modules-2/files-2.1")
    parser.add_argument("--mutations", action="store_true")
    args = parser.parse_args()
    _, java = jdk_tools(args.jdk_home)
    jars, stdlib = compiler_jars(args.gradle_cache)
    production = actual_methods(args.root.resolve())
    variants = {"production": production}
    if args.mutations:
        for name, (before, after) in MUTATIONS.items():
            if production.count(before) != 1:
                raise AssertionError(f"Mutation boundary not unique: {name}")
            variants[name] = production.replace(before, after, 1)
    with tempfile.TemporaryDirectory(prefix="rtl-pdf-bitmap-ownership-") as folder:
        temp = Path(folder)
        # Exercise the real generated lifecycle patch, not a copied policy.
        root = args.root.resolve()
        canonical = (root / "native/PdfPageView.kt.template").read_text(encoding="utf-8")
        project = temp / "generated"
        generated = project / "android/app/src/main/java/test/PdfPageView.kt"
        generated.parent.mkdir(parents=True)
        generated.write_text(canonical.replace("package __PACKAGE__", "package test"), encoding="utf-8")
        subprocess.run([sys.executable, str(root / "scripts/patch_transient_detach.py"), str(project)],
                       check=True, timeout=15)
        patched = generated.read_text(encoding="utf-8")
        detached = patched[patched.index("    override fun onDetachedFromWindow() {"):]
        if "dispose()" in detached or "RTL_READER_NATIVE_VIEW_TRANSIENT_DETACH" not in detached:
            raise AssertionError("Generated transient detach must not dispose the view")
        for marker, end in (("    fun dispose() {", "    private fun clearSavedInk() {"),
                            ("    private fun replaceBitmap(", "    private fun emitRenderedAfterDraw(")):
            if section(patched, marker, end) != section(canonical, marker, end):
                raise AssertionError("Lifecycle patch changed permanent-drop ownership")
        print("PASS: actual generated transient-detach patch preserves permanent-drop methods", flush=True)
        for name, source in variants.items():
            trial = temp / name; trial.mkdir()
            input_file = trial / "Ownership.kt"; input_file.write_text(source, encoding="utf-8")
            classes = trial / "classes"; classes.mkdir()
            classpath = os.pathsep.join(map(str, [classes, stdlib, jars[-1]]))
            compiler = [str(java), "-Xmx512m", "-cp", os.pathsep.join(map(str, jars)),
                        "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect",
                        "-jvm-target", "1.8", "-classpath", classpath, "-d", str(classes), "-nowarn", str(input_file)]
            subprocess.run(compiler, check=True, timeout=60)
            result = subprocess.run([str(java), "-ea", "-cp", classpath, "PdfBitmapOwnershipTest"],
                                    text=True, capture_output=True, timeout=30)
            if name == "production":
                if result.returncode != 0:
                    raise AssertionError(result.stdout + result.stderr)
                print(result.stdout.strip(), flush=True)
            else:
                if result.returncode == 0 or "IllegalStateException" not in result.stderr:
                    raise AssertionError(f"Mutation did not fail an ownership assertion: {name}\n{result.stderr}")
                print(f"PASS: rejected {name}", flush=True)


if __name__ == "__main__":
    main()
