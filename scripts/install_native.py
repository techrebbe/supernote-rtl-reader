#!/usr/bin/env python3
"""Install RTL Reader native bridges into a generated React Native template."""

from __future__ import annotations

import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"install_native.py: {message}")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        fail(f"expected one {label} marker, found {count}")
    return text.replace(old, new, 1)


def patch_app_prefetch_direction(path: Path) -> None:
    """Prefetch only the likely reading direction; recently displayed pages are cached natively."""

    text = path.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "      const prefetchPageIndexes = (movingForward\n"
        "        ? [forward, backward]\n"
        "        : [backward, forward]\n"
        "      ).filter(Number.isInteger);",
        "      const prefetchPageIndexes = [movingForward ? forward : backward].filter(\n"
        "        Number.isInteger,\n"
        "      );",
        "single direction-only prefetch",
    )
    text = replace_once(
        text,
        "    const prefetchPageIndexes = (movingForward\n"
        "      ? [...forwardCandidates, ...backwardCandidates]\n"
        "      : [...backwardCandidates, ...forwardCandidates]\n"
        "    ).filter((candidate, index, all) =>\n"
        "      !expected.includes(candidate) && all.indexOf(candidate) === index,\n"
        "    );",
        "    const prefetchPageIndexes = (movingForward\n"
        "      ? forwardCandidates\n"
        "      : backwardCandidates\n"
        "    ).filter((candidate, index, all) =>\n"
        "      !expected.includes(candidate) && all.indexOf(candidate) === index,\n"
        "    );",
        "spread direction-only prefetch",
    )
    path.write_text(text, encoding="utf-8")


def patch_prefetch_priority(text: str) -> str:
    """Keep bitmap prefetch from delaying foreground page turns."""

    text = replace_once(
        text,
        "import java.util.concurrent.atomic.AtomicLong\n",
        "import java.util.concurrent.atomic.AtomicInteger\n"
        "import java.util.concurrent.atomic.AtomicLong\n",
        "AtomicInteger import",
    )
    text = replace_once(
        text,
        "    private val rendererLock = ReentrantLock(true)\n",
        "    private val rendererLock = ReentrantLock()\n",
        "non-fair renderer lock",
    )
    text = replace_once(
        text,
        "    private val pendingPrefetch = ConcurrentHashMap.newKeySet<RenderKey>()\n"
        "    private val bitmapCache = LinkedHashMap<RenderKey, CachedBitmap>(8, 0.75f, true)\n",
        "    private val pendingPrefetch = ConcurrentHashMap.newKeySet<RenderKey>()\n"
        "    private val activePrefetch = ConcurrentHashMap.newKeySet<RenderKey>()\n"
        "    private val foregroundDemand = AtomicInteger(0)\n"
        "    private val bitmapCache = LinkedHashMap<RenderKey, CachedBitmap>(8, 0.75f, true)\n",
        "prefetch priority state",
    )
    text = replace_once(
        text,
        "        rendererLock.lock()\n"
        "        try {\n"
        "            takeCached(key)?.let { cached ->",
        "        // Cancel queued speculative work for this exact page before foreground waits.\n"
        "        // An already-running PdfRenderer page cannot be preempted, but no later prefetch\n"
        "        // may jump ahead of this foreground request.\n"
        "        pendingPrefetch.remove(key)\n"
        "        foregroundDemand.incrementAndGet()\n"
        "        rendererLock.lock()\n"
        "        try {\n"
        "            takeCached(key)?.let { cached ->",
        "foreground demand registration",
    )
    text = replace_once(
        text,
        "        } finally {\n"
        "            rendererLock.unlock()\n"
        "        }\n"
        "    }\n\n"
        "    fun schedulePrefetch(filePath: String, pageIndexes: List<Int>, requestedWidth: Int) {",
        "        } finally {\n"
        "            rendererLock.unlock()\n"
        "            foregroundDemand.decrementAndGet()\n"
        "        }\n"
        "    }\n\n"
        "    fun schedulePrefetch(filePath: String, pageIndexes: List<Int>, requestedWidth: Int) {",
        "foreground demand release",
    )

    old_prefetch = '''    fun schedulePrefetch(filePath: String, pageIndexes: List<Int>, requestedWidth: Int) {
        pageIndexes.distinct().filter { it >= 0 }.forEach { pageIndex ->
            val pair = try {
                makeKey(filePath, pageIndex, requestedWidth)
            } catch (_: Throwable) {
                return@forEach
            }
            val file = pair.first
            val key = pair.second
            if (hasCached(key) || !pendingPrefetch.add(key)) return@forEach

            prefetchExecutor.execute {
                try {
                    if (hasCached(key)) return@execute
                    val totalStarted = SystemClock.elapsedRealtime()
                    rendererLock.lock()
                    try {
                        if (hasCached(key)) return@execute
                        val result = renderLocked(file, key, totalStarted)
                        putCached(
                            key,
                            CachedBitmap(
                                bitmap = result.bitmap,
                                pageCount = result.pageCount,
                            ),
                        )
                        Log.i(
                            LOG_TAG,
                            "RTL_READER_NATIVE_VIEW_PREFETCH page=${pageIndex + 1} reused=${result.reusedRenderer} " +
                                "openMs=${result.openMs} renderMs=${result.renderMs} totalMs=${result.totalMs}",
                        )
                    } finally {
                        rendererLock.unlock()
                    }
                } catch (error: Throwable) {
                    Log.w(
                        LOG_TAG,
                        "RTL_READER_NATIVE_VIEW_PREFETCH_FAILED page=${pageIndex + 1}",
                        error,
                    )
                } finally {
                    pendingPrefetch.remove(key)
                }
            }
        }
    }'''

    new_prefetch = '''    fun schedulePrefetch(filePath: String, pageIndexes: List<Int>, requestedWidth: Int) {
        pageIndexes.distinct().filter { it >= 0 }.forEach { pageIndex ->
            val pair = try {
                makeKey(filePath, pageIndex, requestedWidth)
            } catch (_: Throwable) {
                return@forEach
            }
            val file = pair.first
            val key = pair.second
            if (
                hasCached(key) ||
                activePrefetch.contains(key) ||
                !pendingPrefetch.add(key)
            ) {
                return@forEach
            }

            prefetchExecutor.execute {
                // Claim this queued request. Foreground rendering cancels it by removing the key
                // before the task starts.
                if (!pendingPrefetch.remove(key)) return@execute
                if (!activePrefetch.add(key)) return@execute

                try {
                    if (hasCached(key) || foregroundDemand.get() > 0) {
                        Log.i(
                            LOG_TAG,
                            "RTL_READER_NATIVE_VIEW_PREFETCH_SKIPPED page=${pageIndex + 1} reason=foreground_or_cached",
                        )
                        return@execute
                    }

                    val totalStarted = SystemClock.elapsedRealtime()
                    if (!rendererLock.tryLock(10L, TimeUnit.MILLISECONDS)) {
                        Log.i(
                            LOG_TAG,
                            "RTL_READER_NATIVE_VIEW_PREFETCH_SKIPPED page=${pageIndex + 1} reason=renderer_busy",
                        )
                        return@execute
                    }

                    try {
                        if (hasCached(key) || foregroundDemand.get() > 0) {
                            Log.i(
                                LOG_TAG,
                                "RTL_READER_NATIVE_VIEW_PREFETCH_SKIPPED page=${pageIndex + 1} reason=foreground_after_lock",
                            )
                            return@execute
                        }

                        val result = renderLocked(file, key, totalStarted)
                        putCached(
                            key,
                            CachedBitmap(
                                bitmap = result.bitmap,
                                pageCount = result.pageCount,
                            ),
                        )
                        Log.i(
                            LOG_TAG,
                            "RTL_READER_NATIVE_VIEW_PREFETCH page=${pageIndex + 1} reused=${result.reusedRenderer} " +
                                "openMs=${result.openMs} renderMs=${result.renderMs} totalMs=${result.totalMs}",
                        )
                    } finally {
                        rendererLock.unlock()
                    }
                } catch (error: Throwable) {
                    Log.w(
                        LOG_TAG,
                        "RTL_READER_NATIVE_VIEW_PREFETCH_FAILED page=${pageIndex + 1}",
                        error,
                    )
                } finally {
                    activePrefetch.remove(key)
                }
            }
        }
    }'''

    return replace_once(text, old_prefetch, new_prefetch, "prefetch scheduler")


def patch_visible_bitmap_reuse(text: str) -> str:
    """Return pages leaving the screen to the native LRU and skip stale foreground work."""

    text = replace_once(
        text,
        "private data class PendingRenderedEvent(\n"
        "    val generation: Long,\n"
        "    val filePath: String,\n"
        "    val pageIndex: Int,\n"
        "    val requestedWidth: Int,\n"
        "    val prefetchPageIndexes: List<Int>,\n"
        "    val requestStartedAtMs: Double,\n"
        "    val result: DirectRenderResult,\n"
        ")\n\n"
        "private object PdfDirectRenderEngine {",
        "private data class PendingRenderedEvent(\n"
        "    val generation: Long,\n"
        "    val filePath: String,\n"
        "    val pageIndex: Int,\n"
        "    val requestedWidth: Int,\n"
        "    val prefetchPageIndexes: List<Int>,\n"
        "    val requestStartedAtMs: Double,\n"
        "    val result: DirectRenderResult,\n"
        ")\n\n"
        "private data class VisibleBitmapMetadata(\n"
        "    val filePath: String,\n"
        "    val pageIndex: Int,\n"
        "    val requestedWidth: Int,\n"
        "    val pageCount: Int,\n"
        ")\n\n"
        "private object PdfDirectRenderEngine {",
        "visible bitmap metadata",
    )

    text = replace_once(
        text,
        "    private fun makeKey(filePath: String, pageIndex: Int, requestedWidth: Int): Pair<File, RenderKey> {",
        "    fun returnVisibleBitmap(\n"
        "        filePath: String,\n"
        "        pageIndex: Int,\n"
        "        requestedWidth: Int,\n"
        "        pageCount: Int,\n"
        "        bitmap: Bitmap,\n"
        "    ) {\n"
        "        if (bitmap.isRecycled) return\n"
        "        val key = try {\n"
        "            makeKey(filePath, pageIndex, requestedWidth).second\n"
        "        } catch (_: Throwable) {\n"
        "            bitmap.recycle()\n"
        "            return\n"
        "        }\n"
        "        putCached(key, CachedBitmap(bitmap = bitmap, pageCount = pageCount))\n"
        "        Log.i(LOG_TAG, \"RTL_READER_NATIVE_VIEW_VISIBLE_CACHED page=${pageIndex + 1}\")\n"
        "    }\n\n"
        "    private fun makeKey(filePath: String, pageIndex: Int, requestedWidth: Int): Pair<File, RenderKey> {",
        "visible bitmap return",
    )

    text = replace_once(
        text,
        "    fun renderForeground(filePath: String, pageIndex: Int, requestedWidth: Int): DirectRenderResult {\n"
        "        val totalStarted = SystemClock.elapsedRealtime()\n"
        "        val (file, key) = makeKey(filePath, pageIndex, requestedWidth)\n",
        "    fun renderForeground(\n"
        "        filePath: String,\n"
        "        pageIndex: Int,\n"
        "        requestedWidth: Int,\n"
        "        isCurrent: () -> Boolean,\n"
        "    ): DirectRenderResult? {\n"
        "        val totalStarted = SystemClock.elapsedRealtime()\n"
        "        if (!isCurrent()) return null\n"
        "        val (file, key) = makeKey(filePath, pageIndex, requestedWidth)\n",
        "cancellable foreground signature",
    )

    text = replace_once(
        text,
        "        takeCached(key)?.let { cached ->\n"
        "            val totalMs = SystemClock.elapsedRealtime() - totalStarted",
        "        takeCached(key)?.let { cached ->\n"
        "            if (!isCurrent()) {\n"
        "                putCached(key, cached)\n"
        "                return null\n"
        "            }\n"
        "            val totalMs = SystemClock.elapsedRealtime() - totalStarted",
        "first cache cancellation",
    )
    text = replace_once(
        text,
        "        pendingPrefetch.remove(key)\n"
        "        foregroundDemand.incrementAndGet()",
        "        if (!isCurrent()) return null\n"
        "        pendingPrefetch.remove(key)\n"
        "        foregroundDemand.incrementAndGet()",
        "pre-lock cancellation",
    )
    text = replace_once(
        text,
        "        try {\n"
        "            takeCached(key)?.let { cached ->\n"
        "                val totalMs = SystemClock.elapsedRealtime() - totalStarted",
        "        try {\n"
        "            if (!isCurrent()) return null\n"
        "            takeCached(key)?.let { cached ->\n"
        "                if (!isCurrent()) {\n"
        "                    putCached(key, cached)\n"
        "                    return null\n"
        "                }\n"
        "                val totalMs = SystemClock.elapsedRealtime() - totalStarted",
        "post-lock cancellation",
    )
    text = replace_once(
        text,
        "            val result = renderLocked(file, key, totalStarted)",
        "            if (!isCurrent()) return null\n"
        "            val result = renderLocked(file, key, totalStarted)",
        "pre-render cancellation",
    )

    text = replace_once(
        text,
        "    private var pageBitmap: Bitmap? = null\n"
        "    private var pendingRenderedEvent: PendingRenderedEvent? = null",
        "    private var pageBitmap: Bitmap? = null\n"
        "    private var pageBitmapMetadata: VisibleBitmapMetadata? = null\n"
        "    private var pendingRenderedEvent: PendingRenderedEvent? = null",
        "visible metadata field",
    )

    text = replace_once(
        text,
        "                val result = PdfDirectRenderEngine.renderForeground(filePath, pageIndex, requestedWidth)\n"
        "                post {",
        "                val result = PdfDirectRenderEngine.renderForeground(\n"
        "                    filePath,\n"
        "                    pageIndex,\n"
        "                    requestedWidth,\n"
        "                ) { generation == renderGeneration.get() } ?: return@execute\n"
        "                post {",
        "foreground cancellation callback",
    )
    text = replace_once(
        text,
        "                    if (generation != renderGeneration.get()) {\n"
        "                        result.bitmap.recycle()\n"
        "                        return@post\n"
        "                    }\n\n"
        "                    replaceBitmap(result.bitmap)\n"
        "                    pendingRenderedEvent = PendingRenderedEvent(\n"
        "                        generation = generation,\n"
        "                        filePath = filePath,\n"
        "                        pageIndex = pageIndex,\n"
        "                        requestedWidth = requestedWidth,\n"
        "                        prefetchPageIndexes = prefetchPages,\n"
        "                        requestStartedAtMs = requestStartedAtMs,\n"
        "                        result = result,\n"
        "                    )",
        "                    if (generation != renderGeneration.get()) {\n"
        "                        PdfDirectRenderEngine.returnVisibleBitmap(\n"
        "                            filePath,\n"
        "                            pageIndex,\n"
        "                            requestedWidth,\n"
        "                            result.pageCount,\n"
        "                            result.bitmap,\n"
        "                        )\n"
        "                        return@post\n"
        "                    }\n\n"
        "                    val renderedEvent = PendingRenderedEvent(\n"
        "                        generation = generation,\n"
        "                        filePath = filePath,\n"
        "                        pageIndex = pageIndex,\n"
        "                        requestedWidth = requestedWidth,\n"
        "                        prefetchPageIndexes = prefetchPages,\n"
        "                        requestStartedAtMs = requestStartedAtMs,\n"
        "                        result = result,\n"
        "                    )\n"
        "                    replaceBitmap(\n"
        "                        result.bitmap,\n"
        "                        VisibleBitmapMetadata(\n"
        "                            filePath = filePath,\n"
        "                            pageIndex = pageIndex,\n"
        "                            requestedWidth = requestedWidth,\n"
        "                            pageCount = result.pageCount,\n"
        "                        ),\n"
        "                    )\n"
        "                    pendingRenderedEvent = renderedEvent",
        "visible bitmap handoff",
    )

    invalid_marker = "            replaceBitmap(null)\n            invalidate()"
    if text.count(invalid_marker) != 1:
        fail(f"expected one invalid-view bitmap marker, found {text.count(invalid_marker)}")
    text = text.replace(
        invalid_marker,
        "            replaceBitmap(null, null, cachePrevious = false)\n            invalidate()",
        1,
    )
    text = replace_once(
        text,
        "        replaceBitmap(null)\n"
        "    }\n\n"
        "    private fun replaceBitmap(next: Bitmap?) {\n"
        "        val previous = pageBitmap\n"
        "        pageBitmap = next\n"
        "        if (previous != null && previous !== next && !previous.isRecycled) {\n"
        "            previous.recycle()\n"
        "        }\n"
        "    }",
        "        replaceBitmap(null, null, cachePrevious = false)\n"
        "    }\n\n"
        "    private fun replaceBitmap(\n"
        "        next: Bitmap?,\n"
        "        nextMetadata: VisibleBitmapMetadata?,\n"
        "        cachePrevious: Boolean = true,\n"
        "    ) {\n"
        "        val previous = pageBitmap\n"
        "        val previousMetadata = pageBitmapMetadata\n"
        "        pageBitmap = next\n"
        "        pageBitmapMetadata = nextMetadata\n"
        "        if (previous != null && previous !== next && !previous.isRecycled) {\n"
        "            if (cachePrevious && previousMetadata != null) {\n"
        "                PdfDirectRenderEngine.returnVisibleBitmap(\n"
        "                    previousMetadata.filePath,\n"
        "                    previousMetadata.pageIndex,\n"
        "                    previousMetadata.requestedWidth,\n"
        "                    previousMetadata.pageCount,\n"
        "                    previous,\n"
        "                )\n"
        "            } else {\n"
        "                previous.recycle()\n"
        "            }\n"
        "        }\n"
        "    }",
        "bitmap replacement cache handoff",
    )

    return text


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: install_native.py <generated-project> <repo-root>")

    project = Path(sys.argv[1]).resolve()
    repo_root = Path(sys.argv[2]).resolve()
    java_root = project / "android" / "app" / "src" / "main" / "java"

    patch_app_prefetch_direction(project / "App.js")

    candidates = list(java_root.rglob("MainApplication.kt"))
    if len(candidates) != 1:
        fail(f"expected one MainApplication.kt, found {len(candidates)}")

    main_application = candidates[0]
    text = main_application.read_text(encoding="utf-8")
    match = re.search(r"(?m)^package\s+([A-Za-z0-9_.]+)\s*$", text)
    if not match:
        fail("could not determine Android package from MainApplication.kt")
    package_name = match.group(1)

    package_dir = java_root.joinpath(*package_name.split("."))
    package_dir.mkdir(parents=True, exist_ok=True)

    for source_name, output_name in (
        ("PdfRendererModule.kt.template", "PdfRendererModule.kt"),
        ("ReaderPreferencesModule.kt.template", "ReaderPreferencesModule.kt"),
        ("PdfPageView.kt.template", "PdfPageView.kt"),
        ("PdfPageViewManager.kt.template", "PdfPageViewManager.kt"),
        ("PdfRendererPackage.kt.template", "PdfRendererPackage.kt"),
    ):
        source = repo_root / "native" / source_name
        rendered = source.read_text(encoding="utf-8").replace("__PACKAGE__", package_name)
        if source_name == "PdfPageView.kt.template":
            rendered = patch_prefetch_priority(rendered)
            rendered = patch_visible_bitmap_reuse(rendered)
        (package_dir / output_name).write_text(rendered, encoding="utf-8")

    registration = "add(PdfRendererPackage())"
    if registration not in text:
        marker = "PackageList(this).packages.apply {"
        marker_index = text.find(marker)
        if marker_index < 0:
            fail("could not find PackageList(...).packages.apply block")

        insert_at = text.find("\n", marker_index)
        if insert_at < 0:
            fail("could not find insertion point in MainApplication.kt")

        line_start = text.rfind("\n", 0, marker_index) + 1
        indent = re.match(r"\s*", text[line_start:marker_index]).group(0)
        child_indent = indent + "  "
        text = (
            text[: insert_at + 1]
            + f"{child_indent}{registration}\n"
            + text[insert_at + 1 :]
        )
        main_application.write_text(text, encoding="utf-8")

    print(
        "Installed PdfRendererModule + ReaderPreferencesModule + PdfPageView "
        f"in Android package {package_name}"
    )
    print(f"Patched {main_application}")


if __name__ == "__main__":
    main()
