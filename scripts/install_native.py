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


def patch_prefetch_priority(text: str) -> str:
    """Keep v0.4 bitmap prefetch from delaying foreground page turns."""

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


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: install_native.py <generated-project> <repo-root>")

    project = Path(sys.argv[1]).resolve()
    repo_root = Path(sys.argv[2]).resolve()
    java_root = project / "android" / "app" / "src" / "main" / "java"

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
