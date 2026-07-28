#!/usr/bin/env python3
"""Run the v0.4.2 native installer with narrowly scoped strict patches.

The source template contains the same renderLocked call in foreground and prefetch code.
The v0.4.2 cancellation guard belongs only before the first (foreground) occurrence.
This wrapper also preserves each bitmap's original RenderKey when visible or stale
results are returned to the native LRU.
"""

from __future__ import annotations

import install_native


_original_replace_once = install_native.replace_once
_original_patch_visible_bitmap_reuse = install_native.patch_visible_bitmap_reuse


def _replace_once(text: str, old: str, new: str, label: str) -> str:
    if label == "pre-render cancellation":
        count = text.count(old)
        if count < 1:
            install_native.fail("expected a pre-render cancellation marker, found 0")
        return text.replace(old, new, 1)
    return _original_replace_once(text, old, new, label)


def _replace_count(text: str, old: str, new: str, expected: int, label: str) -> str:
    count = text.count(old)
    if count != expected:
        install_native.fail(f"expected {expected} {label} markers, found {count}")
    return text.replace(old, new)


def _patch_visible_bitmap_reuse(text: str) -> str:
    text = _original_patch_visible_bitmap_reuse(text)

    text = _replace_once(
        text,
        "private data class DirectRenderResult(\n"
        "    val bitmap: Bitmap,\n"
        "    val pageCount: Int,",
        "private data class DirectRenderResult(\n"
        "    val bitmap: Bitmap,\n"
        "    val key: RenderKey,\n"
        "    val pageCount: Int,",
        "render result key field",
    )

    text = _replace_once(
        text,
        "            val result = DirectRenderResult(\n"
        "                bitmap = bitmap,\n"
        "                pageCount = renderer.pageCount,",
        "            val result = DirectRenderResult(\n"
        "                bitmap = bitmap,\n"
        "                key = key,\n"
        "                pageCount = renderer.pageCount,",
        "rendered bitmap key assignment",
    )

    text = _replace_count(
        text,
        "                bitmap = cached.bitmap,\n"
        "                pageCount = cached.pageCount,",
        "                bitmap = cached.bitmap,\n"
        "                key = key,\n"
        "                pageCount = cached.pageCount,",
        2,
        "cached bitmap key assignment",
    )

    text = _replace_once(
        text,
        "private data class VisibleBitmapMetadata(\n"
        "    val filePath: String,\n"
        "    val pageIndex: Int,\n"
        "    val requestedWidth: Int,\n"
        "    val pageCount: Int,\n"
        ")",
        "private data class VisibleBitmapMetadata(\n"
        "    val key: RenderKey,\n"
        "    val pageCount: Int,\n"
        ")",
        "visible bitmap render key metadata",
    )

    text = _replace_once(
        text,
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
        "    }",
        "    fun returnVisibleBitmap(\n"
        "        key: RenderKey,\n"
        "        pageCount: Int,\n"
        "        bitmap: Bitmap,\n"
        "    ) {\n"
        "        if (bitmap.isRecycled) return\n"
        "        putCached(key, CachedBitmap(bitmap = bitmap, pageCount = pageCount))\n"
        "        Log.i(LOG_TAG, \"RTL_READER_NATIVE_VIEW_VISIBLE_CACHED page=${key.pageIndex + 1}\")\n"
        "    }",
        "visible bitmap exact-key return",
    )

    text = _replace_once(
        text,
        "                        PdfDirectRenderEngine.returnVisibleBitmap(\n"
        "                            filePath,\n"
        "                            pageIndex,\n"
        "                            requestedWidth,\n"
        "                            result.pageCount,\n"
        "                            result.bitmap,\n"
        "                        )",
        "                        PdfDirectRenderEngine.returnVisibleBitmap(\n"
        "                            result.key,\n"
        "                            result.pageCount,\n"
        "                            result.bitmap,\n"
        "                        )",
        "stale rendered bitmap exact-key return",
    )

    text = _replace_once(
        text,
        "                        VisibleBitmapMetadata(\n"
        "                            filePath = filePath,\n"
        "                            pageIndex = pageIndex,\n"
        "                            requestedWidth = requestedWidth,\n"
        "                            pageCount = result.pageCount,\n"
        "                        ),",
        "                        VisibleBitmapMetadata(\n"
        "                            key = result.key,\n"
        "                            pageCount = result.pageCount,\n"
        "                        ),",
        "visible bitmap exact-key metadata assignment",
    )

    text = _replace_once(
        text,
        "                PdfDirectRenderEngine.returnVisibleBitmap(\n"
        "                    previousMetadata.filePath,\n"
        "                    previousMetadata.pageIndex,\n"
        "                    previousMetadata.requestedWidth,\n"
        "                    previousMetadata.pageCount,\n"
        "                    previous,\n"
        "                )",
        "                PdfDirectRenderEngine.returnVisibleBitmap(\n"
        "                    previousMetadata.key,\n"
        "                    previousMetadata.pageCount,\n"
        "                    previous,\n"
        "                )",
        "previous visible bitmap exact-key return",
    )

    return text


install_native.replace_once = _replace_once
install_native.patch_visible_bitmap_reuse = _patch_visible_bitmap_reuse
install_native.main()
