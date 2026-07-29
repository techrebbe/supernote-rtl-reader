#!/usr/bin/env python3
"""Patch generated PdfPageView lifecycle for transient PluginHost detach/reattach.

React Native may temporarily detach the two native page views while constructing the
initial landscape spread. Disposal belongs to ViewManager.onDropViewInstance(), not
to every Android window detach. Preserve the queued render/bitmap across transient
detach and recommit valid props when the same view reattaches without a bitmap.
"""

from __future__ import annotations

import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"patch_transient_detach.py: {message}")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        fail(f"expected one {label}, found {count}")
    return text.replace(old, new, 1)


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: patch_transient_detach.py <generated-project>")

    project = Path(sys.argv[1]).resolve()
    candidates = list(
        (project / "android" / "app" / "src" / "main" / "java").rglob(
            "PdfPageView.kt"
        )
    )
    if len(candidates) != 1:
        fail(f"expected one generated PdfPageView.kt, found {len(candidates)}")

    path = candidates[0]
    text = path.read_text(encoding="utf-8")

    text = replace_once(
        text,
        '''override fun onAttachedToWindow() {
    super.onAttachedToWindow()
    requestBitmapRedraw("attached")
}''',
        '''override fun onAttachedToWindow() {
    super.onAttachedToWindow()
    val hasValidRequest =
        !pendingFilePath.isNullOrBlank() &&
            pendingPageIndex >= 0 &&
            pendingRequestedWidth > 0
    if (pageBitmap == null && hasValidRequest) {
        Log.i(
            "RTL_READER",
            "RTL_READER_NATIVE_VIEW_ATTACHED_RECOMMIT page=${pendingPageIndex + 1}",
        )
        committedSignature = null
        commitProps()
    } else {
        requestBitmapRedraw("attached")
    }
}''',
        "attached lifecycle block",
    )

    text = replace_once(
        text,
        '''    override fun onDetachedFromWindow() {
        dispose()
        super.onDetachedFromWindow()
    }''',
        '''    override fun onDetachedFromWindow() {
        Log.i(
            "RTL_READER",
            "RTL_READER_NATIVE_VIEW_TRANSIENT_DETACH page=${pendingPageIndex + 1} preserve=true",
        )
        super.onDetachedFromWindow()
    }''',
        "detached lifecycle block",
    )

    for marker in (
        "RTL_READER_NATIVE_VIEW_ATTACHED_RECOMMIT",
        "RTL_READER_NATIVE_VIEW_TRANSIENT_DETACH",
    ):
        if marker not in text:
            fail(f"generated source missing lifecycle marker: {marker}")

    if '''override fun onDetachedFromWindow() {
        dispose()''' in text:
        fail("generated source still disposes on transient detach")

    path.write_text(text, encoding="utf-8")
    print(f"Patched transient detach lifecycle in {path}")


if __name__ == "__main__":
    main()
