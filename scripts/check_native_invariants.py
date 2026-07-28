#!/usr/bin/env python3
"""Verify invariants of the canonical and generated native PDF page view."""

from __future__ import annotations

import re
import sys
from pathlib import Path


REQUIRED_MARKERS = (
    "private data class RenderKey(",
    "private data class VisibleBitmapMetadata(",
    "val key: RenderKey",
    "private val rendererLock = ReentrantLock()",
    "private val activePrefetch = ConcurrentHashMap.newKeySet<RenderKey>()",
    "private val foregroundDemand = AtomicInteger(0)",
    "rendererLock.tryLock(10L, TimeUnit.MILLISECONDS)",
    "isCurrent: () -> Boolean",
    "RTL_READER_NATIVE_VIEW_PREFETCH_SKIPPED",
    "RTL_READER_NATIVE_VIEW_VISIBLE_CACHED",
    "previousMetadata.key",
    "result.key",
    "activeLength == key.length",
    "activeModified == key.modified",
)

FORBIDDEN_MARKERS = (
    "ReentrantLock(true)",
    "previousMetadata.filePath",
    "previousMetadata.pageIndex",
    "previousMetadata.requestedWidth",
)


def fail(message: str) -> None:
    raise SystemExit(f"check_native_invariants.py: {message}")


def normalize_package(text: str) -> str:
    normalized, count = re.subn(
        r"(?m)^package\s+[A-Za-z0-9_.]+\s*$",
        "package __PACKAGE__",
        text,
        count=1,
    )
    if count != 1:
        fail("expected exactly one Kotlin package declaration")
    return normalized


def verify_source(text: str, label: str) -> None:
    missing = [marker for marker in REQUIRED_MARKERS if marker not in text]
    if missing:
        fail(f"{label} is missing required markers: {missing}")

    forbidden = [marker for marker in FORBIDDEN_MARKERS if marker in text]
    if forbidden:
        fail(f"{label} contains obsolete markers: {forbidden}")

    if text.count("val key: RenderKey") < 2:
        fail(f"{label} must preserve RenderKey in render and visible metadata")

    return_start = text.find("    fun returnVisibleBitmap(")
    make_key_start = text.find("    private fun makeKey(", return_start)
    if return_start < 0 or make_key_start < 0:
        fail(f"{label} is missing the visible-bitmap return/key boundary")
    return_block = text[return_start:make_key_start]
    if "makeKey(" in return_block:
        fail(f"{label} reconstructs file metadata when returning a visible bitmap")
    if "putCached(key," not in return_block:
        fail(f"{label} does not return visible bitmaps under their original key")

    render_key_match = re.search(
        r"private data class RenderKey\((.*?)\n\)",
        text,
        flags=re.DOTALL,
    )
    if not render_key_match:
        fail(f"{label} does not define RenderKey")
    render_key_body = render_key_match.group(1)
    for field in (
        "canonicalPath: String",
        "length: Long",
        "modified: Long",
        "pageIndex: Int",
        "requestedWidth: Int",
    ):
        if field not in render_key_body:
            fail(f"{label} RenderKey is missing {field}")


def check(repo_root: Path, generated_project: Path | None = None) -> None:
    canonical_path = repo_root / "native" / "PdfPageView.kt.template"
    canonical = canonical_path.read_text(encoding="utf-8")
    verify_source(canonical, "canonical PdfPageView template")

    if generated_project is not None:
        java_root = (
            generated_project
            / "android"
            / "app"
            / "src"
            / "main"
            / "java"
        )
        candidates = list(java_root.rglob("PdfPageView.kt"))
        if len(candidates) != 1:
            fail(f"expected one generated PdfPageView.kt, found {len(candidates)}")
        generated = candidates[0].read_text(encoding="utf-8")
        verify_source(generated, "generated PdfPageView")
        if normalize_package(generated) != canonical:
            fail("generated PdfPageView differs from the canonical template")

    print("Native PDF renderer invariants: PASS")


def main() -> None:
    if len(sys.argv) not in (2, 3):
        fail("usage: check_native_invariants.py <repo-root> [generated-project]")
    repo_root = Path(sys.argv[1]).resolve()
    generated_project = Path(sys.argv[2]).resolve() if len(sys.argv) == 3 else None
    check(repo_root, generated_project)


if __name__ == "__main__":
    main()
