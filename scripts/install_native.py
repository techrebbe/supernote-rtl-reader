#!/usr/bin/env python3
"""Install RTL Reader's canonical native bridges into a generated RN project."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from check_native_invariants import check


def fail(message: str) -> None:
    raise SystemExit(f"install_native.py: {message}")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        fail(f"expected one {label} marker, found {count}")
    return text.replace(old, new, 1)


def patch_app_prefetch_direction(path: Path) -> None:
    """Prefetch only the likely direction; visible pages supply reverse cache."""

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
        (
            "NativeReaderV2AuthorityJournal.kt.template",
            "NativeReaderV2AuthorityJournal.kt",
        ),
        ("PdfPageView.kt.template", "PdfPageView.kt"),
        ("PdfPageViewManager.kt.template", "PdfPageViewManager.kt"),
        ("PdfRendererPackage.kt.template", "PdfRendererPackage.kt"),
    ):
        source = repo_root / "native" / source_name
        rendered = source.read_text(encoding="utf-8").replace("__PACKAGE__", package_name)
        if source_name == "PdfPageView.kt.template":
            for marker in (
                "override fun onSizeChanged",
                "override fun onAttachedToWindow",
                "RTL_READER_NATIVE_VIEW_SIZE_REDRAW",
            ):
                if marker not in rendered:
                    fail(f"canonical PdfPageView missing lifecycle marker: {marker}")
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

    check(repo_root, project)

    print(
        "Installed canonical PdfRendererModule + ReaderPreferencesModule + "
        f"PdfPageView in Android package {package_name}"
    )
    print(f"Patched {main_application}")


if __name__ == "__main__":
    main()
