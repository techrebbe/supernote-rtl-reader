#!/usr/bin/env python3
"""Install RTL Reader native bridges into a generated React Native template."""

from __future__ import annotations

import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"install_native.py: {message}")


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
