#!/usr/bin/env python3
"""One-time v0.4.3 source consolidation.

Run after the v0.4.2 installer has generated the tested Android source. The
script promotes that generated PdfPageView implementation to the canonical
repository template, replaces the layered installer with a small copy/register
installer, and removes the temporary v0.4.2 wrapper and this one-time workflow.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


SIMPLE_INSTALLER = r'''#!/usr/bin/env python3
"""Install RTL Reader's canonical native bridges into a generated RN project."""

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
        "Installed canonical PdfRendererModule + ReaderPreferencesModule + "
        f"PdfPageView in Android package {package_name}"
    )
    print(f"Patched {main_application}")


if __name__ == "__main__":
    main()
'''


def fail(message: str) -> None:
    raise SystemExit(f"canonicalize_v043.py: {message}")


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: canonicalize_v043.py <generated-project> <repo-root>")

    project = Path(sys.argv[1]).resolve()
    repo_root = Path(sys.argv[2]).resolve()

    generated_candidates = list(
        (project / "android" / "app" / "src" / "main" / "java").rglob(
            "PdfPageView.kt"
        )
    )
    if len(generated_candidates) != 1:
        fail(f"expected one generated PdfPageView.kt, found {len(generated_candidates)}")

    generated_text = generated_candidates[0].read_text(encoding="utf-8")
    canonical_text, replacements = re.subn(
        r"(?m)^package\s+[A-Za-z0-9_.]+\s*$",
        "package __PACKAGE__",
        generated_text,
        count=1,
    )
    if replacements != 1:
        fail("could not replace generated package declaration")

    required_markers = (
        "RTL_READER_NATIVE_VIEW_VISIBLE_CACHED",
        "RTL_READER_NATIVE_VIEW_PREFETCH_SKIPPED",
        "val key: RenderKey",
        "foregroundDemand",
        "isCurrent: () -> Boolean",
    )
    missing = [marker for marker in required_markers if marker not in canonical_text]
    if missing:
        fail(f"generated source is missing expected v0.4.2 markers: {missing}")

    (repo_root / "native" / "PdfPageView.kt.template").write_text(
        canonical_text,
        encoding="utf-8",
    )
    (repo_root / "scripts" / "install_native.py").write_text(
        SIMPLE_INSTALLER,
        encoding="utf-8",
    )

    build_path = repo_root / "build.sh"
    build_text = build_path.read_text(encoding="utf-8")
    old_call = 'python3 "$ROOT/scripts/install_native_v042.py" "$PROJECT" "$ROOT"'
    new_call = 'python3 "$ROOT/scripts/install_native.py" "$PROJECT" "$ROOT"'
    if build_text.count(old_call) != 1:
        fail("expected one v0.4.2 installer call in build.sh")
    build_path.write_text(build_text.replace(old_call, new_call, 1), encoding="utf-8")

    for obsolete in (
        repo_root / "scripts" / "install_native_v042.py",
        repo_root / "scripts" / "canonicalize_v043.py",
        repo_root / ".github" / "workflows" / "canonicalize-v043.yml",
    ):
        if obsolete.exists():
            obsolete.unlink()

    print("Promoted generated v0.4.2 PdfPageView to canonical native template")
    print("Simplified native installer and removed one-time wrapper/workflow")


if __name__ == "__main__":
    main()
