#!/usr/bin/env python3
"""Install only the diagnostic bridge/UI into a freshly pinned template project.

Generated build-tree copying/renaming only. Normal RTL sources/builds are untouched.
"""
from pathlib import Path
import shutil
import sys

PACKAGE = "com.supernotertlinkprobe"


def replace_once(path: Path, before: str, after: str) -> None:
    value = path.read_text(encoding="utf-8")
    if value.count(before) != 1:
        raise SystemExit(f"Expected one template marker {before!r} in {path}")
    path.write_text(value.replace(before, after, 1), encoding="utf-8")


def install(project: Path, repo: Path) -> None:
    java = project / "android/app/src/main/java"
    mains = list(java.rglob("MainApplication.kt"))
    activities = list(java.rglob("MainActivity.kt"))
    if len(mains) != 1 or len(activities) != 1:
        raise SystemExit("Expected exactly one template application/activity")
    for path in [*mains, *activities]:
        replace_once(path, "package com.supernotertlreader", f"package {PACKAGE}")
    replace_once(activities[0], '"SupernoteRtlReader"', '"SupernoteRtlInkProbe"')
    gradle = project / "android/app/build.gradle"
    replace_once(gradle, 'namespace "com.supernotertlreader"', f'namespace "{PACKAGE}"')
    replace_once(gradle, 'applicationId "com.supernotertlreader"', f'applicationId "{PACKAGE}"')
    replace_once(mains[0], "PackageList(this).packages.apply {", "PackageList(this).packages.apply {\n          add(PdfRendererPackage())")
    package_dir = java.joinpath(*PACKAGE.split("."))
    package_dir.mkdir(parents=True, exist_ok=True)
    for source, destination in (
        (repo / "native/AnnotationPreviewModule.kt.template", "AnnotationPreviewModule.kt"),
        (repo / "probes/annotation-preview/PdfRendererPackage.kt.template", "PdfRendererPackage.kt"),
    ):
        value = source.read_text(encoding="utf-8")
        if value.count("package __PACKAGE__") != 1:
            raise SystemExit(f"Invalid diagnostic template: {source}")
        (package_dir / destination).write_text(value.replace("__PACKAGE__", PACKAGE), encoding="utf-8")
    for name in ("App.js", "index.js", "app.json", "PluginConfig.json"):
        shutil.copyfile(repo / "probes/annotation-preview" / name, project / name)
    shutil.copyfile(repo / "overlay/annotationPreview.js", project / "annotationPreview.js")
    # Reuse the normal reviewed icon, not another generated asset source.
    import base64
    build = (repo / "build.sh").read_text(encoding="utf-8")
    begin = 'cat > "$PROJECT/assets/icon.png.b64" <<\'B64\'\n'
    if build.count(begin) != 1:
        raise SystemExit("Reviewed icon source marker changed")
    encoded = build.split(begin, 1)[1].split("\nB64", 1)[0]
    (project / "assets").mkdir(exist_ok=True)
    (project / "assets/icon.png").write_bytes(base64.b64decode(encoded, validate=True))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: install_annotation_preview_probe.py <fresh-template-project> <repo-root>")
    install(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
