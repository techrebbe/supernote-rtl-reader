#!/usr/bin/env python3
"""Prepare a fresh isolated probe build; invoke npm/template build only afterwards.

Reuses the frozen template lock and packager hardening without altering their
production defaults. The destination must not already exist.
"""
from pathlib import Path
import sys
import materialize_plugin_template as template
import patch_plugin_packager as packager
from install_annotation_preview_probe import install


def prepare(tarball: Path, repo: Path, destination: Path) -> None:
    template.materialize(tarball, repo / "provenance/plugin-template-package-lock.json.gz.b64", destination)
    install(destination, repo)
    strict = packager.STRICT_PACKAGE
    replacements = {
        "com.supernotertlreader.PdfRendererPackage": "com.supernotertlinkprobe.PdfRendererPackage",
        "android/app/src/main/java/com/supernotertlreader/PdfRendererPackage.kt":
            "android/app/src/main/java/com/supernotertlinkprobe/PdfRendererPackage.kt",
    }
    for old, new in replacements.items():
        if strict.count(old) != 1:
            raise SystemExit(f"Reviewed packager boundary changed: {old}")
        strict = strict.replace(old, new, 1)
    # MainApplication retains its original generated source location but its
    # Kotlin package, Gradle namespace/application ID and manifest class agree.
    original = packager.STRICT_PACKAGE
    try:
        packager.STRICT_PACKAGE = strict
        script = destination / "buildPlugin.sh"
        patched = packager.patch_text(script.read_text(encoding="utf-8"))
        # Preserve the pinned package.json and npm lock. The diagnostic bundle
        # and archive must instead match this isolated PluginConfig identity.
        naming = '    PACKAGE_NAME="$name"'
        if patched.count(naming) != 1:
            raise SystemExit("Reviewed packager naming boundary changed")
        patched = patched.replace(naming, '    PACKAGE_NAME="SupernoteRtlInkProbe"', 1)
        script.write_text(patched, encoding="utf-8")
    finally:
        packager.STRICT_PACKAGE = original
    print(f"Prepared isolated diagnostic build: {destination}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit("usage: build_annotation_preview_probe.py <pinned-template-tgz> <repo-root> <new-build-project>")
    prepare(*(Path(value).resolve() for value in sys.argv[1:]))
