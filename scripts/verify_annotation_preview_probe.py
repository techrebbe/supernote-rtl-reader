#!/usr/bin/env python3
"""Reuse strict package/Dex/signature checks with isolated diagnostic identities."""
from pathlib import Path
import re
import sys
import verify_plugin_package as verifier


def verify(package: Path, repo: Path, bundle: Path, apk: Path) -> None:
    # Do not repin the normal reader verifier or its signer/version contracts.
    def runtime_marker(root: Path) -> bytes:
        matches = re.findall(r"RTL_READER_OPEN ([A-Za-z0-9._-]+)", (root / "index.js").read_text(encoding="utf-8"))
        if len(matches) != 1:
            raise SystemExit("Expected one diagnostic runtime marker")
        return matches[0].encode("ascii")
    overrides = {
        "EXPECTED_REACT_PACKAGES": ["com.supernotertlinkprobe.PdfRendererPackage"],
        "EXPECTED_NATIVE_CLASS_DESCRIPTORS": (
            b"Lcom/supernotertlinkprobe/AnnotationPreviewModule;",
            b"Lcom/supernotertlinkprobe/PdfRendererPackage;",
        ),
        "EXPECTED_ANDROID_PACKAGE": "com.supernotertlinkprobe",
        "EXPECTED_ANDROID_APPLICATION": "com.supernotertlinkprobe.MainApplication",
        "EXPECTED_ANDROID_ACTIVITY": "com.supernotertlinkprobe.MainActivity",
        "expected_runtime_marker": runtime_marker,
    }
    originals = {name: getattr(verifier, name) for name in overrides}
    try:
        for name, value in overrides.items():
            setattr(verifier, name, value)
        verifier.verify(package, repo / "probes/annotation-preview", bundle.read_bytes(), apk.read_bytes())
    finally:
        for name, value in originals.items():
            setattr(verifier, name, value)


if __name__ == "__main__":
    if len(sys.argv) != 5:
        raise SystemExit("usage: verify_annotation_preview_probe.py <snplg> <repo> <bundle> <apk>")
    verify(*(Path(argument).resolve() for argument in sys.argv[1:]))
