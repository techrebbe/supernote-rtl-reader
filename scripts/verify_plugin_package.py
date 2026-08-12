#!/usr/bin/env python3
"""Strictly verify the installable RTL Reader package and embedded native APK."""

from __future__ import annotations

import io
import json
import re
import sys
import zipfile
from pathlib import Path


EXPECTED_REACT_PACKAGES = ["com.supernotertlreader.PdfRendererPackage"]
EXPECTED_NATIVE_CLASSES = (
    b"ReaderPreferencesModule",
    b"PdfRendererPackage",
    b"PdfPageView",
)
MINIMUM_NATIVE_APK_SIZE = 1_000_000


def fail(message: str) -> None:
    raise SystemExit(f"verify_plugin_package.py: {message}")


def require_single_entry(archive: zipfile.ZipFile, name: str) -> bytes:
    matches = [info for info in archive.infolist() if info.filename == name]
    if len(matches) != 1:
        fail(f"expected exactly one {name!r} archive entry, found {len(matches)}")
    if matches[0].is_dir():
        fail(f"required archive entry {name!r} is a directory")
    return archive.read(matches[0])


def read_json(data: bytes, label: str) -> dict[str, object]:
    try:
        value = json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not valid UTF-8 JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must contain a JSON object")
    return value


def expected_runtime_marker(repo_root: Path) -> bytes:
    index_text = (repo_root / "overlay" / "index.js").read_text(encoding="utf-8")
    matches = re.findall(r"RTL_READER_OPEN ([A-Za-z0-9._-]+)", index_text)
    if len(matches) != 1:
        fail(
            "overlay/index.js must contain exactly one literal RTL_READER_OPEN "
            f"runtime marker, found {len(matches)}"
        )
    return matches[0].encode("ascii")


def verify_native_apk(data: bytes) -> None:
    if len(data) < MINIMUM_NATIVE_APK_SIZE:
        fail(
            "embedded app.npk is implausibly small for the RTL Reader native "
            f"runtime: {len(data)} bytes"
        )
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as native:
            corrupt = native.testzip()
            if corrupt is not None:
                fail(f"embedded app.npk has a corrupt entry: {corrupt}")
            native_names = native.namelist()
            for required in (
                "AndroidManifest.xml",
                "lib/arm64-v8a/libnative-lib.so",
            ):
                if native_names.count(required) != 1:
                    fail(
                        f"embedded app.npk must contain exactly one {required!r}"
                    )
            dex_names = sorted(
                name
                for name in native_names
                if re.fullmatch(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex", name)
            )
            if not dex_names:
                fail("embedded app.npk does not contain Android bytecode")
            dex_payloads = [native.read(name) for name in dex_names]
            for class_name in EXPECTED_NATIVE_CLASSES:
                if not any(class_name in payload for payload in dex_payloads):
                    fail(
                        "embedded app.npk is missing reviewed native class "
                        + class_name.decode("ascii")
                    )
    except zipfile.BadZipFile as error:
        fail(f"embedded app.npk is not a valid APK/ZIP: {error}")


def verify(package_path: Path, repo_root: Path) -> None:
    source_config = read_json(
        (repo_root / "PluginConfig.json").read_bytes(),
        "source PluginConfig.json",
    )
    plugin_key = source_config.get("pluginKey")
    if not isinstance(plugin_key, str) or not plugin_key:
        fail("source PluginConfig.json has no valid pluginKey")
    bundle_name = f"{plugin_key}.bundle"
    expected_files = {
        "PluginConfig.json",
        "app.npk",
        "icon.png",
        bundle_name,
        "drawable-mdpi/assets_icon.png",
    }

    try:
        with zipfile.ZipFile(package_path) as package:
            corrupt = package.testzip()
            if corrupt is not None:
                fail(f"plugin archive has a corrupt entry: {corrupt}")
            file_names = [info.filename for info in package.infolist() if not info.is_dir()]
            if len(file_names) != len(set(file_names)):
                fail("plugin archive contains duplicate file names")
            if set(file_names) != expected_files:
                missing = sorted(expected_files - set(file_names))
                unexpected = sorted(set(file_names) - expected_files)
                fail(
                    "plugin archive payload does not match the reviewed layout; "
                    f"missing={missing}, unexpected={unexpected}"
                )

            packaged_config = read_json(
                require_single_entry(package, "PluginConfig.json"),
                "packaged PluginConfig.json",
            )
            expected_config = dict(source_config)
            expected_config["iconPath"] = "/icon.png"
            expected_config["reactPackages"] = EXPECTED_REACT_PACKAGES
            expected_config["nativeCodePackage"] = "/app.npk"
            if packaged_config != expected_config:
                fail(
                    "packaged PluginConfig.json differs from the reviewed source "
                    "plus the exact native-package fields"
                )

            bundle = require_single_entry(package, bundle_name)
            marker = expected_runtime_marker(repo_root)
            if marker not in bundle:
                fail(
                    "JavaScript bundle does not contain the reviewed runtime marker "
                    + marker.decode("ascii")
                )
            verify_native_apk(require_single_entry(package, "app.npk"))
    except zipfile.BadZipFile as error:
        fail(f"plugin package is not a valid ZIP archive: {error}")


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: verify_plugin_package.py <package.snplg> <repo-root>")
    package_path = Path(sys.argv[1]).resolve()
    repo_root = Path(sys.argv[2]).resolve()
    if not package_path.is_file():
        fail(f"plugin package not found: {package_path}")
    verify(package_path, repo_root)
    print(f"Verified native RTL Reader package: {package_path}")


if __name__ == "__main__":
    main()
