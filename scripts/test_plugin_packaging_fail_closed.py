#!/usr/bin/env python3
"""Failure-injection tests for native plugin packaging and verification."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import warnings
import zipfile
from pathlib import Path

from patch_plugin_packager import (
    STRICT_NATIVE_BUILD,
    STRICT_PACKAGE,
    STRICT_PACKAGE_UPDATE,
    UPSTREAM_PACKAGE_SCAN,
    UPSTREAM_PACKAGE_UPDATE,
    UPSTREAM_SOFT_NATIVE_BUILD,
    patch_text,
)
from verify_plugin_package import verify


PLUGIN_KEY = "FixturePlugin"
RUNTIME_MARKER = "v9.9.9-fixture"
SOURCE_CONFIG = {
    "name": "Fixture",
    "pluginKey": PLUGIN_KEY,
    "pluginID": "fixture-native-plugin",
    "iconPath": "assets/icon.png",
    "desc": "fixture",
    "versionCode": "999",
    "versionName": "9.9.9",
    "jsMainPath": "index",
    "author": "test",
}


def fail(message: str) -> None:
    raise SystemExit(f"test_plugin_packaging_fail_closed.py: {message}")


def native_apk(*, include_classes: bool = True, padding: int = 1_000_100) -> bytes:
    output = io.BytesIO()
    dex = b"dex\n035\0"
    if include_classes:
        dex += b"ReaderPreferencesModule PdfRendererPackage PdfPageView"
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("AndroidManifest.xml", b"manifest")
        archive.writestr("lib/arm64-v8a/libnative-lib.so", b"native")
        archive.writestr("classes.dex", dex)
        archive.writestr("assets/padding.bin", b"x" * padding)
    return output.getvalue()


def package_bytes(
    *,
    config: dict[str, object] | None = None,
    app_npk: bytes | None = None,
    bundle: bytes | None = None,
    include_app: bool = True,
    extra_file: bool = False,
    duplicate_config: bool = False,
) -> bytes:
    packaged_config = dict(SOURCE_CONFIG)
    packaged_config["iconPath"] = "/icon.png"
    packaged_config["reactPackages"] = [
        "com.supernotertlreader.PdfRendererPackage"
    ]
    packaged_config["nativeCodePackage"] = "/app.npk"
    if config is not None:
        packaged_config = config
    if app_npk is None:
        app_npk = native_apk()
    if bundle is None:
        bundle = f"RTL_READER_OPEN {RUNTIME_MARKER}".encode("ascii")

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(
            "PluginConfig.json",
            json.dumps(packaged_config).encode("utf-8"),
        )
        if duplicate_config:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                archive.writestr(
                    "PluginConfig.json",
                    json.dumps(packaged_config).encode("utf-8"),
                )
        if include_app:
            archive.writestr("app.npk", app_npk)
        archive.writestr("icon.png", b"icon")
        archive.writestr(f"{PLUGIN_KEY}.bundle", bundle)
        archive.writestr("drawable-mdpi/assets_icon.png", b"icon")
        if extra_file:
            archive.writestr("unexpected.bin", b"unexpected")
    return output.getvalue()


def expect_rejected(package: Path, repo_root: Path, label: str) -> None:
    try:
        verify(package, repo_root)
    except SystemExit:
        return
    fail(f"invalid package unexpectedly passed: {label}")


def write_package(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def test_packager_patch() -> None:
    upstream = (
        "prefix\n"
        + UPSTREAM_PACKAGE_SCAN
        + "middle\n"
        + UPSTREAM_PACKAGE_UPDATE
        + "later\n"
        + UPSTREAM_SOFT_NATIVE_BUILD
        + "suffix\n"
    )
    patched = patch_text(upstream)
    for required in (
        STRICT_PACKAGE,
        STRICT_PACKAGE_UPDATE,
        STRICT_NATIVE_BUILD,
    ):
        if patched.count(required) != 1:
            fail("packager patch did not publish one strict replacement")
    if UPSTREAM_SOFT_NATIVE_BUILD in patched:
        fail("packager patch retained the soft native-build fallback")
    for required in (
        'if ! build_android_apk "$project_root" "$gen_cfg"; then',
        'if ! copy_apk_and_update_config "$project_root" "$gen_dir" "$gen_cfg"; then',
        'write_color_output "Required RTL Reader native build was not selected" "Red"',
    ):
        if patched.count(required) != 1:
            fail(f"patched packager lacks strict executable guard: {required}")
    if (
        'copy_apk_and_update_config "$project_root" "$gen_dir" "$gen_cfg" || true'
        in patched
    ):
        fail("patched packager still ignores native APK copy failure")
    try:
        patch_text(upstream.replace(UPSTREAM_PACKAGE_SCAN, "", 1))
    except SystemExit:
        pass
    else:
        fail("packager patch accepted a drifted upstream script")


def test_package_verifier() -> None:
    with tempfile.TemporaryDirectory(prefix="rtl-reader-package-test-") as temp:
        root = Path(temp)
        (root / "overlay").mkdir()
        (root / "PluginConfig.json").write_text(
            json.dumps(SOURCE_CONFIG),
            encoding="utf-8",
        )
        (root / "overlay" / "index.js").write_text(
            f"console.log('RTL_READER_OPEN {RUNTIME_MARKER}');\n",
            encoding="utf-8",
        )
        package = root / "fixture.snplg"

        write_package(package, package_bytes())
        verify(package, root)

        write_package(package, package_bytes(include_app=False))
        expect_rejected(package, root, "missing app.npk")

        bad_config = dict(SOURCE_CONFIG)
        bad_config["iconPath"] = "/icon.png"
        bad_config["reactPackages"] = [
            "com.supernotertlreader.PdfRendererPackage"
        ]
        bad_config["nativeCodePackage"] = "C:/app.npk"
        write_package(package, package_bytes(config=bad_config))
        expect_rejected(package, root, "converted nativeCodePackage path")

        write_package(package, package_bytes(extra_file=True))
        expect_rejected(package, root, "unexpected archive payload")

        write_package(package, package_bytes(bundle=b"wrong marker"))
        expect_rejected(package, root, "wrong runtime marker")

        write_package(
            package,
            package_bytes(app_npk=native_apk(include_classes=False)),
        )
        expect_rejected(package, root, "missing reviewed native classes")

        write_package(package, package_bytes(app_npk=b"not an apk"))
        expect_rejected(package, root, "invalid embedded APK")

        write_package(package, package_bytes(duplicate_config=True))
        expect_rejected(package, root, "duplicate PluginConfig.json")


def main() -> None:
    test_packager_patch()
    test_package_verifier()
    print("Native plugin packaging fail-closed tests: PASS")


if __name__ == "__main__":
    main()
