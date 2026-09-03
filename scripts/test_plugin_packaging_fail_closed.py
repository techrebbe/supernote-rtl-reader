#!/usr/bin/env python3
"""Failure-injection tests for native plugin packaging and verification."""

from __future__ import annotations

import io
import hashlib
import json
import os
import struct
import sys
import tempfile
import warnings
import zipfile
import zlib
from pathlib import Path
from unittest.mock import patch

from patch_plugin_packager import (
    APK_COPY_FUNCTION_MARKER,
    STRICT_APK_RESIGNING,
    STRICT_APK_SELECTION,
    STRICT_NATIVE_BUILD,
    STRICT_PACKAGE,
    STRICT_PACKAGE_UPDATE,
    UPSTREAM_PACKAGE_SCAN,
    UPSTREAM_PACKAGE_UPDATE,
    UPSTREAM_APK_SELECTION,
    UPSTREAM_SOFT_NATIVE_BUILD,
    patch_text,
)
from verify_plugin_package import (
    ANDROID_BUILD_TOOLS_VERSION,
    EXPECTED_ANDROID_APPLICATION,
    EXPECTED_NATIVE_CLASS_DESCRIPTORS,
    EXPECTED_NATIVE_APK_SIGNER_SHA256,
    find_android_tool,
    verify,
    verify_application_xmltree,
    verify_dex,
    verify_signer_output,
)


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


def fixture_bundle(marker: str = RUNTIME_MARKER) -> bytes:
    return (
        "var __BUNDLE_START_TIME__=0;"
        f"console.log('RTL_READER_OPEN {marker}');\n"
        "__r(1);\n__r(0);"
    ).encode("ascii")


def fail(message: str) -> None:
    raise SystemExit(f"test_plugin_packaging_fail_closed.py: {message}")


def expect_failure(action, label: str) -> None:
    try:
        action()
    except SystemExit:
        return
    fail(f"invalid verifier evidence unexpectedly passed: {label}")


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


def fixture_dex(descriptors: tuple[bytes, ...]) -> bytes:
    header_size = 0x70
    string_offset = header_size
    type_offset = string_offset + len(descriptors) * 4
    class_offset = type_offset + len(descriptors) * 4
    data_offset = class_offset + len(descriptors) * 32
    strings = bytearray()
    string_offsets: list[int] = []
    for descriptor in descriptors:
        if len(descriptor) >= 0x80:
            fail("fixture descriptor is too long for one-byte ULEB128")
        string_offsets.append(data_offset + len(strings))
        strings.extend(bytes((len(descriptor),)) + descriptor + b"\0")
    map_offset = data_offset + len(strings)
    body = bytearray(map_offset + 4)
    body[:8] = b"dex\n035\0"
    struct.pack_into("<III", body, 32, len(body), header_size, 0x12345678)
    struct.pack_into("<I", body, 52, map_offset)
    struct.pack_into("<II", body, 56, len(descriptors), string_offset)
    struct.pack_into("<II", body, 64, len(descriptors), type_offset)
    struct.pack_into("<II", body, 96, len(descriptors), class_offset)
    struct.pack_into("<II", body, 104, len(body) - data_offset, data_offset)
    for index, offset in enumerate(string_offsets):
        struct.pack_into("<I", body, string_offset + index * 4, offset)
        struct.pack_into("<I", body, type_offset + index * 4, index)
        struct.pack_into("<I", body, class_offset + index * 32, index)
    body[data_offset : data_offset + len(strings)] = strings
    struct.pack_into("<I", body, map_offset, 0)
    body[12:32] = hashlib.sha1(body[32:]).digest()
    struct.pack_into("<I", body, 8, zlib.adler32(body[12:]) & 0xFFFFFFFF)
    return bytes(body)


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
        bundle = fixture_bundle()

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


def packaged_payload(package: Path, name: str, fallback: bytes) -> bytes:
    try:
        with zipfile.ZipFile(package) as archive:
            matches = [entry for entry in archive.infolist() if entry.filename == name]
            if len(matches) == 1:
                return archive.read(matches[0])
    except zipfile.BadZipFile:
        pass
    return fallback


def expect_rejected(
    package: Path,
    repo_root: Path,
    label: str,
    *,
    expected_bundle: bytes | None = None,
    expected_app: bytes | None = None,
) -> None:
    if expected_bundle is None:
        expected_bundle = packaged_payload(
            package,
            f"{PLUGIN_KEY}.bundle",
            fixture_bundle(),
        )
    if expected_app is None:
        expected_app = packaged_payload(package, "app.npk", native_apk())
    try:
        verify(package, repo_root, expected_bundle, expected_app)
    except SystemExit:
        return
    fail(f"invalid package unexpectedly passed: {label}")


def write_package(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def test_packager_patch() -> None:
    upstream = (
        "prefix\n"
        + APK_COPY_FUNCTION_MARKER
        + "copy body\n"
        + UPSTREAM_APK_SELECTION
        + "copy suffix\n"
        + UPSTREAM_PACKAGE_SCAN
        + "middle\n"
        + UPSTREAM_PACKAGE_UPDATE
        + "later\n"
        + UPSTREAM_SOFT_NATIVE_BUILD
        + "suffix\n"
    )
    patched = patch_text(upstream)
    if "\x01" in patched:
        fail("packager patch emitted a control character instead of a sed backreference")
    expected_signer_parser = (
        "certificate SHA-256 digest:[[:space:]]*([0-9A-Fa-f:]+)"
        "[[:space:]]*$/\\1/p'"
    )
    if expected_signer_parser not in patched:
        fail("packager patch did not preserve the signer parser backreference")
    for required in (
        STRICT_PACKAGE,
        STRICT_PACKAGE_UPDATE,
        STRICT_NATIVE_BUILD,
        STRICT_APK_RESIGNING,
        STRICT_APK_SELECTION,
    ):
        if patched.count(required) != 1:
            fail("packager patch did not publish one strict replacement")
    if UPSTREAM_SOFT_NATIVE_BUILD in patched:
        fail("packager patch retained the soft native-build fallback")
    for required in (
        'if ! build_android_apk "$project_root" "$gen_cfg"; then',
        'if ! copy_apk_and_update_config "$project_root" "$gen_dir" "$gen_cfg"; then',
        'write_color_output "Required RTL Reader native build was not selected" "Red"',
        'signed_apk="$(sign_compacted_apk "$project_root" "$apk_path")"',
        '"$apksigner" verify --verbose --print-certs "$signed"',
        'Final compacted APK signer is not the reviewed identity',
        '$sdk_root/build-tools/35.0.0',
        'Final compacted APK must contain exactly one signer digest',
        'for required_scheme in 2 3; do',
    ):
        if patched.count(required) != 1:
            fail(f"patched packager lacks strict executable guard: {required}")
    for required in ("normalized_verification_output", "signer_digests"):
        if required not in patched:
            fail(f"patched packager lacks normalized signer evidence: {required}")
    if "sort -V" in patched or "tail -n 1" in patched:
        fail("patched packager still discovers the newest Android build-tools")
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

        # Archive/config/bundle behavior is tested with an injected trusted APK
        # boundary. Production verification always uses the real structural,
        # manifest, DEX, and signature validator below.
        expected_app = native_apk()
        expected_bundle = fixture_bundle()
        write_package(
            package,
            package_bytes(app_npk=expected_app, bundle=expected_bundle),
        )
        verify(
            package,
            root,
            expected_bundle,
            expected_app,
            native_apk_validator=lambda _data: None,
        )

        expect_rejected(
            package,
            root,
            "bundle provenance mismatch",
            expected_bundle=expected_bundle + b"-different",
            expected_app=expected_app,
        )
        expect_rejected(
            package,
            root,
            "native APK provenance mismatch",
            expected_bundle=expected_bundle,
            expected_app=expected_app + b"-different",
        )

        write_package(package, package_bytes())
        expect_rejected(package, root, "padded fake APK")

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

        write_package(package, package_bytes(bundle=fixture_bundle("wrong-marker")))
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


def test_dex_class_descriptor_verification() -> None:
    dex = fixture_dex(EXPECTED_NATIVE_CLASS_DESCRIPTORS)
    if verify_dex(dex, "fixture.dex") != set(EXPECTED_NATIVE_CLASS_DESCRIPTORS):
        fail("DEX verifier did not return the defined class descriptors")

    decoy = (
        EXPECTED_NATIVE_CLASS_DESCRIPTORS[0],
        EXPECTED_NATIVE_CLASS_DESCRIPTORS[1],
        b"Lfixture/PdfPageViewDecoy;",
    )
    defined = verify_dex(fixture_dex(decoy), "decoy.dex")
    if EXPECTED_NATIVE_CLASS_DESCRIPTORS[2] in defined:
        fail("DEX verifier accepted a class-name substring as a descriptor")

    corrupt = bytearray(dex)
    class_offset = struct.unpack_from("<I", corrupt, 100)[0]
    struct.pack_into("<I", corrupt, class_offset, 0xFFFFFFFF)
    corrupt[12:32] = hashlib.sha1(corrupt[32:]).digest()
    struct.pack_into("<I", corrupt, 8, zlib.adler32(corrupt[12:]) & 0xFFFFFFFF)
    try:
        verify_dex(bytes(corrupt), "corrupt.dex")
    except SystemExit:
        pass
    else:
        fail("DEX verifier accepted an invalid class type index")


def test_manifest_and_signer_evidence() -> None:
    valid_xmltree = (
        "N: android=http://schemas.android.com/apk/res/android\n"
        "  E: manifest (line=1)\n"
        "    E: application (line=5)\n"
        f'      A: android:name(0x01010003)="{EXPECTED_ANDROID_APPLICATION}"\n'
        "      E: activity (line=6)\n"
        '        A: android:name(0x01010003)="fixture.Activity"\n'
    )
    verify_application_xmltree(valid_xmltree)
    expect_failure(
        lambda: verify_application_xmltree(
            valid_xmltree.replace(
                f'      A: android:name(0x01010003)="{EXPECTED_ANDROID_APPLICATION}"\n',
                "",
            ).replace(
                '        A: android:name(0x01010003)="fixture.Activity"',
                f'        A: android:name(0x01010003)="{EXPECTED_ANDROID_APPLICATION}"',
            )
        ),
        "application-class decoy in nested activity",
    )
    expect_failure(
        lambda: verify_application_xmltree(valid_xmltree + valid_xmltree),
        "duplicate application element",
    )

    colon_digest = ":".join(
        EXPECTED_NATIVE_APK_SIGNER_SHA256.upper()[index : index + 2]
        for index in range(0, 64, 2)
    )
    valid_signature = (
        "  Verified using v2 scheme (APK Signature Scheme v2): true  \r\n"
        "\tVerified using v3 scheme (APK Signature Scheme v3):\ttrue\r\n"
        "Number of signers: 1\r\n"
        f"  Signer #1 certificate SHA-256 digest: {colon_digest}  \r\n"
    )
    verify_signer_output(valid_signature, 0)
    verify_signer_output(
        valid_signature.replace("\r\n", "\n").replace(
            colon_digest, EXPECTED_NATIVE_APK_SIGNER_SHA256
        ),
        0,
    )
    expect_failure(
        lambda: verify_signer_output(
            valid_signature.replace(
                f"  Signer #1 certificate SHA-256 digest: {colon_digest}  \r\n",
                "",
            ),
            0,
        ),
        "missing signer digest",
    )
    expect_failure(
        lambda: verify_signer_output(
            valid_signature
            + f"Signer #2 certificate SHA-256 digest: {colon_digest}\n",
            0,
        ),
        "multiple signer digests",
    )
    expect_failure(
        lambda: verify_signer_output(
            valid_signature.replace(colon_digest, "0" * 64),
            0,
        ),
        "unexpected signer identity",
    )
    expect_failure(
        lambda: verify_signer_output(
            valid_signature.replace("v2): true", "v2): false"),
            0,
        ),
        "missing v2 signature scheme",
    )
    expect_failure(
        lambda: verify_signer_output(
            valid_signature.replace("v3):\ttrue", "v3):\tfalse"), 0
        ),
        "missing v3 signature scheme",
    )
    expect_failure(
        lambda: verify_signer_output(valid_signature, 1),
        "nonzero verifier result",
    )


def test_exact_android_build_tools_selection() -> None:
    if ANDROID_BUILD_TOOLS_VERSION != "35.0.0":
        fail("plugin verifier build-tools pin drifted")
    suffix = ".bat" if sys.platform.startswith("win") else ""
    with tempfile.TemporaryDirectory(prefix="rtl-reader-sdk-test-") as temp:
        sdk = Path(temp)
        pinned = sdk / "build-tools" / "35.0.0" / f"apksigner{suffix}"
        newer = sdk / "build-tools" / "99.0.0" / f"apksigner{suffix}"
        pinned.parent.mkdir(parents=True)
        newer.parent.mkdir(parents=True)
        pinned.write_text("fixture", encoding="utf-8")
        newer.write_text("fixture", encoding="utf-8")
        with patch.dict(
            os.environ,
            {"ANDROID_SDK_ROOT": str(sdk), "ANDROID_HOME": ""},
            clear=False,
        ):
            if Path(find_android_tool("apksigner")) != pinned:
                fail("plugin verifier selected unpinned Android build-tools")
            pinned.unlink()
            expect_failure(
                lambda: find_android_tool("apksigner"),
                "missing pinned build-tools despite newer installation",
            )


def main() -> None:
    test_packager_patch()
    test_package_verifier()
    test_dex_class_descriptor_verification()
    test_manifest_and_signer_evidence()
    test_exact_android_build_tools_selection()
    print("Native plugin packaging fail-closed tests: PASS")


if __name__ == "__main__":
    main()
