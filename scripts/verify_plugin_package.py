#!/usr/bin/env python3
"""Strictly verify the installable RTL Reader package and embedded native APK."""

from __future__ import annotations

import io
import hashlib
import hmac
import json
import re
import os
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib
from pathlib import Path
from typing import Callable


EXPECTED_REACT_PACKAGES = ["com.supernotertlreader.PdfRendererPackage"]
EXPECTED_NATIVE_CLASS_DESCRIPTORS = (
    b"Lcom/supernotertlreader/ReaderPreferencesModule;",
    b"Lcom/supernotertlreader/PdfRendererPackage;",
    b"Lcom/supernotertlreader/PdfPageView;",
)
MINIMUM_NATIVE_APK_SIZE = 1_000_000
EXPECTED_ANDROID_PACKAGE = "com.supernotertlreader"
EXPECTED_ANDROID_VERSION_CODE = "1"
EXPECTED_ANDROID_VERSION_NAME = "1.0"
EXPECTED_ANDROID_MIN_SDK = "27"
EXPECTED_ANDROID_TARGET_SDK = "35"
EXPECTED_ANDROID_APPLICATION = "com.supernotertlreader.MainApplication"
EXPECTED_ANDROID_ACTIVITY = "com.supernotertlreader.MainActivity"
EXPECTED_NATIVE_APK_SIGNER_SHA256 = (
    "fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c"
)


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


def verify_binary_manifest(data: bytes) -> None:
    if len(data) < 8:
        fail("embedded APK AndroidManifest.xml is truncated")
    chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, 0)
    if chunk_type != 0x0003 or header_size != 8 or chunk_size != len(data):
        fail("embedded APK AndroidManifest.xml is not compiled binary XML")
    offset = header_size
    saw_string_pool = False
    saw_start_element = False
    while offset < len(data):
        if offset + 8 > len(data):
            fail("embedded APK AndroidManifest.xml has a truncated chunk")
        child_type, child_header, child_size = struct.unpack_from(
            "<HHI", data, offset
        )
        if (
            child_header < 8
            or child_size < child_header
            or offset + child_size > len(data)
        ):
            fail("embedded APK AndroidManifest.xml has invalid chunk bounds")
        saw_string_pool |= child_type == 0x0001
        saw_start_element |= child_type == 0x0102
        offset += child_size
    if offset != len(data) or not saw_string_pool or not saw_start_element:
        fail("embedded APK AndroidManifest.xml lacks required XML structure")


def read_uleb128(data: bytes, offset: int, label: str) -> tuple[int, int]:
    value = 0
    for index in range(5):
        if offset >= len(data):
            fail(f"embedded APK {label} has a truncated ULEB128")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << (index * 7)
        if not byte & 0x80:
            return value, offset
    fail(f"embedded APK {label} has an oversized ULEB128")


def dex_string_bytes(data: bytes, offset: int, label: str) -> bytes:
    _, cursor = read_uleb128(data, offset, label)
    terminator = data.find(b"\0", cursor)
    if terminator < 0:
        fail(f"embedded APK {label} has an unterminated DEX string")
    return data[cursor:terminator]


def verify_dex(data: bytes, name: str) -> set[bytes]:
    if len(data) < 0x70 or not re.fullmatch(rb"dex\n0(?:35|37|38|39|40|41)\0", data[:8]):
        fail(f"embedded APK {name} has an invalid DEX header")
    expected_checksum = struct.unpack_from("<I", data, 8)[0]
    if expected_checksum != zlib.adler32(data[12:]) & 0xFFFFFFFF:
        fail(f"embedded APK {name} has an invalid DEX checksum")
    if data[12:32] != hashlib.sha1(data[32:]).digest():
        fail(f"embedded APK {name} has an invalid DEX signature")
    file_size, header_size, endian_tag = struct.unpack_from("<III", data, 32)
    if file_size != len(data) or header_size != 0x70 or endian_tag != 0x12345678:
        fail(f"embedded APK {name} has inconsistent DEX dimensions")
    map_offset = struct.unpack_from("<I", data, 52)[0]
    if map_offset < header_size or map_offset + 4 > len(data):
        fail(f"embedded APK {name} has an invalid DEX map offset")
    for count_offset in range(56, 104, 8):
        count, offset = struct.unpack_from("<II", data, count_offset)
        if count and (offset < header_size or offset >= len(data)):
            fail(f"embedded APK {name} has an out-of-bounds DEX section")
    data_size, data_offset = struct.unpack_from("<II", data, 104)
    if data_offset < header_size or data_offset + data_size != len(data):
        fail(f"embedded APK {name} has an invalid DEX data section")

    string_count, string_offset = struct.unpack_from("<II", data, 56)
    type_count, type_offset = struct.unpack_from("<II", data, 64)
    class_count, class_offset = struct.unpack_from("<II", data, 96)
    if string_count == 0 or type_count == 0 or class_count == 0:
        fail(f"embedded APK {name} lacks DEX strings, types, or class definitions")
    for count, offset, width, label in (
        (string_count, string_offset, 4, "string IDs"),
        (type_count, type_offset, 4, "type IDs"),
        (class_count, class_offset, 32, "class definitions"),
    ):
        if offset < header_size or count > (len(data) - offset) // width:
            fail(f"embedded APK {name} has invalid {label} bounds")

    string_offsets = struct.unpack_from(
        f"<{string_count}I", data, string_offset
    )
    type_string_indices = struct.unpack_from(
        f"<{type_count}I", data, type_offset
    )
    descriptors: list[bytes] = []
    for string_index in type_string_indices:
        if string_index >= string_count:
            fail(f"embedded APK {name} has an invalid type string index")
        string_data_offset = string_offsets[string_index]
        if string_data_offset < data_offset or string_data_offset >= len(data):
            fail(f"embedded APK {name} has an invalid string-data offset")
        descriptors.append(
            dex_string_bytes(data, string_data_offset, f"{name} type descriptor")
        )

    defined_classes: set[bytes] = set()
    for index in range(class_count):
        class_index = struct.unpack_from("<I", data, class_offset + index * 32)[0]
        if class_index >= len(descriptors):
            fail(f"embedded APK {name} has an invalid class type index")
        descriptor = descriptors[class_index]
        if not descriptor.startswith(b"L") or not descriptor.endswith(b";"):
            fail(f"embedded APK {name} has a non-class class descriptor")
        defined_classes.add(descriptor)
    return defined_classes


ANDROID_BUILD_TOOLS_VERSION = "35.0.0"


def find_android_tool(tool: str) -> str:
    executable_names = [tool]
    if sys.platform.startswith("win"):
        # Android build-tools ships aapt as an .exe and apksigner as a .bat.
        executable_names = [f"{tool}.bat", f"{tool}.exe", tool]
    for key in ("ANDROID_SDK_ROOT", "ANDROID_HOME"):
        root = os.environ.get(key)
        if not root:
            continue
        build_tools = Path(root) / "build-tools" / ANDROID_BUILD_TOOLS_VERSION
        for executable in executable_names:
            candidate = build_tools / executable
            if candidate.is_file():
                return str(candidate)
    fail(
        f"Android SDK build-tools {ANDROID_BUILD_TOOLS_VERSION} tool "
        f"{tool!r} is required for package verification"
    )


def verify_application_xmltree(output: str) -> None:
    lines = output.replace("\r\n", "\n").replace("\r", "\n").splitlines()
    applications: list[tuple[int, int]] = []
    for index, line in enumerate(lines):
        match = re.match(r"^(\s*)E: application(?:\s|$)", line)
        if match is not None:
            applications.append((index, len(match.group(1))))
    if len(applications) != 1:
        fail(
            "embedded app.npk manifest must contain exactly one application "
            f"element, found {len(applications)}"
        )
    start, indentation = applications[0]
    direct_names: list[str] = []
    for line in lines[start + 1 :]:
        stripped = line.lstrip(" ")
        current_indentation = len(line) - len(stripped)
        if current_indentation <= indentation:
            break
        if current_indentation != indentation + 2 or not stripped.startswith("A: "):
            continue
        match = re.match(r'A: android:name\([^)]*\)="([^"]+)"', stripped)
        if match is not None:
            direct_names.append(match.group(1))
    if direct_names != [EXPECTED_ANDROID_APPLICATION]:
        fail("embedded app.npk has an unexpected Android application class")


def verify_signer_output(output: str, return_code: int) -> None:
    normalized = output.replace("\r\n", "\n").replace("\r", "\n")
    signer_digests = re.findall(
        r"^[ \t]*Signer #[0-9]+ certificate SHA-256 digest:[ \t]*([0-9A-Fa-f:]+)[ \t]*$",
        normalized,
        re.MULTILINE,
    )
    normalized_signers = [
        value.replace(":", "").lower() for value in signer_digests
    ]
    if (
        return_code != 0
        or normalized_signers != [EXPECTED_NATIVE_APK_SIGNER_SHA256]
    ):
        evidence = ",".join(normalized_signers) if normalized_signers else "none"
        fail(
            "embedded app.npk signature verification failed "
            f"(returnCode={return_code}, certificateDigests={evidence})"
        )
    required_schemes = set(
        re.findall(
            r"^[ \t]*Verified using v([23]) scheme \(APK Signature Scheme v\1\):[ \t]*true[ \t]*$",
            normalized,
            re.MULTILINE,
        )
    )
    if required_schemes != {"2", "3"}:
        fail("embedded app.npk must have verified v2 and v3 APK signatures")


def verify_apk_tools(apk_path: Path) -> None:
    aapt = find_android_tool("aapt")
    apksigner = find_android_tool("apksigner")
    badging = subprocess.run(
        [aapt, "dump", "badging", str(apk_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if badging.returncode != 0:
        fail(f"embedded app.npk manifest validation failed: {badging.stderr.strip()}")
    package_match = re.search(
        r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'",
        badging.stdout,
        re.MULTILINE,
    )
    if package_match is None or package_match.groups() != (
        EXPECTED_ANDROID_PACKAGE,
        EXPECTED_ANDROID_VERSION_CODE,
        EXPECTED_ANDROID_VERSION_NAME,
    ):
        fail("embedded app.npk has an unexpected Android package identity")
    sdk_match = re.search(r"^sdkVersion:'([^']+)'$", badging.stdout, re.MULTILINE)
    target_match = re.search(
        r"^targetSdkVersion:'([^']+)'$", badging.stdout, re.MULTILINE
    )
    activity_match = re.search(
        r"^launchable-activity: name='([^']+)'", badging.stdout, re.MULTILINE
    )
    if (
        sdk_match is None
        or sdk_match.group(1) != EXPECTED_ANDROID_MIN_SDK
        or target_match is None
        or target_match.group(1) != EXPECTED_ANDROID_TARGET_SDK
        or activity_match is None
        or activity_match.group(1) != EXPECTED_ANDROID_ACTIVITY
    ):
        fail("embedded app.npk has unexpected SDK or activity provenance")
    xmltree = subprocess.run(
        [aapt, "dump", "xmltree", str(apk_path), "AndroidManifest.xml"],
        capture_output=True,
        text=True,
        check=False,
    )
    if xmltree.returncode != 0:
        fail(f"embedded app.npk XML-tree validation failed: {xmltree.stderr.strip()}")
    verify_application_xmltree(xmltree.stdout)
    signature = subprocess.run(
        [apksigner, "verify", "--verbose", "--print-certs", str(apk_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    verify_signer_output(signature.stdout + signature.stderr, signature.returncode)


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
            if len(native_names) != len(set(native_names)):
                fail("embedded app.npk contains duplicate entry names")
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
            verify_binary_manifest(native.read("AndroidManifest.xml"))
            defined_classes: set[bytes] = set()
            for name in dex_names:
                defined_classes.update(verify_dex(native.read(name), name))
            for descriptor in EXPECTED_NATIVE_CLASS_DESCRIPTORS:
                if descriptor not in defined_classes:
                    fail(
                        "embedded app.npk is missing reviewed native class descriptor "
                        + descriptor.decode("ascii")
                    )
    except zipfile.BadZipFile as error:
        fail(f"embedded app.npk is not a valid APK/ZIP: {error}")
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as temporary:
            temporary.write(data)
            temporary_name = temporary.name
        verify_apk_tools(Path(temporary_name))
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def verify(
    package_path: Path,
    repo_root: Path,
    expected_bundle: bytes | None = None,
    expected_native_apk: bytes | None = None,
    native_apk_validator: Callable[[bytes], None] = verify_native_apk,
) -> None:
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
            if expected_bundle is None or not hmac.compare_digest(
                hashlib.sha256(bundle).digest(),
                hashlib.sha256(expected_bundle).digest(),
            ):
                fail("JavaScript bundle does not match the independently named build output")
            marker = expected_runtime_marker(repo_root)
            if bundle.count(marker) != 1:
                fail(
                    "JavaScript bundle does not contain exactly one reviewed runtime marker "
                    + marker.decode("ascii")
                )
            if not bundle.startswith(b"var __BUNDLE_START_TIME__=") or not re.search(
                rb"__r\(\d+\);\s*__r\(\d+\);\s*$", bundle
            ):
                fail("JavaScript bundle lacks the reviewed Metro bundle structure")
            native_apk = require_single_entry(package, "app.npk")
            if expected_native_apk is None or not hmac.compare_digest(
                hashlib.sha256(native_apk).digest(),
                hashlib.sha256(expected_native_apk).digest(),
            ):
                fail("embedded app.npk does not match the independently named build output")
            native_apk_validator(native_apk)
    except zipfile.BadZipFile as error:
        fail(f"plugin package is not a valid ZIP archive: {error}")


def main() -> None:
    if len(sys.argv) != 5:
        fail(
            "usage: verify_plugin_package.py <package.snplg> <repo-root> "
            "<expected.bundle> <expected-app.npk>"
        )
    package_path = Path(sys.argv[1]).resolve()
    repo_root = Path(sys.argv[2]).resolve()
    if not package_path.is_file():
        fail(f"plugin package not found: {package_path}")
    expected_bundle_path = Path(sys.argv[3]).resolve()
    expected_native_apk_path = Path(sys.argv[4]).resolve()
    if not expected_bundle_path.is_file() or not expected_native_apk_path.is_file():
        fail("expected bundle/native APK provenance input is missing")
    verify(
        package_path,
        repo_root,
        expected_bundle_path.read_bytes(),
        expected_native_apk_path.read_bytes(),
    )
    print(f"Verified native RTL Reader package: {package_path}")


if __name__ == "__main__":
    main()
