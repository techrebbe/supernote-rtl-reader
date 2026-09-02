#!/usr/bin/env python3
"""Strictly verify the installable RTL Reader package and embedded native APK."""

from __future__ import annotations

import io
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
import zlib
from pathlib import Path
from typing import Callable


EXPECTED_REACT_PACKAGES = ["com.supernotertlreader.PdfRendererPackage"]
EXPECTED_NATIVE_CLASSES = (
    b"ReaderPreferencesModule",
    b"PdfRendererPackage",
    b"PdfPageView",
)
MINIMUM_NATIVE_APK_SIZE = 1_000_000
EXPECTED_ANDROID_PACKAGE = "com.supernotertlreader"


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


def verify_dex(data: bytes, name: str) -> None:
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


def find_android_tool(tool: str) -> str:
    executable_names = [tool]
    if sys.platform.startswith("win"):
        # Android build-tools ships aapt as an .exe and apksigner as a .bat.
        executable_names = [f"{tool}.bat", f"{tool}.exe", tool]
    for executable in executable_names:
        from_path = shutil.which(executable)
        if from_path:
            return from_path
    roots = [
        value
        for key in ("ANDROID_SDK_ROOT", "ANDROID_HOME")
        if (value := __import__("os").environ.get(key))
    ]
    candidates: list[Path] = []
    for root in roots:
        build_tools = Path(root) / "build-tools"
        if build_tools.is_dir():
            for version in build_tools.iterdir():
                if not version.is_dir():
                    continue
                for executable in executable_names:
                    candidate = version / executable
                    if candidate.is_file():
                        candidates.append(candidate)
    if not candidates:
        fail(f"Android SDK tool {tool!r} is required for package verification")
    return str(sorted(candidates, key=lambda value: value.parent.name)[-1])


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
    package_match = re.search(r"^package: name='([^']+)'", badging.stdout, re.MULTILINE)
    if package_match is None or package_match.group(1) != EXPECTED_ANDROID_PACKAGE:
        fail("embedded app.npk has an unexpected Android package identity")
    signature = subprocess.run(
        [apksigner, "verify", "--verbose", "--print-certs", str(apk_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    signature_output = signature.stdout + signature.stderr
    if signature.returncode != 0 or "Number of signers: 1" not in signature_output:
        fail("embedded app.npk signature verification failed")
    if not re.search(
        r"Verified using v(?:2|3) scheme \(APK Signature Scheme v[23]\): true",
        signature_output,
    ):
        fail("embedded app.npk lacks a verified modern APK signature")


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
            verify_binary_manifest(native.read("AndroidManifest.xml"))
            dex_payloads = [native.read(name) for name in dex_names]
            for name, payload in zip(dex_names, dex_payloads):
                verify_dex(payload, name)
            for class_name in EXPECTED_NATIVE_CLASSES:
                if not any(class_name in payload for payload in dex_payloads):
                    fail(
                        "embedded app.npk is missing reviewed native class "
                        + class_name.decode("ascii")
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
            marker = expected_runtime_marker(repo_root)
            if marker not in bundle:
                fail(
                    "JavaScript bundle does not contain the reviewed runtime marker "
                    + marker.decode("ascii")
                )
            native_apk_validator(require_single_entry(package, "app.npk"))
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
