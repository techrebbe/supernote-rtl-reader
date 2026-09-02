#!/usr/bin/env python3
"""Deterministic tests for locked template inputs and APK normalization."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import sys
import tempfile
import warnings
import zipfile
from pathlib import Path

from materialize_plugin_template import (
    EXPECTED_LOCK_SHA256,
    read_and_validate_lock,
    verify_template,
)
from normalize_apk_zip import CANONICAL_TIMESTAMP, normalize


def fail(message: str) -> None:
    raise SystemExit(f"test_build_provenance.py: {message}")


def expect_failure(action, label: str) -> None:
    try:
        action()
    except SystemExit:
        return
    fail(f"invalid provenance input unexpectedly passed: {label}")


def locked_package_json(lock: dict[str, object]) -> bytes:
    packages = lock["packages"]
    if not isinstance(packages, dict) or not isinstance(packages.get(""), dict):
        fail("test lock lacks a root package")
    root = packages[""]
    return json.dumps(
        {
            key: root[key]
            for key in (
                "name",
                "version",
                "dependencies",
                "devDependencies",
                "engines",
            )
        }
    ).encode("utf-8")


def test_locked_dependencies(repo_root: Path, temp_root: Path) -> None:
    source = repo_root / "provenance" / "plugin-template-package-lock.json.gz.b64"
    encoded = "".join(source.read_text(encoding="ascii").split())
    lock_bytes = gzip.decompress(base64.b64decode(encoded, validate=True))
    if hashlib.sha256(lock_bytes).hexdigest() != EXPECTED_LOCK_SHA256:
        fail("committed package lock has an unexpected SHA-256")
    lock = json.loads(lock_bytes.decode("utf-8"))
    package_json = locked_package_json(lock)
    if read_and_validate_lock(source, package_json) != lock_bytes:
        fail("valid locked dependency graph changed during validation")
    packages = lock["packages"]
    if packages["node_modules/react-native"]["version"] != "0.79.2":
        fail("React Native is not locked to 0.79.2")
    if packages["node_modules/@react-native-community/cli"]["version"] != "18.0.0":
        fail("React Native CLI is not locked to 18.0.0")
    if packages["node_modules/sn-plugin-lib"]["version"] != "0.1.43":
        fail("Supernote plugin library is not locked to the reviewed version")

    mutated = bytearray(lock_bytes)
    mutated[-2] ^= 1
    mutated_input = temp_root / "mutated-lock.gz.b64"
    mutated_input.write_text(
        base64.b64encode(gzip.compress(bytes(mutated))).decode("ascii"),
        encoding="ascii",
    )
    expect_failure(
        lambda: read_and_validate_lock(mutated_input, package_json),
        "mutated package lock",
    )


def make_zip(path: Path, order: list[str], timestamp: tuple[int, ...]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in order:
            info = zipfile.ZipInfo(name, timestamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, (name + "\n").encode("ascii") * 5)


def test_zip_normalization(temp_root: Path) -> None:
    first = temp_root / "first.zip"
    second = temp_root / "second.zip"
    first_output = temp_root / "first-normalized.zip"
    second_output = temp_root / "second-normalized.zip"
    make_zip(first, ["z.txt", "a.txt", "middle.bin"], (2026, 8, 1, 2, 4, 6))
    make_zip(second, ["middle.bin", "a.txt", "z.txt"], (2025, 2, 3, 4, 6, 8))
    normalize(first, first_output)
    normalize(second, second_output)
    if first_output.read_bytes() != second_output.read_bytes():
        fail("canonical ZIP output depends on input order or timestamps")
    with zipfile.ZipFile(first_output) as archive:
        names = [entry.filename for entry in archive.infolist()]
        if names != sorted(names):
            fail("canonical ZIP entries are not sorted")
        for entry in archive.infolist():
            if entry.date_time != CANONICAL_TIMESTAMP:
                fail("canonical ZIP retained a variable timestamp")
            if entry.compress_type != zipfile.ZIP_STORED:
                fail("canonical ZIP retained compressor-dependent bytes")

    duplicate = temp_root / "duplicate.zip"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(duplicate, "w") as archive:
            archive.writestr("same", b"one")
            archive.writestr("same", b"two")
    expect_failure(
        lambda: normalize(duplicate, temp_root / "duplicate-output.zip"),
        "duplicate ZIP entry",
    )

    unsafe = temp_root / "unsafe.zip"
    with zipfile.ZipFile(unsafe, "w") as archive:
        archive.writestr("../outside", b"not allowed")
    expect_failure(
        lambda: normalize(unsafe, temp_root / "unsafe-output.zip"),
        "unsafe ZIP entry",
    )


def test_template_digest_failure(temp_root: Path) -> None:
    fake = temp_root / "template.tgz"
    fake.write_bytes(b"not the reviewed template")
    expect_failure(lambda: verify_template(fake), "unreviewed template tarball")


def main() -> None:
    repo_root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    with tempfile.TemporaryDirectory(prefix="rtl-reader-provenance-") as temp:
        temp_root = Path(temp)
        test_locked_dependencies(repo_root, temp_root)
        test_zip_normalization(temp_root)
        test_template_digest_failure(temp_root)
    print("Build provenance and deterministic ZIP tests: PASS")


if __name__ == "__main__":
    main()
