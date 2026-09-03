#!/usr/bin/env python3
"""Deterministic tests for locked template inputs and APK normalization."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import re
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

EXPECTED_NATIVE_READER_SIGNING_JOB_SHA256 = (
    "2f09cc1784d04641d2a070c5993039b2d2cc0df2896a4eacddff769da7429b64"
)


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


def workflow_job(workflow: str, job_name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job_name)}:\n.*?(?=^  [a-z0-9][a-z0-9-]*:\n|\Z)",
        workflow,
    )
    if match is None:
        fail(f"workflow lacks expected job: {job_name}")
    return match.group(0)


def validate_native_reader_signing_isolation(workflow: str) -> None:
    unsigned_job = workflow_job(workflow, "native-spread-build")
    signing_job = workflow_job(workflow, "native-spread-upgrade-artifact")

    signing_job_sha256 = hashlib.sha256(signing_job.encode("utf-8")).hexdigest()
    if signing_job_sha256 != EXPECTED_NATIVE_READER_SIGNING_JOB_SHA256:
        fail(
            "protected Native Reader signing job differs from the exact audited "
            "inline-command boundary"
        )

    if "-AlignedOnly" not in unsigned_job:
        fail("Native Reader release input is not assembled as unsigned/aligned only")
    for required in (
        "provenance.json",
        "artifactSha256",
        "sourceCommit = '${{ github.sha }}'",
        "native-reader-v2-release-input-${{ github.sha }}",
    ):
        if required not in unsigned_job:
            fail(f"unsigned Native Reader job lacks release evidence: {required}")
    if "secrets." in unsigned_job or "NATIVE_SPREAD_KEYSTORE_B64" in unsigned_job:
        fail("repository-controlled Native Reader build receives a signing secret")
    if "NATIVE_SPREAD_KEYSTORE_B64" in workflow.replace(signing_job, ""):
        fail("Native Reader signing secret is referenced outside the protected signer")

    if "environment: virtual-spread-release" not in signing_job:
        fail("Native Reader signing job is not protected by its release environment")
    if (
        "NATIVE_SPREAD_KEYSTORE_B64 must exist only as an environment" not in signing_job
        or "never as a repository-scoped secret" not in signing_job
    ):
        fail("workflow does not require environment-only Native Reader credentials")
    if "actions/checkout@" in signing_job:
        fail("secret-bearing Native Reader signing job checks out repository code")
    for forbidden in (
        "native-spread-module",
        "scripts/",
        "scripts\\",
        ".ps1",
        ".py",
        "GITHUB_ENV",
    ):
        if forbidden in signing_job:
            fail(
                "secret-bearing Native Reader signing job can invoke repository "
                f"state: {forbidden}"
            )
    for required in (
        "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
        "native-reader-v2-release-input-${{ github.sha }}",
        "Verify aligned APK provenance without signing credentials",
        "Release input APK is unexpectedly already signed.",
        "Sign, verify, and remove protected Native Reader signing key",
        "secrets.NATIVE_SPREAD_KEYSTORE_B64",
        "$env:NATIVE_SPREAD_KEYSTORE_B64 = $null",
        "Remove-Item -LiteralPath $keystore -Force",
        "release-output/SupernoteNativeSpreadProbe-v0.0.137.apk",
    ):
        if required not in signing_job:
            fail(f"protected Native Reader signing job lacks invariant: {required}")
    if signing_job.index("Verify aligned APK provenance without signing credentials") > signing_job.index(
        "secrets.NATIVE_SPREAD_KEYSTORE_B64"
    ):
        fail("Native Reader signing secret is exposed before release input verification")


def test_native_reader_signing_isolation(repo_root: Path) -> None:
    workflow_path = repo_root / ".github" / "workflows" / "build.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    validate_native_reader_signing_isolation(workflow)

    unsigned_marker = "  native-spread-build:\n"
    expect_failure(
        lambda: validate_native_reader_signing_isolation(
            workflow.replace(
                unsigned_marker,
                unsigned_marker + "    env:\n      LEAK: ${{ secrets.NATIVE_SPREAD_KEYSTORE_B64 }}\n",
                1,
            )
        ),
        "signing secret exposed to checked-out build",
    )
    signing_marker = "  native-spread-upgrade-artifact:\n"
    expect_failure(
        lambda: validate_native_reader_signing_isolation(
            workflow.replace(
                signing_marker,
                signing_marker + "    # actions/checkout@0000000000000000000000000000000000000000\n",
                1,
            )
        ),
        "checkout introduced into protected signing job",
    )
    expect_failure(
        lambda: validate_native_reader_signing_isolation(
            workflow.replace(
                signing_marker,
                signing_marker + "    # scripts/attacker.py\n",
                1,
            )
        ),
        "repository script introduced into protected signing job",
    )


def main() -> None:
    repo_root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    with tempfile.TemporaryDirectory(prefix="rtl-reader-provenance-") as temp:
        temp_root = Path(temp)
        test_locked_dependencies(repo_root, temp_root)
        test_zip_normalization(temp_root)
        test_template_digest_failure(temp_root)
        test_native_reader_signing_isolation(repo_root)
    print("Build provenance and deterministic ZIP tests: PASS")


if __name__ == "__main__":
    main()
