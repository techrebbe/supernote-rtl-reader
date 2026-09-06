#!/usr/bin/env python3
"""Materialize the reviewed Supernote template without executing package code."""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import os
import re
import shutil
import sys
import tarfile
from pathlib import Path, PurePosixPath


TEMPLATE_PREFIX = PurePosixPath("package/template")
RENAMED_DOTFILES = {
    "_eslintrc.js": ".eslintrc.js",
    "_gitignore": ".gitignore",
    "_prettierrc.js": ".prettierrc.js",
    "_watchmanconfig": ".watchmanconfig",
    "_xcode.env": ".xcode.env",
}
EXPECTED_TEMPLATE_PACKAGE = "@supernote-plugin/sn-plugin-template"
EXPECTED_TEMPLATE_VERSION = "1.0.12"
EXPECTED_TEMPLATE_SHA256 = (
    "34dceadedd77d2c77c83521fee838dc60f3893b948a9070bf38271184268636f"
)
EXPECTED_TEMPLATE_SRI = (
    "sha512-n7wY9y43DYJUNGdFEjFu+i8bU9C3TX9UG1yWjYbkcn3zWBUNSFuEC5LQ5FmK"
    "vz3onOE/1wUk52/X0RDJpPcmuA=="
)
EXPECTED_LOCK_SHA256 = (
    "33ea436d56b68d332949db0689f4b0c2bfd6f227e78e904b7706360ebc161022"
)
PROJECT_NAME = "SupernoteRtlReader"
PACKAGE_NAME = "com.supernotertlreader"


def fail(message: str) -> None:
    raise SystemExit(f"materialize_plugin_template.py: {message}")


def digest(path: Path, algorithm: str) -> str:
    hasher = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_template(tarball: Path) -> None:
    if digest(tarball, "sha256") != EXPECTED_TEMPLATE_SHA256:
        fail("template tarball SHA-256 does not match the reviewed release")
    actual_sri = "sha512-" + base64.b64encode(
        bytes.fromhex(digest(tarball, "sha512"))
    ).decode("ascii")
    if actual_sri != EXPECTED_TEMPLATE_SRI:
        fail("template tarball SRI does not match the reviewed release")


def renamed_path(relative: PurePosixPath) -> Path:
    parts: list[str] = []
    for part in relative.parts:
        if not part or part in (".", "..") or "\\" in part or "\0" in part:
            fail(f"unsafe template member path: {relative}")
        part = RENAMED_DOTFILES.get(part, part)
        part = part.replace("HelloWorld", PROJECT_NAME)
        part = part.replace("helloworld", PROJECT_NAME.lower())
        parts.append(part)
    candidate = Path(*parts)
    if candidate.is_absolute() or ".." in candidate.parts:
        fail(f"unsafe template member path: {relative}")
    return candidate


def transform_content(data: bytes) -> bytes:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return data
    return (
        text.replace("Hello App Display Name", "RTL Reader")
        .replace("com.helloworld", PACKAGE_NAME)
        .replace("HelloWorld", PROJECT_NAME)
        .replace("helloworld", PROJECT_NAME.lower())
        .encode("utf-8")
    )


def read_and_validate_lock(lock_path: Path, package_json: bytes) -> bytes:
    try:
        encoded = "".join(lock_path.read_text(encoding="ascii").split())
        lock_bytes = gzip.decompress(base64.b64decode(encoded, validate=True))
    except (OSError, UnicodeError, ValueError, gzip.BadGzipFile) as error:
        fail(f"cannot decode the locked dependency input: {error}")
    if hashlib.sha256(lock_bytes).hexdigest() != EXPECTED_LOCK_SHA256:
        fail("package-lock.json digest does not match the reviewed dependency graph")
    try:
        lock = json.loads(lock_bytes.decode("utf-8"))
        package = json.loads(package_json.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"locked dependency input is not valid JSON: {error}")
    if lock.get("lockfileVersion") != 3 or lock.get("requires") is not True:
        fail("package-lock.json must be npm lockfile version 3")
    packages = lock.get("packages")
    if not isinstance(packages, dict) or not isinstance(packages.get(""), dict):
        fail("package-lock.json lacks its root package record")
    root = packages[""]
    for field in ("name", "version", "dependencies", "devDependencies", "engines"):
        if root.get(field) != package.get(field):
            fail(f"package-lock root {field!r} differs from the template package")
    for name, record in packages.items():
        if name == "":
            continue
        if not isinstance(record, dict):
            fail(f"package-lock record {name!r} is not an object")
        version = record.get("version")
        if not isinstance(version, str) or not version:
            fail(f"package-lock record {name!r} lacks an exact version")
        resolved = record.get("resolved")
        if not isinstance(resolved, str) or not resolved.startswith(
            "https://registry.npmjs.org/"
        ):
            fail(f"dependency {name!r} is not pinned to the npm registry")
        integrity = record.get("integrity")
        if not isinstance(integrity, str) or not re.fullmatch(
            r"sha512-[A-Za-z0-9+/]+={0,2}", integrity
        ):
            fail(f"registry dependency {name!r} lacks SHA-512 integrity")
    return lock_bytes


def materialize(tarball: Path, lock_path: Path, destination: Path) -> None:
    verify_template(tarball)
    if destination.exists():
        fail(f"destination already exists: {destination}")
    destination.mkdir(parents=True)
    seen: set[str] = set()
    package_json: bytes | None = None
    try:
        with tarfile.open(tarball, "r:gz") as archive:
            members = archive.getmembers()
            package_metadata = [m for m in members if m.name == "package/package.json"]
            if len(package_metadata) != 1 or not package_metadata[0].isfile():
                fail("template archive lacks one package/package.json")
            metadata_stream = archive.extractfile(package_metadata[0])
            if metadata_stream is None:
                fail("cannot read template package metadata")
            metadata = json.loads(metadata_stream.read().decode("utf-8"))
            if (
                metadata.get("name") != EXPECTED_TEMPLATE_PACKAGE
                or metadata.get("version") != EXPECTED_TEMPLATE_VERSION
            ):
                fail("template package identity does not match the reviewed release")

            for member in members:
                member_path = PurePosixPath(member.name)
                try:
                    relative = member_path.relative_to(TEMPLATE_PREFIX)
                except ValueError:
                    continue
                if not relative.parts:
                    continue
                if member.issym() or member.islnk() or member.isdev():
                    fail(f"template contains a forbidden special entry: {member.name}")
                target_relative = renamed_path(relative)
                target_key = target_relative.as_posix()
                if target_key in seen:
                    fail(f"template paths collide after renaming: {target_key}")
                seen.add(target_key)
                target = destination / target_relative
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    fail(f"template contains an unsupported entry: {member.name}")
                source = archive.extractfile(member)
                if source is None:
                    fail(f"cannot read template entry: {member.name}")
                content = transform_content(source.read())
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
                os.chmod(target, member.mode & 0o777)
                if target_relative.as_posix() == "package.json":
                    package_json = content
    except (tarfile.TarError, json.JSONDecodeError) as error:
        shutil.rmtree(destination, ignore_errors=True)
        fail(f"invalid template archive: {error}")

    if package_json is None:
        shutil.rmtree(destination, ignore_errors=True)
        fail("materialized template lacks package.json")
    lock_bytes = read_and_validate_lock(lock_path, package_json)
    (destination / "package-lock.json").write_bytes(lock_bytes)


def main() -> None:
    if len(sys.argv) != 4:
        fail(
            "usage: materialize_plugin_template.py "
            "<template.tgz> <package-lock.json.gz.b64> <destination>"
        )
    materialize(
        Path(sys.argv[1]).resolve(),
        Path(sys.argv[2]).resolve(),
        Path(sys.argv[3]).resolve(),
    )
    print(f"Materialized authenticated Supernote template: {sys.argv[3]}")


if __name__ == "__main__":
    main()
