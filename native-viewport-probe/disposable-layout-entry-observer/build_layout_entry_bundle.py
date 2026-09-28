"""Offline Frida 17 Java-bridge bundle builder for the synthetic observer.

Reads only pinned local source, lock and installed bridge. No npm install,
network, ADB, app, device or Frida attach. Candidate mode prints a digest but
never publishes a runnable bundle. Set BUNDLE_SHA256 to the reviewed digest
before verified mode can publish the file accepted by the runner.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile


HERE = Path(__file__).resolve().parent
NVPROBE = HERE.parent
PROJECT = HERE.parents[3]
LOCK = NVPROBE / "frida-display0-lock"
INSTALL = PROJECT / "local-node" / "frida-display0"
FRIDA_SITE = PROJECT / "local-python" / "frida-17.9.11"
SOURCE = HERE / "layout_entry_observer.js"
ENTRY = HERE / "layout_entry_bundle_entry.js"
BUILD = HERE / "build"
BUNDLE = BUILD / "layout_entry_bundle.js"

FRIDA_VERSION = "17.9.11"
BRIDGE_VERSION = "7.0.13"
BRIDGE_INTEGRITY = "sha512-YSyKjxbxKnSi3KSUy9vciOvTOuq0RRh9dkxzkQVEdfIIZlw20zE8D3Cq9eL2FDqUVj4YKas6Wf09kCjL5zbffg=="
SOURCE_SHA256 = "e374cf8c93e7c8e630d7f89e8484bde90f311115b59e40fe597bd8ccae3d83ab"
ENTRY_SHA256 = "3159a6a54045724dc6a7722cdef64aff15b9b8f4ea96e97c3df496e12244f489"
PACKAGE_SHA256 = "2bf82a222a26a051202e9c603439ecebc1b7a4a6aa91b24a5e7391e7ed63c896"
LOCK_SHA256 = "d69079427755d24d18aef5b16d6ca841d18c02c731d4e8a230b2117e9a10751b"
BRIDGE_TREE_SHA256 = "6c3150864236fe84c1780dd669c2acdedbc8832f19edbc8c87fad81467102279"
BUNDLE_SHA256: str | None = "241fd6a94067b26a737df8ddf6c192b82895006472c434cae4cbd06dc29a2d66"
MAX_BUNDLE_BYTES = 2_097_152


class BundleError(RuntimeError):
    pass


def need(ok: bool, code: str) -> None:
    if not ok:
        raise BundleError(code)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read(path: Path, maximum: int, code: str) -> bytes:
    try:
        need(path.is_file() and not path.is_symlink(), code)
        raw = path.read_bytes()
        need(0 < len(raw) <= maximum, code)
        return raw
    except OSError as error:
        raise BundleError(code) from error


def tree_sha(root: Path) -> str:
    need(root.is_dir() and not root.is_symlink(), "BUNDLE_INSTALL_CHANGED")
    digest = hashlib.sha256()
    try:
        entries = sorted(root.rglob("*"),
                         key=lambda path: path.relative_to(root).as_posix())
        need(len(entries) <= 128, "BUNDLE_INSTALL_CHANGED")
        for path in entries:
            need(not path.is_symlink(), "BUNDLE_INSTALL_CHANGED")
            name = path.relative_to(root).as_posix().encode("utf-8", "strict")
            if path.is_dir():
                digest.update(b"D\0" + name + b"\0")
            else:
                raw = read(path, 1_048_576, "BUNDLE_INSTALL_CHANGED")
                digest.update(b"F\0" + name + b"\0" +
                              len(raw).to_bytes(8, "big") + raw)
    except (OSError, UnicodeError, ValueError) as error:
        raise BundleError("BUNDLE_INSTALL_CHANGED") from error
    return digest.hexdigest()


def check_inputs() -> None:
    need(sha(read(SOURCE, 65_536, "BUNDLE_SOURCE_CHANGED")) == SOURCE_SHA256,
         "BUNDLE_SOURCE_CHANGED")
    need(sha(read(ENTRY, 8192, "BUNDLE_ENTRY_CHANGED")) == ENTRY_SHA256,
         "BUNDLE_ENTRY_CHANGED")
    package = read(LOCK / "package.json", 4096, "BUNDLE_PACKAGE_CHANGED")
    lock = read(LOCK / "package-lock.json", 16_384, "BUNDLE_LOCK_CHANGED")
    need(sha(package) == PACKAGE_SHA256 and sha(lock) == LOCK_SHA256,
         "BUNDLE_LOCK_CHANGED")
    try:
        value = json.loads(lock)
        bridge = value["packages"]["node_modules/frida-java-bridge"]
        need(value["lockfileVersion"] == 3 and
             value["packages"][""]["dependencies"] ==
                {"frida-java-bridge": BRIDGE_VERSION} and
             bridge["version"] == BRIDGE_VERSION and
             bridge["integrity"] == BRIDGE_INTEGRITY,
             "BUNDLE_LOCK_CHANGED")
    except (KeyError, TypeError, ValueError) as error:
        raise BundleError("BUNDLE_LOCK_CHANGED") from error
    need(read(INSTALL / "package.json", 4096, "BUNDLE_INSTALL_CHANGED") ==
         package and
         read(INSTALL / "package-lock.json", 16_384,
              "BUNDLE_INSTALL_CHANGED") == lock and
         tree_sha(INSTALL / "node_modules" / "frida-java-bridge") ==
            BRIDGE_TREE_SHA256,
         "BUNDLE_INSTALL_CHANGED")


def _build_bytes() -> bytes:
    check_inputs()
    try:
        BUILD.mkdir(exist_ok=True)
        need(not BUILD.is_symlink() and BUILD.resolve() == HERE / "build",
             "BUNDLE_BUILD_PATH_INVALID")
        modules = BUILD / "node_modules"
        need(not modules.is_symlink(), "BUNDLE_BUILD_PATH_INVALID")
        modules.mkdir(exist_ok=True)
        bridge_copy = modules / "frida-java-bridge"
        if not bridge_copy.exists():
            shutil.copytree(INSTALL / "node_modules" / "frida-java-bridge",
                            bridge_copy, symlinks=False)
        need(tree_sha(bridge_copy) == BRIDGE_TREE_SHA256,
             "BUNDLE_BUILD_PATH_INVALID")
        for source in (SOURCE, ENTRY):
            target = BUILD / source.name
            need(not target.is_symlink(), "BUNDLE_BUILD_PATH_INVALID")
            target.write_bytes(source.read_bytes())
        sys.path.insert(0, str(FRIDA_SITE))
        import frida  # type: ignore[import-not-found]
        need(importlib.metadata.version("frida") == FRIDA_VERSION and
             callable(getattr(frida, "Compiler", None)),
             "BUNDLE_COMPILER_CHANGED")
        compiled = frida.Compiler().build(
            str(BUILD / ENTRY.name), project_root=str(BUILD),
            output_format="unescaped", bundle_format="iife", type_check="none",
            source_maps="omitted", compression="none", platform="gum")
        need(type(compiled) is str, "BUNDLE_COMPILER_FAILED")
        raw = compiled.encode("utf-8", "strict")
        need(0 < len(raw) <= MAX_BUNDLE_BYTES, "BUNDLE_OVERSIZE")
        return raw
    except BundleError:
        raise
    except BaseException as error:
        raise BundleError("BUNDLE_COMPILER_FAILED") from error


def candidate_digest() -> dict[str, object]:
    raw = _build_bytes()
    return {"sha256": sha(raw), "bytes": len(raw), "published": False}


def build_verified() -> dict[str, object]:
    raw = _build_bytes()
    need(BUNDLE_SHA256 is not None and sha(raw) == BUNDLE_SHA256,
         "BUNDLE_HASH_UNPINNED_OR_CHANGED")
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=BUILD,
                                         prefix=".layout-entry-", suffix=".tmp",
                                         delete=False) as out:
            temporary = Path(out.name)
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
        need(not BUNDLE.is_symlink(), "BUNDLE_BUILD_PATH_INVALID")
        os.replace(temporary, BUNDLE)
        temporary = None
    except OSError as error:
        raise BundleError("BUNDLE_WRITE_FAILED") from error
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return {"sha256": BUNDLE_SHA256, "bytes": len(raw), "published": True,
            "path": str(BUNDLE)}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("candidate-digest", "build-verified"))
    choice = p.parse_args().mode
    try:
        result = candidate_digest() if choice == "candidate-digest" else build_verified()
        print(json.dumps(result, sort_keys=True))
    except BundleError as error:
        print(json.dumps({"error": str(error)}, sort_keys=True))
        raise SystemExit(2)
