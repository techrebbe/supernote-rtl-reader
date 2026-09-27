"""Offline, pinned Frida 17 Java-bridge bundle for the disposable observer.

The installed npm tree is only a build input. This module performs no npm
install, ADB access, Frida attach, or network operation. The raw observer and
the generated bundle have separate fixed SHA-256 pins. Generated files live
under ignored ``native-viewport-probe/build`` and are never authoritative.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile


HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[2]
LOCK = HERE / "frida-display0-lock"
INSTALL = PROJECT / "local-node" / "frida-display0"
FRIDA_SITE = PROJECT / "local-python" / "frida-17.9.11"
SOURCE = HERE / "native_page_display0_identity_observer.js"
BUILD = HERE / "build"
ENTRYPOINT = BUILD / "native_page_display0_identity_entry.js"
BUNDLE = BUILD / "native_page_display0_identity_bundle.js"

FRIDA_VERSION = "17.9.11"
BRIDGE_VERSION = "7.0.13"
BRIDGE_INTEGRITY = "sha512-YSyKjxbxKnSi3KSUy9vciOvTOuq0RRh9dkxzkQVEdfIIZlw20zE8D3Cq9eL2FDqUVj4YKas6Wf09kCjL5zbffg=="
SOURCE_SHA256 = "366d0ea9fd965fbb0e479e65f00498b5479a7cb5bcb4bb16c545c079ef44fcab"
PACKAGE_SHA256 = "2bf82a222a26a051202e9c603439ecebc1b7a4a6aa91b24a5e7391e7ed63c896"
LOCK_SHA256 = "d69079427755d24d18aef5b16d6ca841d18c02c731d4e8a230b2117e9a10751b"
BRIDGE_TREE_SHA256 = "6c3150864236fe84c1780dd669c2acdedbc8832f19edbc8c87fad81467102279"
BUNDLE_SHA256 = "868b5d97e58073b382d24448e8f706aea4e3f6be36920bbdb1910d0e2cb9ee9c"
MAX_BUNDLE_BYTES = 2_097_152
IMPORT = b"import Java from 'frida-java-bridge';\n"


class BundleError(RuntimeError):
    """Only fixed, path-free error codes are exposed."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _need(ok: bool, code: str) -> None:
    if not ok:
        raise BundleError(code)


def _read(path: Path, maximum: int, code: str) -> bytes:
    try:
        _need(path.is_file() and not path.is_symlink(), code)
        data = path.read_bytes()
        _need(0 < len(data) <= maximum, code)
        return data
    except (OSError, ValueError) as error:
        raise BundleError(code) from error


def _lock_values(raw: bytes) -> None:
    try:
        value = json.loads(raw)
        package = value["packages"]["node_modules/frida-java-bridge"]
        _need(value["lockfileVersion"] == 3 and
              value["packages"][""]["dependencies"] ==
              {"frida-java-bridge": BRIDGE_VERSION} and
              package["version"] == BRIDGE_VERSION and
              package["integrity"] == BRIDGE_INTEGRITY,
              "BUNDLE_LOCK_CHANGED")
    except (KeyError, TypeError, ValueError) as error:
        raise BundleError("BUNDLE_LOCK_CHANGED") from error


def _tree_sha256(root: Path) -> str:
    """Hash exact relative names and contents; reject links and extra files."""
    _need(root.is_dir() and not root.is_symlink(), "BUNDLE_INSTALL_CHANGED")
    digest = hashlib.sha256()
    try:
        paths = sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix())
        _need(len(paths) <= 128, "BUNDLE_INSTALL_CHANGED")
        for path in paths:
            _need(not path.is_symlink(), "BUNDLE_INSTALL_CHANGED")
            name = path.relative_to(root).as_posix().encode("utf-8", "strict")
            if path.is_dir():
                digest.update(b"D\0" + name + b"\0")
            else:
                _need(path.is_file(), "BUNDLE_INSTALL_CHANGED")
                content = _read(path, 1_048_576, "BUNDLE_INSTALL_CHANGED")
                digest.update(b"F\0" + name + b"\0" +
                              len(content).to_bytes(8, "big") + content)
    except (OSError, UnicodeError, ValueError) as error:
        raise BundleError("BUNDLE_INSTALL_CHANGED") from error
    return digest.hexdigest()


def check_inputs() -> bytes:
    """Authenticate the raw source, committed lock, and installed npm tree."""
    source = _read(SOURCE, 65_536, "BUNDLE_SOURCE_CHANGED")
    _need(_sha(source) == SOURCE_SHA256, "BUNDLE_SOURCE_CHANGED")
    package = _read(LOCK / "package.json", 4096, "BUNDLE_PACKAGE_CHANGED")
    lock = _read(LOCK / "package-lock.json", 16_384, "BUNDLE_LOCK_CHANGED")
    _need(_sha(package) == PACKAGE_SHA256, "BUNDLE_PACKAGE_CHANGED")
    _need(_sha(lock) == LOCK_SHA256, "BUNDLE_LOCK_CHANGED")
    _lock_values(lock)
    installed_package = _read(INSTALL / "package.json", 4096,
                              "BUNDLE_INSTALL_CHANGED")
    installed_lock = _read(INSTALL / "package-lock.json", 16_384,
                           "BUNDLE_INSTALL_CHANGED")
    _need(installed_package == package and installed_lock == lock,
          "BUNDLE_INSTALL_CHANGED")
    bridge_package = _read(INSTALL / "node_modules" / "frida-java-bridge" / "package.json",
                           16_384, "BUNDLE_INSTALL_CHANGED")
    try:
        _need(json.loads(bridge_package)["version"] == BRIDGE_VERSION,
              "BUNDLE_INSTALL_CHANGED")
    except (KeyError, TypeError, ValueError) as error:
        raise BundleError("BUNDLE_INSTALL_CHANGED") from error
    _need(_tree_sha256(INSTALL / "node_modules" / "frida-java-bridge") ==
          BRIDGE_TREE_SHA256, "BUNDLE_INSTALL_CHANGED")
    return source


def _verified_bundle(raw: bytes) -> bytes:
    _need(0 < len(raw) <= MAX_BUNDLE_BYTES and
          len(BUNDLE_SHA256) == 64 and _sha(raw) == BUNDLE_SHA256,
          "BUNDLE_HASH_MISMATCH")
    return raw


def _atomic_bytes(path: Path, data: bytes) -> None:
    _need(not BUILD.is_symlink() and BUILD.resolve() == HERE / "build",
          "BUNDLE_BUILD_PATH_INVALID")
    _need(not path.is_symlink(), "BUNDLE_BUILD_PATH_INVALID")
    temp: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=BUILD, prefix=".bundle-",
                                         suffix=".tmp", delete=False) as handle:
            temp = Path(handle.name)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    except OSError as error:
        raise BundleError("BUNDLE_BUILD_WRITE_FAILED") from error
    finally:
        if temp is not None:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass


def build_verified_bundle() -> bytes:
    """Compile offline, verify the exact output hash, then publish locally."""
    source = check_inputs()
    try:
        BUILD.mkdir(exist_ok=True)
        _need(not BUILD.is_symlink() and BUILD.resolve() == HERE / "build",
              "BUNDLE_BUILD_PATH_INVALID")
        node_modules = BUILD / "node_modules"
        _need(not node_modules.is_symlink(), "BUNDLE_BUILD_PATH_INVALID")
        node_modules.mkdir(exist_ok=True)
        bridge_copy = node_modules / "frida-java-bridge"
        if not bridge_copy.exists():
            _need(not bridge_copy.is_symlink(), "BUNDLE_BUILD_PATH_INVALID")
            shutil.copytree(INSTALL / "node_modules" / "frida-java-bridge",
                            bridge_copy, symlinks=False)
        _need(_tree_sha256(bridge_copy) == BRIDGE_TREE_SHA256,
              "BUNDLE_BUILD_PATH_INVALID")
        _atomic_bytes(ENTRYPOINT, IMPORT + source)
        sys.path.insert(0, str(FRIDA_SITE))
        import frida  # type: ignore[import-not-found]
        _need(importlib.metadata.version("frida") == FRIDA_VERSION and
              callable(getattr(frida, "Compiler", None)),
              "BUNDLE_COMPILER_CHANGED")
        compiled = frida.Compiler().build(
            str(ENTRYPOINT), project_root=str(BUILD),
            output_format="unescaped", bundle_format="iife", type_check="none",
            source_maps="omitted", compression="none", platform="gum")
        _need(type(compiled) is str, "BUNDLE_COMPILER_FAILED")
        raw = compiled.encode("utf-8", "strict")
        _verified_bundle(raw)
        _atomic_bytes(BUNDLE, raw)
        return raw
    except BundleError:
        raise
    except BaseException as error:
        raise BundleError("BUNDLE_COMPILER_FAILED") from error


def load_verified_bundle() -> bytes:
    """The killable child loads only a hash-pinned build, never raw JS."""
    check_inputs()
    return _verified_bundle(_read(BUNDLE, MAX_BUNDLE_BYTES,
                                  "BUNDLE_MISSING"))
