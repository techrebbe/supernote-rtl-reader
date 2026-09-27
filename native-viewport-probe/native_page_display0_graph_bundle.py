"""Pinned offline bundle for the separate stock-display graph calibration.

This builds only host-side JavaScript. It does not connect to ADB, attach to the
reader, or run a device experiment. The existing identity bundle establishes
the exact installed Frida compiler and Java-bridge dependency tree first.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
from pathlib import Path
import sys

import native_page_display0_bundle as base


HERE = Path(__file__).resolve().parent
SOURCE = HERE / "native_page_display0_graph_observer.js"
ENTRYPOINT = base.BUILD / "native_page_display0_graph_entry.js"
BUNDLE = base.BUILD / "native_page_display0_graph_bundle.js"
SOURCE_SHA256 = "f2c680ee9ea7039ef5e27621ddc7e07ea69bcf8cb54512e76cfa75a55d48106c"
BUNDLE_SHA256 = "19de2ae3e2f88a59e631cead2a07d643b2478b174ffa3ff067e7d54a70e7c081"


class GraphBundleError(RuntimeError):
    """Only fixed, path-free failure codes are exposed."""


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _need(ok: bool, code: str) -> None:
    if not ok:
        raise GraphBundleError(code)


def _source() -> bytes:
    try:
        _need(SOURCE.is_file() and not SOURCE.is_symlink(), "GRAPH_SOURCE_CHANGED")
        source = SOURCE.read_bytes()
    except OSError as error:
        raise GraphBundleError("GRAPH_SOURCE_CHANGED") from error
    _need(0 < len(source) <= 65_536 and _sha(source) == SOURCE_SHA256,
          "GRAPH_SOURCE_CHANGED")
    return source


def _verified_bundle(raw: bytes) -> bytes:
    _need(0 < len(raw) <= base.MAX_BUNDLE_BYTES and
          len(BUNDLE_SHA256) == 64 and _sha(raw) == BUNDLE_SHA256,
          "GRAPH_BUNDLE_HASH_MISMATCH")
    return raw


def build_verified_bundle() -> bytes:
    """Compile using the pinned dependency tree, then verify before publish."""
    source = _source()
    try:
        base.build_verified_bundle()
        base._atomic_bytes(ENTRYPOINT, base.IMPORT + source)
        sys.path.insert(0, str(base.FRIDA_SITE))
        import frida  # type: ignore[import-not-found]
        _need(importlib.metadata.version("frida") == base.FRIDA_VERSION and
              callable(getattr(frida, "Compiler", None)),
              "GRAPH_COMPILER_CHANGED")
        compiled = frida.Compiler().build(
            str(ENTRYPOINT), project_root=str(base.BUILD),
            output_format="unescaped", bundle_format="iife", type_check="none",
            source_maps="omitted", compression="none", platform="gum")
        _need(type(compiled) is str, "GRAPH_COMPILER_FAILED")
        raw = _verified_bundle(compiled.encode("utf-8", "strict"))
        base._atomic_bytes(BUNDLE, raw)
        return raw
    except GraphBundleError:
        raise
    except base.BundleError as error:
        raise GraphBundleError("GRAPH_DEPENDENCY_CHANGED") from error
    except BaseException as error:
        raise GraphBundleError("GRAPH_COMPILER_FAILED") from error


def load_verified_bundle() -> bytes:
    """The killable child loads only this hash-pinned compiled artifact."""
    _source()
    try:
        base.check_inputs()
        _need(BUNDLE.is_file() and not BUNDLE.is_symlink(),
              "GRAPH_BUNDLE_MISSING")
        return _verified_bundle(BUNDLE.read_bytes())
    except GraphBundleError:
        raise
    except base.BundleError as error:
        raise GraphBundleError("GRAPH_DEPENDENCY_CHANGED") from error
    except OSError as error:
        raise GraphBundleError("GRAPH_BUNDLE_MISSING") from error
