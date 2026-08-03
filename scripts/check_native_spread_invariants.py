#!/usr/bin/env python3
"""Verify fail-closed Native Spread handshake and lifecycle invariants."""

from __future__ import annotations

import re
import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"check_native_spread_invariants.py: {message}")


def require_markers(text: str, markers: tuple[str, ...], label: str) -> None:
    missing = [marker for marker in markers if marker not in text]
    if missing:
        fail(f"{label} is missing required markers: {missing}")


def check(repo_root: Path) -> None:
    plugin_path = repo_root / "native" / "ReaderPreferencesModule.kt.template"
    module_path = (
        repo_root
        / "native-spread-module"
        / "src"
        / "com"
        / "techrebbe"
        / "supernote"
        / "spreadprobe"
        / "SpreadProbe.java"
    )
    manifest_path = repo_root / "native-spread-module" / "AndroidManifest.xml"
    app_path = repo_root / "overlay" / "App.js"

    plugin = plugin_path.read_text(encoding="utf-8")
    module = module_path.read_text(encoding="utf-8")
    manifest = manifest_path.read_text(encoding="utf-8")
    app = app_path.read_text(encoding="utf-8")

    require_markers(
        plugin,
        (
            "NATIVE_SPREAD_MIN_VERSION_CODE = 62L",
            "NATIVE_SPREAD_HANDSHAKE_REQUEST",
            "NATIVE_SPREAD_HANDSHAKE_RESPONSE",
            "requestNativeSpreadHandshake(pdfFile) { handshake ->",
            "if (!handshake.active)",
            "writeNativeSpreadReadOnlyMarker(",
            "check(handshake.active)",
            "canonicalReportedPath == expectedPath",
            "documentApkLength == SUPPORTED_DOCUMENT_APK_LENGTH",
            "RTL_READER_NATIVE_SPREAD_HANDSHAKE_REQUEST",
            'putBoolean("configured", configured)',
            'putBoolean("configuredEditable", configuredEditable)',
            'putBoolean("enabled", configured && runtimeCompatible)',
        ),
        "plugin handshake",
    )
    require_markers(
        app,
        (
            "const [nativeSpreadConfigured, setNativeSpreadConfigured]",
            "nativeSpread?.configured === true",
            "nativeSpread?.configuredEditable === true",
            "next === 'ltr' &&",
            "nativeSpreadConfigured &&",
            "!nativeSpreadConfiguredEditable",
            "setNativeSpreadConfigured(enabled);",
            "active={!nativeSpreadConfigured}",
            "RTL read-only remains configured, but the compatible hooks are inactive.",
        ),
        "configured/runtime Native Spread state separation",
    )
    configure_start = plugin.find("fun configureNativeSpreadReadOnly(")
    marker_writer_start = plugin.find(
        "private fun writeNativeSpreadReadOnlyMarker(",
        configure_start,
    )
    if configure_start < 0 or marker_writer_start < 0:
        fail("could not isolate Native Spread configuration method")
    configure = plugin[configure_start:marker_writer_start]
    rejection = configure.find("if (!handshake.active)")
    marker_write = configure.find("writeNativeSpreadReadOnlyMarker(")
    if rejection < 0 or marker_write < 0 or rejection > marker_write:
        fail("marker creation is not gated by a successful live handshake")

    require_markers(
        module,
        (
            "HANDSHAKE_REQUEST_ACTION",
            "HANDSHAKE_RESPONSE_ACTION",
            "private static volatile boolean hooksReady;",
            "registerHandshakeReceiver(activeActivity);",
            "hooksReady = true;",
            "response.setPackage(PLUGIN_HOST_PACKAGE);",
            "response.putExtra(HANDSHAKE_EXTRA_HOOKS_READY, true);",
            "HANDSHAKE_EXTRA_DOCUMENT_APK_LENGTH",
            "HANDSHAKE_EXTRA_PROCESS_ID",
            "sameCanonicalPath(",
            "releaseActivityResources(activity);",
            "activeActivity = null;",
            "recycleRemovedBitmap(COMPOSITES, activity)",
            "COMMITTED_INK_COMPOSITES",
            "FULL_INK_BITMAPS",
            "DIGEST_COMPOSITES",
            "LEFT_DESTINATIONS.remove(activity);",
            "RIGHT_DESTINATIONS.remove(activity);",
            "SPREAD_CONFIGS.remove(activity);",
            "activity_resources_released",
        ),
        "companion handshake/lifecycle",
    )

    handle_start = module.find("public void handleLoadPackage(")
    first_helper = module.find(
        "private static synchronized void registerHandshakeReceiver(",
        handle_start,
    )
    if handle_start < 0 or first_helper < 0:
        fail("could not isolate handleLoadPackage")
    handle = module[handle_start:first_helper]
    hooks_ready = handle.rfind("hooksReady = true;")
    last_hook = handle.rfind("XposedHelpers.findAndHookMethod(")
    if hooks_ready < 0 or last_hook < 0 or hooks_ready < last_hook:
        fail("hooksReady must be set only after all hook registrations succeed")

    destroy_match = re.search(
        r'"onDestroy".*?new XC_MethodHook\(\) \{(.*?)\n\s*\}\n\s*\);',
        module,
        flags=re.DOTALL,
    )
    if not destroy_match:
        fail("could not isolate DocumentActivity onDestroy hook")
    destroy = destroy_match.group(1)
    if "protected void afterHookedMethod" not in destroy:
        fail("destroyed activity resources must be released after onDestroy")
    if "releaseActivityResources(activity);" not in destroy:
        fail("onDestroy does not release all per-activity resources")

    if 'android:versionCode="62"' not in manifest:
        fail("companion manifest must use versionCode 62 for handshake support")
    if 'android:versionName="0.0.62"' not in manifest:
        fail("companion manifest must use versionName 0.0.62")

    print("Native Spread safety invariants: PASS")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: check_native_spread_invariants.py <repo-root>")
    check(Path(sys.argv[1]).resolve())


if __name__ == "__main__":
    main()
