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
            "NATIVE_SPREAD_MIN_VERSION_CODE = 65L",
            'setProperty("documentSha256", sha256(pdfFile))',
            'properties.getProperty("documentSha256", "") != sha256(pdfFile)',
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
            "fun configureNativeSpreadEditable(",
            "ensureNativeAnnotationBackup(pdfFile)",
            "retireNativeAnnotationBackup(",
            "A verified annotation backup belongs to an inactive protected session",
            "writeNativeSpreadEditableMarker(",
            "fun restoreNativeAnnotationBackup(",
            "scheduleAnnotationRestore(pdfFile, backup)",
            "Recovery snapshot changed before restore",
            "copyFileAtomically(backup.snapshot, currentMark)",
            "RTL_READER_NATIVE_BACKUP_RESTORE_ABORTED_ACTIVE_PROCESS",
            "Native document process remained active; annotation recovery was not written",
            'putBoolean("backupAvailable", backupResult.backup != null)',
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
            "RTL editable",
            "Back up & enable",
            "restoreNativeAnnotationBackup",
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

    editable_start = plugin.find("fun configureNativeSpreadEditable(")
    restore_start = plugin.find("fun restoreNativeAnnotationBackup(", editable_start)
    if editable_start < 0 or restore_start < 0:
        fail("could not isolate protected editable configuration method")
    editable_configure = plugin[editable_start:restore_start]
    editable_handshake = editable_configure.find("if (!handshake.active)")
    editable_backup = editable_configure.find("ensureNativeAnnotationBackup(pdfFile)")
    editable_marker = editable_configure.find("writeNativeSpreadEditableMarker(")
    if not (0 <= editable_handshake < editable_backup < editable_marker):
        fail("editable marker is not gated by handshake then verified backup")

    ensure_start = plugin.find("private fun ensureNativeAnnotationBackup(")
    read_backup_start = plugin.find("private fun readNativeAnnotationBackup(", ensure_start)
    if ensure_start < 0 or read_backup_start < 0:
        fail("could not isolate annotation backup creation/reuse method")
    ensure_backup = plugin[ensure_start:read_backup_start]
    inactive_guard = ensure_backup.find("protectedEditableMarkerValid(")
    reuse_log = ensure_backup.find("RTL_READER_NATIVE_BACKUP_REUSED")
    if inactive_guard < 0 or reuse_log < 0 or inactive_guard > reuse_log:
        fail("a verified backup can be reused without an active protected session")

    restore_worker_start = plugin.find("private fun scheduleAnnotationRestore(")
    restore_worker_end = plugin.find("\n    }\n}", restore_worker_start)
    if restore_worker_start < 0 or restore_worker_end < 0:
        fail("could not isolate annotation restore worker")
    restore_worker = plugin[restore_worker_start:restore_worker_end]
    remaining_check = restore_worker.find("val remaining = documentPids(activityManager)")
    active_abort = restore_worker.find(
        "RTL_READER_NATIVE_BACKUP_RESTORE_ABORTED_ACTIVE_PROCESS"
    )
    mark_write = restore_worker.find("copyFileAtomically(backup.snapshot, currentMark)")
    if not (0 <= remaining_check < active_abort < mark_write):
        fail("annotation restore can touch .mark before all document processes exit")

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
            "protectedEditableBackupValid(document, properties)",
            '"protected-editable-pilot"',
            "expectedManifestHash.equals(sha256(expectedManifest))",
            'backup.getProperty("documentSha256", "").trim().equals(',
            "protected_editable_document_mtime_changed",
            "protected_editable_backup_verified",
            "cached.backupModified == backupModified",
            "cached.snapshotModified == snapshotModified",
            "spreadLassoCanonicalSelection && mode == 1",
            '" preserve_size=" + preserveCanonicalSize',
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

    if 'android:versionCode="65"' not in manifest:
        fail("companion manifest must use versionCode 65 for protected editing")
    if 'android:versionName="0.0.65"' not in manifest:
        fail("companion manifest must use versionName 0.0.65")

    print("Native Spread safety invariants: PASS")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: check_native_spread_invariants.py <repo-root>")
    check(Path(sys.argv[1]).resolve())


if __name__ == "__main__":
    main()
