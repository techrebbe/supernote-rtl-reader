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
    trace_script_path = repo_root / "native-spread-module" / "trace.ps1"
    app_path = repo_root / "overlay" / "App.js"
    pdf_view_path = repo_root / "native" / "PdfPageView.kt.template"
    pdf_view_manager_path = repo_root / "native" / "PdfPageViewManager.kt.template"
    direct_patch_path = repo_root / "scripts" / "patch_direct_view.py"

    plugin = plugin_path.read_text(encoding="utf-8")
    module = module_path.read_text(encoding="utf-8")
    manifest = manifest_path.read_text(encoding="utf-8")
    trace_script = trace_script_path.read_text(encoding="utf-8")
    app = app_path.read_text(encoding="utf-8")
    pdf_view = pdf_view_path.read_text(encoding="utf-8")
    pdf_view_manager = pdf_view_manager_path.read_text(encoding="utf-8")
    direct_patch = direct_patch_path.read_text(encoding="utf-8")

    require_markers(
        plugin,
        (
            "NATIVE_SPREAD_MIN_VERSION_CODE = 118L",
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
            'startNativeBackupWorker("RTLReaderNativeBackupCreate")',
            'startNativeBackupWorker("RTLReaderNativeBackupRetire")',
            "retireNativeAnnotationBackup(",
            "val previousMarkerBytes = if (marker.isFile) marker.readBytes() else null",
            "writeBytesAtomically(marker, previousMarkerBytes)",
            "RTL_READER_NATIVE_MARKER_ROLLED_BACK",
            "RTL_READER_NATIVE_EDITABLE_ACTIVATION_ROLLED_BACK",
            "sameNativeAnnotationBackup(backup, revalidatedBackup)",
            "A verified annotation backup belongs to an inactive protected session",
            "writeNativeSpreadEditableMarker(",
            "fun restoreNativeAnnotationBackup(",
            "scheduleAnnotationRestore(pdfFile, backup)",
            "Recovery snapshot changed before restore",
            "copyFileAtomically(revalidatedBackup.snapshot, currentMark)",
            "RTL_READER_NATIVE_BACKUP_RESTORE_ABORTED_ACTIVE_PROCESS",
            "Native document process remained active; annotation recovery was not written",
            'promise.resolve(nativeAnnotationBackupMap(backup, "restored"))',
            "Toast.makeText(",
            "RTL_READER_NATIVE_BACKUP_RETIREMENT_ROLLED_BACK",
            "RTL_READER_NATIVE_BACKUP_CREATION_ROLLED_BACK",
            "nativeAnnotationRetiringSnapshot(pdfFile)",
            "removeNativeAnnotationBackupFiles(pdfFile, backup)",
            'putBoolean("backupAvailable", backupResult.backup != null)',
            'setProperty("showDivider", showDivider.toString())',
            'setProperty("showHeader", showHeader.toString())',
            '"spreadSizing"',
            'putBoolean("showDivider", showDivider)',
            'putBoolean("showHeader", showHeader)',
            'putString("spreadSizing", spreadSizing)',
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
            "const nativeSpreadBusyRef = useRef(false);",
            "nativeSpreadBusyRef.current = true;",
            "if (nativeSpreadBusyRef.current) return;",
            "BackHandler.addEventListener(",
            "if (!nativeSpreadBusyRef.current) return false;",
            "Wait for the native reader change to finish before closing.",
            "const [showSpreadDivider, setShowSpreadDivider]",
            "const [showNativeSpreadHeader, setShowNativeSpreadHeader]",
            "const [spreadSizing, setSpreadSizing]",
            "setNativeSpreadAppearanceValue",
            "nativeSpread?.showHeader !== false",
            "Active-page header",
            """const restoredCoverSeparate = nativeSpread?.configured
          ? nativeSpread?.coverSeparate === true
          : restored.coverSeparate;""",
            """const restoredSizing = nativeSpread?.configured
          ? nativeSpread?.spreadSizing === 'native_fill'
            ? 'native_fill'
            : 'fit'
          : restored.spreadSizing;""",
        ),
        "configured/runtime Native Spread state separation",
    )
    history_hook_start = module.find(
        'for (String methodName : new String[] {"undo", "redo"})'
    )
    history_hook_end = module.find(
        '"loadHandWrite",\n            int.class,', history_hook_start
    )
    if history_hook_start < 0 or history_hook_end < 0:
        fail("could not isolate native Undo/Redo transaction guards")
    history_hook = module[history_hook_start:history_hook_end]
    history_reset = history_hook.find(
        "PAGE_ACTIVATION_HISTORY_BLOCKED.remove();"
    )
    history_transaction = history_hook.find(
        "PAGE_ACTIVATION_TRANSACTIONS.get(activity)", history_reset
    )
    history_mark_blocked = history_hook.find(
        "PAGE_ACTIVATION_HISTORY_BLOCKED.set(Boolean.TRUE)",
        history_transaction,
    )
    history_suppress = history_hook.find(
        "param.setResult(null);", history_mark_blocked
    )
    history_native_path = history_hook.find(
        "FORCE_CANONICAL_ACTIVE_INK.set(true);", history_suppress
    )
    history_after = history_hook.find(
        "protected void afterHookedMethod", history_native_path
    )
    history_after_guard = history_hook.find(
        "PAGE_ACTIVATION_HISTORY_BLOCKED.get()", history_after
    )
    history_after_clear = history_hook.find(
        "PAGE_ACTIVATION_HISTORY_BLOCKED.remove();", history_after_guard
    )
    history_after_return = history_hook.find("return;", history_after_clear)
    history_after_native = history_hook.find("try {", history_after_return)
    if not (
        0 <= history_reset < history_transaction < history_mark_blocked
        < history_suppress < history_native_path < history_after
        < history_after_guard < history_after_clear < history_after_return
        < history_after_native
    ):
        fail(
            "native Undo/Redo can mutate or reload presenter state during an "
            "ownership transfer"
        )

    require_markers(
        module,
        (
            "final boolean showDivider;",
            "final boolean showHeader;",
            "final boolean nativeFill;",
            'properties.getProperty("showDivider", "true")',
            'properties.getProperty("showHeader", "true")',
            'properties.getProperty("spreadSizing", "fit")',
            "LEFT_VISIBLE_BOUNDS",
            "RIGHT_VISIBLE_BOUNDS",
            "SpreadPageLayout",
            "drawPageBitmap(canvas, leftBitmap, leftLayout, bitmapPaint)",
            "canvas.clipRect(layout.visibleBounds)",
            "showStatusOverlay(",
            "!config.showHeader",
            "removeOverlay(activity);",
            "visibleBoundsOrDestination(activity, activeDestination)",
            "Math.max(",
        ),
        "native spread appearance geometry",
    )
    captured_ink_start = module.find(
        "private static Bitmap renderCapturedFullInk("
    )
    combined_ink_start = module.find(
        "private static Bitmap renderCombinedCommittedInk(",
        captured_ink_start,
    )
    if captured_ink_start < 0 or combined_ink_start < 0:
        fail("could not isolate active settled-ink compositor")
    require_markers(
        module[captured_ink_start:combined_ink_start],
        (
            "RectF activeVisibleBounds = activePageVisibleBounds(activity)",
            "activeVisibleBounds = new RectF(activeDestination)",
            "canvas.clipRect(activeVisibleBounds)",
            "canvas.drawBitmap(",
            "canvas.restoreToCount(saveCount)",
        ),
        "Native Fill active settled-ink clipping",
    )
    require_markers(
        pdf_view + pdf_view_manager + direct_patch,
        (
            'var pendingContentMode: String = "fit"',
            'if (pendingContentMode == "native_fill")',
            "max(widthScale, heightScale)",
            '@ReactProp(name = "contentMode")',
            "contentMode={spreadSizing}",
            'contentMode="fit"',
            "{showSpreadDivider && <View style={styles.spreadDivider} />}",
        ),
        "full-screen custom reader spread sizing",
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
    handshake_apply = configure.find(
        "applyReadOnlyConfiguration(handshake)",
        rejection,
    )
    if (
        rejection < 0
        or marker_write < 0
        or "checkNotNull(handshake)" not in configure
        or handshake_apply < rejection
    ):
        fail("marker creation is not gated by a successful live handshake")

    editable_start = plugin.find("fun configureNativeSpreadEditable(")
    restore_start = plugin.find("fun restoreNativeAnnotationBackup(", editable_start)
    if editable_start < 0 or restore_start < 0:
        fail("could not isolate protected editable configuration method")
    editable_configure = plugin[editable_start:restore_start]
    editable_handshake = editable_configure.find("if (!handshake.active)")
    editable_worker = editable_configure.find(
        'startNativeBackupWorker("RTLReaderNativeBackupCreate")'
    )
    editable_backup = editable_configure.find(
        "ensureStableNativeAnnotationBackupForActivation("
    )
    editable_marker = editable_configure.find("writeNativeSpreadEditableMarker(")
    if not (
        0 <= editable_handshake < editable_worker < editable_backup < editable_marker
    ):
        fail(
            "editable marker is not gated by handshake then background verified backup"
        )
    editable_backup_existed = editable_configure.find(
        "val backupManifestExisted = nativeAnnotationBackupManifest(pdfFile).isFile"
    )
    editable_marker_snapshot = editable_configure.find("val previousMarkerBytes =")
    editable_cleanup = editable_configure.find(
        "removeNativeAnnotationBackupFiles(pdfFile, backup)",
        editable_marker,
    )
    editable_rollback = editable_configure.find(
        "RTL_READER_NATIVE_EDITABLE_ACTIVATION_ROLLED_BACK",
        editable_marker,
    )
    if not (
        0 <= editable_marker_snapshot < editable_backup_existed < editable_backup
        < editable_marker < editable_cleanup < editable_rollback
    ):
        fail("new backup and editable marker activation are not rollback-capable")

    stable_backup_start = plugin.find(
        "private fun ensureStableNativeAnnotationBackupForActivation("
    )
    read_backup_start = plugin.find(
        "private fun readNativeAnnotationBackup(",
        stable_backup_start,
    )
    if stable_backup_start < 0 or read_backup_start < 0:
        fail("could not isolate live annotation backup stabilization")
    stable_backup = plugin[stable_backup_start:read_backup_start]
    require_markers(
        stable_backup,
        (
            "repeat(maximumAttempts)",
            "val backup = ensureNativeAnnotationBackup(pdfFile)",
            "liveNativeAnnotationMatchesBackup(backup)",
            "removeNativeAnnotationBackupFiles(pdfFile, backup)",
            "mark.length() == backup.markLength",
            "sha256(mark) == backup.markSha256",
            "!mark.exists()",
            "RTL_READER_NATIVE_BACKUP_LIVE_MARK_CHANGED",
        ),
        "live annotation backup stabilization",
    )
    snapshot_attempt = stable_backup.find(
        "val backup = ensureNativeAnnotationBackup(pdfFile)"
    )
    live_check = stable_backup.find(
        "liveNativeAnnotationMatchesBackup(backup)",
        snapshot_attempt,
    )
    retry_cleanup = stable_backup.find(
        "removeNativeAnnotationBackupFiles(pdfFile, backup)",
        live_check,
    )
    if not 0 <= snapshot_attempt < live_check < retry_cleanup:
        fail("editable activation does not retry a snapshot after live .mark drift")

    configure_worker = configure.find(
        'startNativeBackupWorker("RTLReaderNativeBackupRetire")'
    )
    marker_snapshot = configure.find("val previousMarkerBytes =")
    retirement = configure.find("retireNativeAnnotationBackup(")
    marker_rollback = configure.find("writeBytesAtomically(marker, previousMarkerBytes)")
    if not (
        0 <= configure_worker < marker_snapshot < retirement < marker_rollback
    ):
        fail("read-only/off transition does not preserve and roll back its marker")

    require_markers(
        module,
        (
            "final long documentModified;",
            "final long documentLength;",
            "final long documentDevice;",
            "final long documentInode;",
            "final long documentChangeSeconds;",
            "final long documentChangeNanos;",
            "&& cached.documentModified == documentModified",
            "&& cached.documentLength == documentLength",
            "&& cached.documentDevice == documentDevice",
            "&& cached.documentInode == documentInode",
            "&& cached.documentChangeSeconds == documentChangeSeconds",
            "&& cached.documentChangeNanos == documentChangeNanos",
            "&& documentModified == nextDocumentModified",
            "&& documentLength == nextDocumentLength",
            "&& documentDevice == nextDocumentDevice",
            "&& documentInode == nextDocumentInode",
            "&& documentChangeSeconds == nextDocumentChangeSeconds",
            "&& documentChangeNanos == nextDocumentChangeNanos",
            "StructStat documentStat = Os.stat(document.getAbsolutePath());",
            "long documentDevice = documentStat.st_dev;",
            "long documentInode = documentStat.st_ino;",
            "long documentChangeSeconds = documentStat.st_ctim.tv_sec;",
            "long documentChangeNanos = documentStat.st_ctim.tv_nsec;",
            "final FileIdentity markerIdentity;",
            "final FileIdentity backupIdentity;",
            "final FileIdentity snapshotIdentity;",
            "FileIdentity markerIdentity = FileIdentity.capture(marker);",
            "FileIdentity backupIdentity = FileIdentity.capture(backupManifest);",
            "FileIdentity snapshotIdentity = FileIdentity.capture(backupSnapshot);",
            "&& cached.markerIdentity.sameAs(markerIdentity)",
            "&& cached.backupIdentity.sameAs(backupIdentity)",
            "&& cached.snapshotIdentity.sameAs(snapshotIdentity)",
            "&& markerIdentity.sameAs(nextMarkerIdentity)",
            "&& backupIdentity.sameAs(nextBackupIdentity)",
            "&& snapshotIdentity.sameAs(nextSnapshotIdentity)",
            "startProtectedEditableVerification(",
        ),
        "protected PDF replacement invalidation",
    )

    ensure_start = plugin.find("private fun ensureNativeAnnotationBackup(")
    read_backup_start = plugin.find("private fun readNativeAnnotationBackup(", ensure_start)
    if ensure_start < 0 or read_backup_start < 0:
        fail("could not isolate annotation backup creation/reuse method")
    ensure_backup = plugin[ensure_start:read_backup_start]
    inactive_guard = ensure_backup.find("protectedEditableMarkerValid(")
    reuse_log = ensure_backup.find("RTL_READER_NATIVE_BACKUP_REUSED")
    if inactive_guard < 0 or reuse_log < 0 or inactive_guard > reuse_log:
        fail("a verified backup can be reused without an active protected session")
    snapshot_copy = ensure_backup.find("copyFileAtomically(mark, snapshot)")
    final_verification = ensure_backup.find(
        "val verified = readNativeAnnotationBackup(pdfFile)",
        snapshot_copy,
    )
    creation_catch = ensure_backup.find("catch (error: Throwable)", snapshot_copy)
    rollback_log = ensure_backup.find(
        "RTL_READER_NATIVE_BACKUP_CREATION_ROLLED_BACK",
        creation_catch,
    )
    if not (
        0 <= snapshot_copy < final_verification < creation_catch < rollback_log
    ):
        fail("annotation backup final verification is outside rollback scope")

    close_start = app.find("const close = async () =>")
    go_by_start = app.find("const goBy = delta =>", close_start)
    if close_start < 0 or go_by_start < 0:
        fail("could not isolate plugin Close handler")
    close_handler = app[close_start:go_by_start]
    busy_guard = close_handler.find("if (nativeSpreadBusyRef.current)")
    close_plugin = close_handler.find("PluginManager.closePluginView()")
    if not (0 <= busy_guard < close_plugin):
        fail("Close can hand off while a native-mode transition is pending")
    close_settings_start = close_handler.find("const closeSettings = () =>")
    close_settings_guard = close_handler.find(
        "if (nativeSpreadBusyRef.current)",
        close_settings_start,
    )
    close_settings_commit = close_handler.find(
        "setSettingsOpen(false);",
        close_settings_start,
    )
    if not (
        0 <= close_settings_start < close_settings_guard < close_settings_commit
    ):
        fail("Settings can close before the busy ref clears")

    settings_start = app.find("{settingsOpen && !fatalError && (")
    cover_controls_start = app.find(
        "<Text style={styles.settingLabel}>Treat Cover Page Separately</Text>",
        settings_start,
    )
    settings_header = app[settings_start:cover_controls_start]
    if (
        "disabled={nativeSpreadBusy}" not in settings_header
        or "onPress={closeSettings}" not in settings_header
        or "nativeSpreadBusy ? 'Applying...' : 'Done'" not in settings_header
    ):
        fail("Settings Done remains available during a native-mode transition")

    settings_panel_start = app.find("<View style={styles.settingsPanel}>")
    settings_scroll_start = app.find(
        "<ScrollView", settings_panel_start
    )
    warning_panel_start = app.find(
        "{nativeEditableConfirmOpen && (", settings_scroll_start
    )
    recovery_row_start = app.find(
        "{nativeBackupAvailable && (", warning_panel_start
    )
    settings_scroll_end = app.find("</ScrollView>", recovery_row_start)
    if not (
        0 <= settings_panel_start < settings_scroll_start
        < warning_panel_start < recovery_row_start < settings_scroll_end
    ):
        fail("expanded native settings controls are not inside the settings scroll view")
    if (
        "style={styles.settingsScroll}" not in app[
            settings_scroll_start:warning_panel_start
        ]
        or "maxHeight: '90%'" not in app
        or "settingsScroll: {" not in app
        or "flexShrink: 1" not in app
    ):
        fail("settings panel is not bounded to a scrollable viewport")

    restore_worker_start = plugin.find("private fun scheduleAnnotationRestore(")
    restore_worker_end = plugin.find("\n    }\n}", restore_worker_start)
    if restore_worker_start < 0 or restore_worker_end < 0:
        fail("could not isolate annotation restore worker")
    restore_worker = plugin[restore_worker_start:restore_worker_end]
    remaining_check = restore_worker.find("val remaining = documentPids(activityManager)")
    active_abort = restore_worker.find(
        "RTL_READER_NATIVE_BACKUP_RESTORE_ABORTED_ACTIVE_PROCESS"
    )
    document_revalidation = restore_worker.find(
        "val revalidatedBackup = readNativeAnnotationBackup(pdfFile).backup"
    )
    backup_identity_check = restore_worker.find(
        "sameNativeAnnotationBackup(backup, revalidatedBackup)"
    )
    mark_write = restore_worker.find(
        "copyFileAtomically(revalidatedBackup.snapshot, currentMark)"
    )
    if not (
        0 <= remaining_check < active_abort < document_revalidation
        < backup_identity_check < mark_write
    ):
        fail("annotation restore can touch .mark before all document processes exit")
    transactional_cleanup = restore_worker.find(
        "removeNativeAnnotationBackupFiles(pdfFile, revalidatedBackup)",
        mark_write,
    )
    restore_success = restore_worker.find("completion(null)", mark_write)
    if not (0 <= mark_write < transactional_cleanup < restore_success):
        fail("annotation restore cleanup is not transactional before success")

    restore_api_start = plugin.find("fun restoreNativeAnnotationBackup(")
    marker_writer_start = plugin.find(
        "private fun writeNativeSpreadReadOnlyMarker(", restore_api_start
    )
    if restore_api_start < 0 or marker_writer_start < 0:
        fail("could not isolate annotation restore API")
    restore_api = plugin[restore_api_start:marker_writer_start]
    scheduled = restore_api.find("scheduleAnnotationRestore(pdfFile, backup) { error ->")
    completed = restore_api.find(
        'promise.resolve(nativeAnnotationBackupMap(backup, "restored"))'
    )
    failure_toast = restore_api.find("Toast.makeText(")
    if not (0 <= scheduled < completed and 0 <= scheduled < failure_toast):
        fail("annotation restore promise does not report the worker's final outcome")
    if "restore_scheduled" in restore_api:
        fail("annotation restore still reports scheduling as successful recovery")

    restore_handler_start = app.find("const restoreNativeBackup = async () =>")
    open_jump_start = app.find("const openJump = () =>", restore_handler_start)
    if restore_handler_start < 0 or open_jump_start < 0:
        fail("could not isolate Restore snapshot UI handler")
    restore_handler = app[restore_handler_start:open_jump_start]
    restore_completed = restore_handler.find(
        "await ReaderPreferencesModule.restoreNativeAnnotationBackup(filePath)"
    )
    clear_restore_busy_ref = restore_handler.find(
        "nativeSpreadBusyRef.current = false;",
        restore_completed,
    )
    clear_restore_busy_state = restore_handler.find(
        "setNativeSpreadBusy(false);",
        clear_restore_busy_ref,
    )
    restore_close = restore_handler.find("await close();", restore_completed)
    if not (
        0 <= restore_completed < clear_restore_busy_ref
        < clear_restore_busy_state < restore_close
    ):
        fail("successful Restore remains blocked by the native transition busy guard")

    cleanup_start = plugin.find("private fun removeNativeAnnotationBackupFiles(")
    ensure_start = plugin.find("private fun ensureNativeAnnotationBackup(", cleanup_start)
    if cleanup_start < 0 or ensure_start < 0:
        fail("could not isolate transactional annotation backup cleanup")
    cleanup = plugin[cleanup_start:ensure_start]
    stage_snapshot = cleanup.find(
        "Os.rename(backup.snapshot.absolutePath, retiring.absolutePath)"
    )
    delete_manifest = cleanup.find("backup.manifest.delete()")
    rollback_snapshot = cleanup.find(
        "Os.rename(retiring.absolutePath, backup.snapshot.absolutePath)"
    )
    if not (0 <= stage_snapshot < delete_manifest < rollback_snapshot):
        fail("annotation backup retirement can lose its manifest before safe staging")

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
            "PROTECTED_VERIFICATIONS.remove(activity);",
            "activity_resources_released",
            "protectedEditableBackupValid(",
            "startProtectedEditableVerification(",
            'new Thread(() -> {',
            '"SNSpreadBackupVerify"',
            "verification.complete",
            "verification.valid",
            '"protected_backup_verified"',
            "protected_editable_backup_refresh_scheduled",
            '"protected-editable-pilot"',
            "expectedManifestHash.equals(sha256(expectedManifest))",
            'backup.getProperty("documentSha256", "").trim().equals(',
            "protected_editable_document_mtime_changed",
            "protected_editable_backup_verified",
            "cached.backupIdentity.sameAs(backupIdentity)",
            "cached.snapshotIdentity.sameAs(snapshotIdentity)",
            "spreadLassoCanonicalSelection && mode == 1",
            '" preserve_size=" + preserveCanonicalSize',
        ),
        "companion handshake/lifecycle",
    )

    spread_config_start = module.find("private static SpreadConfig spreadConfig(")
    spread_pair_start = module.find(
        "private static SpreadPair spreadPair(",
        spread_config_start,
    )
    if spread_config_start < 0 or spread_pair_start < 0:
        fail("could not isolate spreadConfig")
    spread_config = module[spread_config_start:spread_pair_start]
    if "protectedEditableBackupValid(document, properties)" in spread_config:
        fail("protected backup verification still hashes the PDF on the activity thread")
    if not all(
        marker in spread_config
        for marker in (
            "startProtectedEditableVerification(",
            "verification.complete",
            "verification.valid",
        )
    ):
        fail("spreadConfig does not fail closed while asynchronous verification is pending")

    verification_start = module.find(
        "private static ProtectedVerification startProtectedEditableVerification("
    )
    sha_start = module.find("private static String sha256(", verification_start)
    if verification_start < 0 or sha_start < 0:
        fail("could not isolate asynchronous protected-backup verification")
    verification = module[verification_start:sha_start]
    verification_valid = verification.find("if (valid &&")
    refresh_spread = verification.find(
        "scheduleConfigurationRefresh(",
        verification_valid,
    )
    if not (0 <= verification_valid < refresh_spread):
        fail("successful protected verification does not refresh handwriting geometry")

    cover_start = app.find("const setCoverSeparateValue = async next =>")
    readonly_start = app.find("const setNativeSpreadReadOnly = async", cover_start)
    if cover_start < 0 or readonly_start < 0:
        fail("could not isolate Cover synchronization")
    cover_sync = app[cover_start:readonly_start]
    cover_guard = cover_sync.find("if (nativeSpreadBusyRef.current) return;")
    configured_unavailable = cover_sync.find(
        "nativeSpreadConfigured && !nativeSpreadCompatible"
    )
    unconfigured_local = cover_sync.find("if (!nativeSpreadConfigured)")
    cover_busy = cover_sync.find("nativeSpreadBusyRef.current = true;")
    cover_configure = cover_sync.find("configureNativeSpreadEditable(")
    cover_release = cover_sync.find(
        "nativeSpreadBusyRef.current = false;",
        cover_configure,
    )
    if not (
        0 <= cover_guard < configured_unavailable < unconfigured_local
        < cover_busy < cover_configure < cover_release
    ):
        fail("Cover synchronization is not blocked during native mode transitions")
    if "nativeSpreadConfiguredEditable" not in cover_sync:
        fail("Cover synchronization does not follow the configured marker mode")
    cover_controls_start = app.find(
        "<Text style={styles.settingLabel}>Treat Cover Page Separately</Text>"
    )
    appearance_controls_start = app.find(
        "<Text style={styles.settingLabel}>Spread page sizing</Text>",
        cover_controls_start,
    )
    cover_controls = app[cover_controls_start:appearance_controls_start]
    unavailable_guard = "nativeSpreadConfigured && !nativeSpreadCompatible"
    if cover_controls.count("nativeSpreadBusy ||") != 2:
        fail("both Cover controls must be disabled during native mode transitions")
    if cover_controls.count(unavailable_guard) != 2:
        fail("Cover controls remain enabled for an unavailable configured marker")

    native_controls_start = app.find(
        "<Text style={styles.settingLabel}>Supernote native reader</Text>",
        appearance_controls_start,
    )
    appearance_controls = app[appearance_controls_start:native_controls_start]
    if appearance_controls.count("nativeSpreadBusy ||") != 6:
        fail("all native spread appearance controls must be transition-safe")
    if appearance_controls.count(unavailable_guard) != 6:
        fail("native spread appearance controls ignore unavailable hooks")
    for required in (
        "showSpreadDivider",
        "showNativeSpreadHeader",
        "spreadSizing",
        "setNativeSpreadAppearanceValue",
        "native_fill",
    ):
        if required not in appearance_controls:
            fail(f"native spread appearance controls missing {required}")

    readonly_transition_start = app.find("const setNativeSpreadReadOnly = async")
    editable_transition_start = app.find(
        "const setNativeSpreadEditableMode = async",
        readonly_transition_start,
    )
    readonly_transition = app[readonly_transition_start:editable_transition_start]
    readonly_success = readonly_transition.find(
        "await ReaderPreferencesModule.configureNativeSpreadReadOnly("
    )
    clear_backup = readonly_transition.find(
        "setNativeBackupAvailable(false);",
        readonly_success,
    )
    clear_original = readonly_transition.find(
        "setNativeBackupOriginalMarkPresent(false);",
        readonly_success,
    )
    clear_status = readonly_transition.find(
        "setNativeBackupStatus('missing');",
        readonly_success,
    )
    if not (
        0 <= readonly_success < clear_backup
        and 0 <= readonly_success < clear_original
        and 0 <= readonly_success < clear_status
    ):
        fail("leaving editable mode can leave retired backup state in the UI")

    direction_start = app.find("const setDirectionValue = async next =>")
    view_mode_start = app.find("const setViewModeValue = next =>", direction_start)
    if direction_start < 0 or view_mode_start < 0:
        fail("could not isolate asynchronous reading-direction transition")
    direction_transition = app[direction_start:view_mode_start]
    await_shutdown = direction_transition.find(
        "const disabled = await setNativeSpreadReadOnly(false);"
    )
    shutdown_guard = direction_transition.find("if (!disabled)", await_shutdown)
    commit_ref = direction_transition.find("directionRef.current = next;")
    commit_state = direction_transition.find("setDirection(next);", commit_ref)
    if not (
        0 <= await_shutdown < shutdown_guard < commit_ref < commit_state
    ):
        fail("LTR can commit before protected native mode shuts down successfully")
    if "return true;" not in readonly_transition or "return false;" not in readonly_transition:
        fail("native read-only transition does not report success to direction changes")

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

    require_markers(
        module,
        (
            '"com.supernote.document.document.DocumentActivity$6"',
            '"onDigitalPosition"',
            "handlePenPageActivation(",
            "PEN_ACTIVATION_TARGETS.remove(activity);",
            "pen_page_activation_prearmed",
            "pen_activation_deferred",
            "completePendingPenPageActivation(",
            '"pen_up"',
            "cancelPendingPenPageActivation(",
            '"pen_left_screen"',
            '"sendDisableWriteAreaNotRefreshBitmap"',
            "pen_activation_disable_area_refresh_bypassed",
            "param.setResult(Boolean.TRUE);",
            "PEN_ACTIVATION_MARK_PRIMING",
            "pen_activation_mark_bitmap_suppressed",
            "pen_activation_mark_primed",
            "SN_SPREAD_PROBE pen page activation",
            'applySpreadMarkGeometry(',
            '"pen_page_activation"',
            "int targetMarkPage = targetPage + 1;",
            "capturePendingPenActivationTrails(",
            "normalizePendingPenTrail(",
            "pen_activation_native_save_bypassed",
            "persistPendingPenActivationTrails(",
            "PEN_ACTIVATION_STALE_SAVE_PENDING",
            "PEN_ACTIVATION_STALE_SAVE_SCOPE",
            "pen_activation_stale_save_armed",
            "pen_activation_stale_save_bypassed",
            "PENDING_PAGE_EDIT_HISTORY",
            "PAGE_EDIT_HISTORY_ACTIONS",
            "page_edit_history_registered",
            "page_edit_history_applied",
            "receiveTrials() fetches the completed native trail",
            '"modifyPageTrailsFromFile"',
            'XposedHelpers.callMethod(',
            '"get_erase_line_trail_num"',
            "PEN_ACTIVATION_ERASERS",
            "eraserIntersectsTrail(",
            "process != 0 && process != 6 && process != 7",
            '"pen_activation_eraser_captured',
            "normalizedTrailMatchPoints(",
            "hasPendingPenActivationEdits(activity)",
            '"pen_activation_aborted reason=persistence_failed target="',
            'cancelPendingPenPageActivation(activity, "persistence_failed")',
            "matchingTrailPoints(points, candidatePoints, 6)",
            "matchingTrailInkAttributes(existing, candidate)",
            'matchingTrailValue(existing, candidate, "get_pressures")',
            'matchingTrailValue(existing, candidate, "get_angles")',
            'matchingTrailValue(existing, candidate, "get_flag_draw")',
            'matchingTrailValue(existing, candidate, "get_timestamp")',
        ),
        "inactive-page pen activation",
    )

    transaction_markers = (
        "private static final class PageActivationTransaction",
        "PAGE_ACTIVATION_TRANSACTIONS",
        "PAGE_ACTIVATION_BLOCKED_TOUCHES",
        "PAGE_ACTIVATION_HISTORY_BLOCKED",
        "ACTIVE_PAGE_STROKE_TERMINAL_CLEANUP",
        "PEN_CONTACT_START_PAGES",
        "new ConcurrentHashMap<>()",
        "volatile boolean triggerContactObserved",
        "volatile boolean triggerPenLifted",
        "volatile boolean geometryCommitted",
        "PAGE_ACTIVATION_COUNTER.incrementAndGet()",
        "interceptPenPageActivation(",
        "beginPageActivationTransaction(",
        "requestPageActivationLoad(",
        "schedulePageActivationTimeout(",
        "commitPageActivationGeometry(",
        "markPageActivationPenLifted(",
        "restoreTransactionalActivePageGeometry(",
        "finishPageActivationTransaction(",
        "abortPageActivationTransaction(",
        "failClosedPageActivation(",
        '"page_activation_transaction_started"',
        '"page_activation_transaction_committed"',
        '"page_activation_transaction_aborted"',
        '"trigger_gesture_discarded".equals(reason)',
        '"page_activation_status_refresh_failed id="',
        '"SN_SPREAD_PROBE discard activation gesture"',
        '"page_activation_trigger_input_blocked current="',
        '"page_activation_pen_input_blocked id="',
        '"page_activation_pen_input_blocked reason=native_chrome"',
        '"page_activation_pen_ignored_native_chrome point="',
        '"page_activation_cross_page_point_blocked current="',
        '"page_activation_cross_page_terminal_preserved current="',
        '"page_activation_active_stroke_terminal_preserved"',
        '"page_activation_ignored_cross_page_stroke current="',
        '"page_activation_rejected reason=pen_contact_active"',
        '"page_activation_ui_input_blocked id="',
        '"page_activation_history_blocked id="',
        '"RTL SPREAD: page switch failed - writing disabled"',
    )
    require_markers(
        module,
        transaction_markers,
        "transactional single-active-page ownership",
    )

    digital_position_start = module.find(
        '"com.supernote.document.document.DocumentActivity$6"'
    )
    dispatch_touch_start = module.find('"dispatchTouchEvent",')
    if dispatch_touch_start < 0 or digital_position_start < 0:
        fail("could not isolate transactional UI-input guard")
    dispatch_touch_hook = module[dispatch_touch_start:digital_position_start]
    dispatch_trace = dispatch_touch_hook.find("traceTouchEvent(activity, event);")
    dispatch_block = dispatch_touch_hook.find(
        "blockPageActivationUiInput(activity, event)", dispatch_trace
    )
    dispatch_consume = dispatch_touch_hook.find(
        "param.setResult(true);", dispatch_block
    )
    dispatch_return = dispatch_touch_hook.find("return;", dispatch_consume)
    dispatch_config = dispatch_touch_hook.find(
        "SpreadConfig config = spreadConfig(activity);", dispatch_return
    )
    if not (
        0 <= dispatch_trace < dispatch_block < dispatch_consume
        < dispatch_return < dispatch_config
    ):
        fail(
            "touch input is not consumed before native chrome and page "
            "controls can run during an ownership transfer"
        )
    digital_state_start = module.find(
        '"onDigital",', digital_position_start
    )
    if digital_position_start < 0 or digital_state_start < 0:
        fail("could not isolate native pen-position interception hook")
    digital_position_hook = module[digital_position_start:digital_state_start]
    before_native_callback = digital_position_hook.find(
        "protected void beforeHookedMethod"
    )
    active_stroke_terminal = digital_position_hook.find(
        "boolean completingActivePageStroke = pressure == 0",
        before_native_callback,
    )
    intercept_input = digital_position_hook.find(
        "interceptPenPageActivation(", active_stroke_terminal
    )
    discard_input = digital_position_hook.find(
        "param.setResult(null);", intercept_input
    )
    preserve_terminal = digital_position_hook.find(
        "if (completingActivePageStroke)", discard_input
    )
    schedule_activation = digital_position_hook.find(
        "handlePenPageActivation(", preserve_terminal
    )
    if not (
        0 <= before_native_callback < active_stroke_terminal
        < intercept_input < discard_input < preserve_terminal
        < schedule_activation
    ):
        fail(
            "inactive-page pen input must be discarded before Supernote's "
            "native callback runs, then schedule the ownership transaction"
        )
    pressure_zero_cleanup = digital_position_hook.find(
        'if (pressure == 0 && !completingActivePageStroke)',
        schedule_activation,
    )
    pressure_zero_clear = digital_position_hook.find(
        'clearPenContactStartPage(', pressure_zero_cleanup
    )
    if not 0 <= schedule_activation < pressure_zero_cleanup < pressure_zero_clear:
        fail(
            "a normal pressure-zero pen frame does not clear the active-stroke "
            "start-page guard"
        )
    terminal_cleanup_marked = digital_position_hook.find(
        "ACTIVE_PAGE_STROKE_TERMINAL_CLEANUP.set(activity)",
        preserve_terminal,
    )
    position_after_hook = digital_position_hook.find(
        "protected void afterHookedMethod", pressure_zero_clear
    )
    terminal_cleanup_read = digital_position_hook.find(
        "ACTIVE_PAGE_STROKE_TERMINAL_CLEANUP.get()", position_after_hook
    )
    terminal_cleanup_clear = digital_position_hook.find(
        "clearPenContactStartPage(", terminal_cleanup_read
    )
    if not (
        0 <= preserve_terminal < terminal_cleanup_marked
        < pressure_zero_cleanup < position_after_hook
        < terminal_cleanup_read < terminal_cleanup_clear
    ):
        fail(
            "cross-divider pen-up clears its contact guard before the native "
            "source-page callback completes"
        )

    pen_activation_start = module.find(
        "private static void handlePenPageActivation("
    )
    pending_target_start = module.find(
        "private static Integer pendingPageActivationTarget(",
        pen_activation_start,
    )
    if pen_activation_start < 0 or pending_target_start < 0:
        fail("could not isolate live pen page-activation routing")
    live_pen_activation = module[pen_activation_start:pending_target_start]
    if "beginPageActivationTransaction(" not in live_pen_activation:
        fail("live inactive-page pen input does not start an ownership transaction")
    forbidden_live_merge_markers = (
        "activateDocumentPageFromPen(",
        "PEN_ACTIVATION_TARGETS.put(",
        "capturePendingPenActivationTrails(",
        "persistPendingPenActivationTrails(",
    )
    leaked_live_markers = [
        marker
        for marker in forbidden_live_merge_markers
        if marker in live_pen_activation
    ]
    if leaked_live_markers:
        fail(
            "live pen activation still reaches the experimental inactive-page "
            f"merge path: {leaked_live_markers}"
        )
    chrome_guard = live_pen_activation.find(
        "isNativeChromeTouch(activity, requestedY)"
    )
    target_mapping = live_pen_activation.find("int requestedTarget = pageAt(")
    if not 0 <= chrome_guard < target_mapping:
        fail("native pen chrome must be excluded before inactive-page mapping")

    intercept_method_start = module.find(
        "private static boolean interceptPenPageActivation("
    )
    pending_target_after_intercept = module.find(
        "private static Integer pendingPageActivationTarget(",
        intercept_method_start,
    )
    if intercept_method_start < 0 or pending_target_after_intercept < 0:
        fail("could not isolate synchronous pen interception")
    intercept_method = module[
        intercept_method_start:pending_target_after_intercept
    ]
    intercept_chrome = intercept_method.find(
        "isNativeChromeTouch(activity, y)"
    )
    intercept_chrome_discard = intercept_method.find(
        "return true;", intercept_chrome
    )
    intercept_page_mapping = intercept_method.find(
        "int target = pageAt(activity, x, y);",
        intercept_chrome_discard,
    )
    if not (
        0 <= intercept_chrome < intercept_chrome_discard
        < intercept_page_mapping
    ):
        fail(
            "native chrome must discard the parallel low-latency pen point "
            "without scheduling page activation"
        )
    crossing_guard = intercept_method.find(
        "contactStartPage.intValue() == current"
    )
    crossing_pressure_guard = intercept_method.find(
        "if (pressure > 0)", crossing_guard
    )
    crossing_discard = intercept_method.find("return true;", crossing_guard)
    terminal_pressure_guard = intercept_method.find(
        "if (pressure == 0)", crossing_discard
    )
    terminal_preserved = intercept_method.find(
        "return false;", terminal_pressure_guard
    )
    if not (
        0 <= crossing_guard < crossing_pressure_guard < crossing_discard
        < terminal_pressure_guard < terminal_preserved
    ):
        fail(
            "a stroke begun on the active page is not kept on that page "
            "through its cross-divider terminal frame"
        )

    ui_block_start = module.find(
        "private static boolean blockPageActivationUiInput("
    )
    activation_touch_start = module.find(
        "private static boolean handlePageActivationTouch(", ui_block_start
    )
    native_chrome_start = module.find(
        "private static boolean isNativeChromeTouch(", activation_touch_start
    )
    if ui_block_start < 0 or activation_touch_start < 0 or native_chrome_start < 0:
        fail("could not isolate page-activation UI-input blocking")
    ui_block_method = module[ui_block_start:activation_touch_start]
    require_markers(
        ui_block_method,
        (
            "PAGE_ACTIVATION_BLOCKED_TOUCHES.get(activity)",
            "PAGE_ACTIVATION_TRANSACTIONS.get(activity)",
            "action == MotionEvent.ACTION_HOVER_EXIT",
            "action == MotionEvent.ACTION_DOWN",
            "action == MotionEvent.ACTION_MOVE",
            "PAGE_ACTIVATION_BLOCKED_TOUCHES.put(activity, Boolean.TRUE)",
            "PAGE_ACTIVATION_BLOCKED_TOUCHES.remove(activity)",
            '"page_activation_ui_input_blocked id="',
            "return true;",
        ),
        "transactional UI-input blocking",
    )
    activation_touch_method = module[activation_touch_start:native_chrome_start]
    touch_transaction = activation_touch_method.find(
        "PageActivationTransaction transaction ="
    )
    touch_pending_guard = activation_touch_method.find(
        "if (transaction != null)", touch_transaction
    )
    touch_pending_discard = activation_touch_method.find(
        "return true;", touch_pending_guard
    )
    if not 0 <= touch_transaction < touch_pending_guard < touch_pending_discard:
        fail("finger input can reach native controls during an ownership transfer")
    if "transaction != null && !isNativeChromeTouch" in activation_touch_method:
        fail("native chrome remains exempt from ownership-transfer input blocking")

    digital_lift_start = module.find('"onDigital",', digital_position_start)
    digital_lift_end = module.find(
        "/*", digital_lift_start + len('"onDigital",')
    )
    if digital_lift_start < 0 or digital_lift_end < 0:
        fail("could not isolate pen-lift ownership cleanup")
    digital_lift_hook = module[digital_lift_start:digital_lift_end]
    lift_transaction = digital_lift_hook.find("markPageActivationPenLifted(")
    lift_contact_cleanup = digital_lift_hook.find(
        "clearPenContactStartPage(", lift_transaction
    )
    if not 0 <= lift_transaction < lift_contact_cleanup:
        fail("pen-up does not clear the active-stroke start-page guard")

    transaction_start = module.find(
        "private static boolean beginPageActivationTransaction("
    )
    request_load_start = module.find(
        "private static void requestPageActivationLoad(", transaction_start
    )
    if transaction_start < 0 or request_load_start < 0:
        fail("could not isolate page-activation transaction start")
    transaction_start_method = module[transaction_start:request_load_start]
    active_pen_guard = transaction_start_method.find(
        "!triggerContactObserved"
    )
    active_pen_identity = transaction_start_method.find(
        "PEN_CONTACT_START_PAGES.get(activity) != null",
        active_pen_guard,
    )
    transaction_lookup = transaction_start_method.find(
        "PageActivationTransaction currentTransaction =",
        active_pen_identity,
    )
    if not 0 <= active_pen_guard < active_pen_identity < transaction_lookup:
        fail(
            "finger/page-turn activation can overlap a native pen contact"
        )
    source_save = transaction_start_method.find(
        'XposedHelpers.callMethod(presenter, "saveTrails", false, false);'
    )
    writer_disable = transaction_start_method.find(
        '"SN_SPREAD_PROBE transactional page activation"', source_save
    )
    publish_transaction = transaction_start_method.find(
        "PAGE_ACTIVATION_TRANSACTIONS.put(activity, transaction);",
        writer_disable,
    )
    request_target_load = transaction_start_method.find(
        "requestPageActivationLoad(activity, transaction, viewModel);",
        publish_transaction,
    )
    if not (
        0 <= source_save < writer_disable < publish_transaction
        < request_target_load
    ):
        fail(
            "ownership transfer must save the source, disable writing, publish "
            "the exact transaction, and only then load the target"
        )

    commit_start = module.find(
        "private static boolean commitPageActivationGeometry("
    )
    pen_lift_start = module.find(
        "private static void markPageActivationPenLifted(", commit_start
    )
    if commit_start < 0 or pen_lift_start < 0:
        fail("could not isolate transactional geometry commit")
    commit_method = module[commit_start:pen_lift_start]
    reader_identity = commit_method.find(
        "currentPage != transaction.targetPage"
    )
    presenter_identity = commit_method.find(
        "presenterMarkPage != transaction.targetPage + 1",
        reader_identity,
    )
    commit_state = commit_method.find(
        "transaction.geometryCommitted = true;", presenter_identity
    )
    discard_contact = commit_method.find(
        "transaction.triggerContactObserved", commit_state
    )
    finish_commit = commit_method.find(
        "finishPageActivationTransaction(", discard_contact
    )
    if not (
        0 <= reader_identity < presenter_identity < commit_state
        < discard_contact < finish_commit
    ):
        fail(
            "ownership must commit only after reader and presenter identities "
            "match the target and the triggering contact is fail-closed"
        )

    receive_hook_start_transactional = module.find('"receiveTrials",')
    receive_hook_end_transactional = module.find(
        '"areaSelectionTransition",', receive_hook_start_transactional
    )
    save_hook_start_transactional = module.find('"saveTrails",')
    save_hook_end_transactional = module.find(
        '"receiveTrials",', save_hook_start_transactional
    )
    if (
        receive_hook_start_transactional < 0
        or receive_hook_end_transactional < 0
        or save_hook_start_transactional < 0
        or save_hook_end_transactional < 0
    ):
        fail("could not isolate transactional writer guards")
    transaction_receive_hook = module[
        receive_hook_start_transactional:receive_hook_end_transactional
    ]
    transaction_save_hook = module[
        save_hook_start_transactional:save_hook_end_transactional
    ]
    require_markers(
        transaction_receive_hook,
        (
            "shouldBlockPageActivationGesture(activity)",
            "param.setResult(null);",
            "markPageActivationPenLifted(",
            '"page_activation_trigger_gesture_discarded"',
        ),
        "transactional receiveTrials guard",
    )
    require_markers(
        transaction_save_hook,
        (
            "shouldBlockPageActivationGesture(activity)",
            "param.setResult(null);",
            '"page_activation_save_blocked id="',
        ),
        "transactional saveTrails guard",
    )

    receive_hook_start = module.find(
        '"receiveTrials",',
        module.find("pen_activation_native_save_bypassed"),
    )
    receive_hook_end = module.find(
        '"areaSelectionTransition",',
        receive_hook_start,
    )
    if receive_hook_start < 0 or receive_hook_end < 0:
        fail("could not isolate inactive-page receiveTrials completion hook")
    receive_hook = module[receive_hook_start:receive_hook_end]
    receive_activity = receive_hook.find("Activity activity = activeActivity;")
    receive_contact_cleanup = receive_hook.find(
        "clearPenContactStartPage(", receive_activity
    )
    receive_blocked_branch = receive_hook.find(
        "if (activationGestureBlocked)", receive_contact_cleanup
    )
    if not (
        0 <= receive_activity < receive_contact_cleanup
        < receive_blocked_branch
    ):
        fail(
            "receiveTrials completion does not clear the active-stroke "
            "start-page guard before either completion path returns"
        )
    persist_before_completion = receive_hook.find(
        "persistPendingPenActivationTrails("
    )
    post_completion = receive_hook.find("activity.runOnUiThread(")
    completion_guard = receive_hook.find(
        "completePendingPenPageActivation("
    )
    if not (
        0 <= persist_before_completion < post_completion < completion_guard
    ):
        fail(
            "receiveTrials must persist inactive-page edits before posting "
            "the fail-closed activation completion"
        )

    save_hook_start = module.find('"saveTrails",')
    save_hook_end = module.find('"receiveTrials",', save_hook_start)
    if save_hook_start < 0 or save_hook_end < 0:
        fail("could not isolate inactive-page saveTrails hook")
    save_hook = module[save_hook_start:save_hook_end]
    explicit_save_guard = save_hook.find(
        "boolean explicitCanonicalSave = Boolean.TRUE.equals("
    )
    stale_save_guard = save_hook.find(
        "boolean staleActivationSave = activity != null"
    )
    stale_scope_check = save_hook.find(
        "PEN_ACTIVATION_STALE_SAVE_SCOPE.get()",
        stale_save_guard,
    )
    post_persist_bypass = save_hook.find(
        "if (staleActivationSave && !explicitCanonicalSave)"
    )
    bypass_consumption = save_hook.find(
        "PEN_ACTIVATION_STALE_SAVE_PENDING.remove(activity)",
        post_persist_bypass,
    )
    explicit_save_preserved = save_hook.find(
        "pen_activation_stale_save_preserved"
    )
    pending_capture = save_hook.find(
        "List<Object> captured = activity == null"
    )
    if not (
        0 <= explicit_save_guard < stale_save_guard < stale_scope_check
        < post_persist_bypass
        < bypass_consumption < explicit_save_preserved < pending_capture
    ):
        fail(
            "only the deferred loadPage stale save may consume the inactive-"
            "eraser guard; explicit canonical and ordinary saves must remain "
            "outside that scope"
        )

    persist_start = module.find(
        "private static void persistPendingPenActivationTrails("
    )
    match_start = module.find(
        "private static boolean matchingTrailExists(", persist_start
    )
    if persist_start < 0 or match_start < 0:
        fail("could not isolate inactive-page persistence")
    persist_method = module[persist_start:match_start]
    require_markers(
        persist_method,
        (
            "armPostActivationSaveBypass && erased > 0",
            "PEN_ACTIVATION_STALE_SAVE_PENDING.put(",
            "Boolean.TRUE",
            '" scope=deferred_load_page"',
        ),
        "inactive-page eraser stale-save guard",
    )
    if "POST_ACTIVATION_SAVE_BYPASS_MS" in module:
        fail("inactive-page eraser still uses a broad time-window save bypass")

    require_markers(
        module,
        (
            "private static final class PageEditHistory",
            "registerPendingPageEditHistory(",
            "applyPageEditHistory(",
            'getDeclaredField("isTrail")',
            "isTrailField.setBoolean(action, false)",
            'XposedHelpers.callMethod(stack, "appendTrail")',
            'String listField = undo ? "undoList" : "redoList"',
            'XposedHelpers.callMethod(stack, actionName)',
            '"modifyPageTrailsFromFile"',
            'new ArrayList<>(snapshot)',
            '"loadHandWrite"',
        ),
        "inactive-page native undo and redo integration",
    )

    require_markers(
        module,
        (
            "REPLACE_ACTIVE_INK_MODES",
            "CANONICAL_ONLY_INK_MODES",
            "FORCE_CANONICAL_ACTIVE_INK",
            "EXPLICIT_CANONICAL_TRAIL_SAVE",
            'setReplaceActiveInkMode(',
            '"area_selection"',
            '"eraser:" + eraserType',
            '"pen"',
            'new String[] {"undo", "redo"}',
            'ink_composition_force_canonical reason=',
            'undo_redo_saved_before_canonical_reload',
            '"loadHandWrite",\n                                    markPage',
            "boolean replaceActiveSlot",
            "boolean canonicalOnly",
            "readOnly || canonicalOnly",
            'committed_ink_canonical_only reason=eraser',
            "persistActiveEraserBeforeCanonicalRefresh(",
            'active_eraser_saved_before_canonical_refresh',
            'active_eraser_canonical_reloaded',
            '"active_eraser_canonical_reload"',
            "saveTrailsForCanonicalReload(",
            '"undo_redo:" + mutationName',
            '"active_eraser"',
            'explicit_canonical_trail_save reason=',
            "if (replaceActiveSlot && activeDestination != null)",
            '" mode=" + (replaceActiveSlot ? "replace" : "add")',
        ),
        "settled ink composition",
    )

    active_eraser_start = module.find(
        "private static void persistActiveEraserBeforeCanonicalRefresh("
    )
    canonical_save_start = module.find(
        "private static void saveTrailsForCanonicalReload(",
        active_eraser_start,
    )
    if active_eraser_start < 0 or canonical_save_start < 0:
        fail("could not isolate active-page eraser canonical refresh")
    active_eraser_refresh = module[active_eraser_start:canonical_save_start]
    eraser_save = active_eraser_refresh.find("saveTrailsForCanonicalReload(")
    eraser_reload = active_eraser_refresh.find('"loadHandWrite"', eraser_save)
    eraser_trace = active_eraser_refresh.find(
        '"active_eraser_canonical_reload"', eraser_reload
    )
    if not 0 <= eraser_save < eraser_reload < eraser_trace:
        fail(
            "active-page eraser must save canonical trails before reloading "
            "and tracing the settled bitmap"
        )

    combined_start = module.find(
        "private static Bitmap renderCombinedCommittedInk("
    )
    destination_start = module.find(
        "private static RectF activePageDestination(", combined_start
    )
    if combined_start < 0 or destination_start < 0:
        fail("could not isolate settled ink composition")
    combined = module[combined_start:destination_start]
    clear_slot = combined.find("PorterDuff.Mode.CLEAR")
    replacement_guard = combined.find(
        "if (replaceActiveSlot && activeDestination != null)"
    )
    draw_active = combined.find("canvas.drawBitmap(active, 0.0f, 0.0f, paint)")
    if not 0 <= replacement_guard < clear_slot < draw_active:
        fail("normal pen commits can still clear previously settled active-page ink")

    trail_match_start = module.find("private static boolean matchingTrailExists(")
    eraser_match_start = module.find(
        "private static boolean eraserIntersectsTrail(", trail_match_start
    )
    if trail_match_start < 0 or eraser_match_start < 0:
        fail("could not isolate inactive-page trail deduplication")
    trail_match = module[trail_match_start:eraser_match_start]
    require_markers(
        trail_match,
        (
            "for (int index = 0; index < existing.size(); index++)",
            "matchingTrailPoints(points, candidatePoints, 6)",
            "matchingTrailInkAttributes(existing, candidate)",
            '"get_pen_color"',
            '"get_m_thickness"',
            '"get_walcom_emr_type"',
            '"get_pressures"',
            '"get_angles"',
            '"get_flag_draw"',
            '"get_timestamp"',
        ),
        "full inactive-page stroke identity",
    )
    if "candidateFirst" in trail_match or "candidateLast" in trail_match:
        fail("inactive-page deduplication still accepts endpoint-only identity")

    completion_start = module.find(
        "private static void completePendingPenPageActivation("
    )
    capture_start = module.find(
        "private static void capturePendingPenActivationTrails(",
        completion_start,
    )
    if completion_start < 0 or capture_start < 0:
        fail("could not isolate inactive-page completion handling")
    completion = module[completion_start:capture_start]
    failure_guard = completion.find("hasPendingPenActivationEdits(activity)")
    abort_activation = completion.find(
        'cancelPendingPenPageActivation(activity, "persistence_failed")',
        failure_guard,
    )
    load_target = completion.find('"loadPage"', abort_activation)
    if not 0 <= failure_guard < abort_activation < load_target:
        fail("failed inactive-page persistence can still activate the target page")
    if "PEN_ACTIVATION_TRAILS.remove(activity)" in completion:
        fail("completion cleanup still silently discards failed inactive-page edits")
    stale_scope_set = completion.find(
        "PEN_ACTIVATION_STALE_SAVE_SCOPE.set(Boolean.TRUE)"
    )
    stale_scope_remove = completion.find(
        "PEN_ACTIVATION_STALE_SAVE_SCOPE.remove()",
        load_target,
    )
    stale_guard_cleanup = completion.find(
        "PEN_ACTIVATION_STALE_SAVE_PENDING.remove(activity)",
        stale_scope_remove,
    )
    if not (
        0 <= stale_scope_set < load_target < stale_scope_remove
        < stale_guard_cleanup
    ):
        fail(
            "inactive-page stale-save suppression must be scoped exactly "
            "around the deferred loadPage call"
        )

    require_markers(
        module,
        (
            "configuration_refresh_waiting_for_layout",
            "configuration_refresh_native_reload",
            'XposedHelpers.callMethod(viewModel, "reloadPage")',
        ),
        "portrait rotation refresh",
    )

    require_markers(
        module,
        (
            "nativeTrimmingRect(",
            '"com.supernote.document.utils.TrimmingUtil"',
            '"getTrimmingRect"',
            "trimmingRect.left / horizontalMargin",
            "trimmingRect.top / verticalMargin",
            "left + sourceWidth * scale",
            "top + sourceHeight * scale",
            '"native_fill_trim_detected page="',
        ),
        "native-reader-equivalent spread trimming",
    )

    require_markers(
        module,
        (
            "NATIVE_TOP_CHROME_TOUCH_EXCLUSION_PX",
            "NATIVE_BOTTOM_CHROME_TOUCH_EXCLUSION_PX",
            "isNativeChromeTouch(activity, event.getY())",
            "activation_touch_ignored_native_chrome",
            "activation_touch_cancelled_native_chrome",
        ),
        "native chrome activation exclusion",
    )

    require_markers(
        module,
        (
            "TRACE_CONTROL_ACTION",
            "TRACE_CONTROL_PERMISSION",
            '"android.permission.DUMP"',
            "registerTraceControlReceiver(activeActivity)",
            '"trace_session_started"',
            '"pen_contact_started"',
            '"annotation_boundary"',
            '"save_trails_before"',
            '"save_trails_after"',
            '"receive_trials_before"',
            '"receive_trials_after"',
            '"modify_page_trails_started"',
            '"modify_page_trails_finished"',
            '"mark_snapshot"',
            '"orderedFingerprint"',
            "FileObserver.CLOSE_WRITE",
            "TRACE_MAX_SNAPSHOT_BYTES",
            "TRACE_SNAPSHOT_DEBOUNCE_MS",
            "ScheduledExecutorService",
            "snapshotExecutor.schedule(",
            "pendingSnapshot.cancel(false)",
            "scheduleTraceWorkerTask(",
            "scheduleTraceMarkSnapshot(",
            "lastSnapshotIdentity",
            "traceLogMessage(message)",
        ),
        "opt-in annotation transaction tracing",
    )

    observer_start = module.find(
        "private static void startTraceMarkObserver("
    )
    touch_trace_start = module.find(
        "private static void traceTouchEvent(", observer_start
    )
    if observer_start < 0 or touch_trace_start < 0:
        fail("could not isolate mark observer trace scheduling")
    mark_observer = module[observer_start:touch_trace_start]
    if "scheduleTraceMarkSnapshot(" not in mark_observer:
        fail("mark observer does not use the serialized snapshot worker")
    if "Looper.getMainLooper()" in mark_observer:
        fail("mark observer still posts snapshot hashing onto the UI thread")

    trace_start = module.find("private static void startAnnotationTrace(")
    checkpoint_start = module.find(
        "private static void checkpointAnnotationTrace(", trace_start
    )
    if trace_start < 0 or checkpoint_start < 0:
        fail("could not isolate trace startup failure cleanup")
    require_markers(
        module[trace_start:checkpoint_start],
        (
            "failedObserver.stopWatching()",
            "started.pendingSnapshot.cancel(false)",
            "started.snapshotExecutor.shutdownNow()",
            "started.eventExecutor.shutdownNow()",
            'new File(\n                        started.rootDirectory,\n                        "active.txt"',
            "active.isFile() && !active.delete()",
        ),
        "failed trace startup cleanup",
    )
    trace_startup = module[trace_start:checkpoint_start]
    if '"last.txt"' in trace_startup:
        fail("trace startup publishes last.txt before finalization")

    finish_start = module.find("private static void finishTraceSession(")
    observer_start = module.find(
        "private static void startTraceMarkObserver(", finish_start
    )
    if finish_start < 0 or observer_start < 0:
        fail("could not isolate completed trace pointer publication")
    finish_trace = module[finish_start:observer_start]
    if module.count('"last.txt"') != 1:
        fail("last.txt must be published only by completed trace finalization")
    publish_last = finish_trace.find(
        'new File(session.rootDirectory, "last.txt")'
    )
    cleanup_finally = finish_trace.find("} finally {", publish_last)
    remove_active = finish_trace.find(
        "if (active.isFile() && !active.delete())", cleanup_finally
    )
    if not 0 <= publish_last < cleanup_finally < remove_active:
        fail("last.txt is not published before active.txt is removed")
    require_markers(
        finish_trace,
        (
            "boolean requestedCompleted",
            "boolean eventLogComplete = drainTraceEventWriter(session)",
            "boolean completed = requestedCompleted && eventLogComplete",
            'new File(\n                    session.rootDirectory,\n                    "incomplete.txt"',
            "if (completed)",
            "if (incomplete.isFile() && !incomplete.delete())",
            "writeTraceText(incomplete, session.id",
            '"publication-failed.txt"',
            "preserveTracePublicationFailure(",
            "} finally {",
        ),
        "completed-versus-incomplete trace pointer publication",
    )
    require_markers(
        finish_trace,
        (
            "private static boolean drainTraceEventWriter(",
            "session.eventExecutor.shutdown()",
            "session.eventExecutor.awaitTermination(",
            "session.eventWriteFailure",
            "private static void preserveTracePublicationFailure(",
            "active.renameTo(failed)",
            "writeTraceText(failed, session.id",
        ),
        "event-writer drain and explicit publication-failure state",
    )

    stable_final_start = module.find(
        "private static boolean captureStableFinalTraceMarkSnapshot("
    )
    snapshot_start = module.find(
        "private static boolean captureTraceMarkSnapshot(", stable_final_start
    )
    if stable_final_start < 0 or snapshot_start < 0:
        fail("could not isolate stable final trace snapshot retry")
    stable_final = module[stable_final_start:snapshot_start]
    require_markers(
        stable_final,
        (
            "TRACE_FINAL_SNAPSHOT_ATTEMPTS",
            "captureTraceMarkSnapshot(",
            "return true",
            "SystemClock.sleep(TRACE_FINAL_SNAPSHOT_RETRY_MS)",
            "return false",
        ),
        "stable final trace snapshot retry",
    )
    snapshot_capture_end = module.find(
        "private static void traceEvent(", snapshot_start
    )
    if snapshot_capture_end < 0:
        fail("could not isolate final snapshot source verification")
    snapshot_capture = module[snapshot_start:snapshot_capture_end]
    published_source = snapshot_capture.find(
        "FileIdentity publishedSource = FileIdentity.capture(mark);"
    )
    verify_snapshot = snapshot_capture.find(
        "String publishedHash = sha256(snapshot);", published_source
    )
    verified_source = snapshot_capture.find(
        "FileIdentity verifiedSource = FileIdentity.capture(mark);",
        verify_snapshot,
    )
    compare_verified = snapshot_capture.find(
        "!publishedSource.sameAs(verifiedSource)", verified_source
    )
    accepted_source = snapshot_capture.find(
        "FileIdentity acceptedSource = FileIdentity.capture(mark);",
        compare_verified,
    )
    compare_accepted = snapshot_capture.find(
        "!verifiedSource.sameAs(acceptedSource)", accepted_source
    )
    accepted_state = snapshot_capture.find(
        "expected.lastSnapshotIdentity = acceptedSource;",
        compare_accepted,
    )
    snapshot_event = snapshot_capture.find(
        '"mark_snapshot",', accepted_state
    )
    if not (
        0 <= published_source < verify_snapshot < verified_source
        < compare_verified < accepted_source < compare_accepted
        < accepted_state < snapshot_event
    ):
        fail(
            "snapshot publication does not recheck the source after "
            "verifying the copied snapshot"
        )
    missing_before = snapshot_capture.find(
        "FileIdentity missingBefore = FileIdentity.capture(mark);"
    )
    missing_after = snapshot_capture.find(
        "FileIdentity missingAfter = FileIdentity.capture(mark);",
        missing_before,
    )
    missing_compare = snapshot_capture.find(
        "!missingBefore.sameAs(missingAfter)", missing_after
    )
    missing_accept = snapshot_capture.find(
        'expected.lastSnapshotHash = "missing";', missing_compare
    )
    missing_event = snapshot_capture.find(
        '"mark_snapshot",', missing_accept
    )
    unchanged_branch = snapshot_capture.find("if (unchanged)")
    unchanged_verified = snapshot_capture.find(
        "FileIdentity unchangedVerified = FileIdentity.capture(mark);",
        unchanged_branch,
    )
    unchanged_compare = snapshot_capture.find(
        "!after.sameAs(unchangedVerified)", unchanged_verified
    )
    unchanged_accept = snapshot_capture.find(
        "expected.lastSnapshotIdentity = unchangedVerified;",
        unchanged_compare,
    )
    unchanged_event = snapshot_capture.find(
        '"mark_snapshot_unchanged"', unchanged_accept
    )
    if not (
        0 <= missing_before < missing_after < missing_compare
        < missing_accept < missing_event
        and 0 <= unchanged_branch < unchanged_verified
        < unchanged_compare < unchanged_accept < unchanged_event
    ):
        fail(
            "missing or unchanged final snapshots bypass their final "
            "source-identity recheck"
        )
    stop_session_start = module.find(
        "private static void stopAnnotationTrace("
    )
    if stop_session_start < 0 or stable_final_start < stop_session_start:
        fail("could not isolate final snapshot completion gating")
    stop_session = module[stop_session_start:stable_final_start]
    require_markers(
        stop_session,
        (
            "captureStableFinalTraceMarkSnapshot(session)",
            '"trace_session_incomplete"',
            '"final_snapshot_unstable"',
            "finishTraceSession(\n                                session,",
            "false",
            '"trace_session_stopped"',
            "true",
        ),
        "stable snapshot requirement before completed trace publication",
    )

    boundary_start = module.find(
        "private static void traceAnnotationBoundary("
    )
    capture_trails_start = module.find(
        "private static TraceTrailListCapture captureTraceTrailList(",
        boundary_start,
    )
    if boundary_start < 0 or capture_trails_start < 0:
        fail("could not isolate annotation-boundary trace collection")
    boundary = module[boundary_start:capture_trails_start]
    if "sha256(mark)" in boundary:
        fail("annotation boundaries still hash the .mark file on the UI thread")
    if "scheduleTraceMarkSnapshot(" not in boundary:
        fail("annotation boundary snapshots do not use the background worker")
    trail_capture = boundary.find(
        "final TraceTrailListCapture fileTrails = captureTraceTrailList("
    )
    worker_submit = boundary.find("scheduleTraceWorkerTask(", trail_capture)
    worker_run = boundary.find("public void run()", worker_submit)
    trail_serialize = boundary.find("traceTrailList(fileTrails)", worker_run)
    if not 0 <= trail_capture < worker_submit < worker_run < trail_serialize:
        fail("annotation trail serialization is not confined to the trace worker")
    require_markers(
        boundary,
        (
            "traceLastSnapshotHash(session, mark)",
            '"trace_stop".equals(boundary)',
            '"markSha256"',
            "markHash",
        ),
        "identity-aware annotation boundary hash and final boundary queueing",
    )

    trace_list_start = module.find(
        "private static JSONObject traceTrailList(", capture_trails_start
    )
    if trace_list_start < 0:
        fail("could not isolate immutable trace trail capture")
    trail_capture_code = module[capture_trails_start:trace_list_start]
    if "traceTrailFingerprint(" in trail_capture_code or "sha256Text(" in trail_capture_code:
        fail("trail fingerprinting still runs while capturing hook-thread input")
    if "traceValueDescription(" in trail_capture_code:
        fail("trail auxiliary values are still serialized on the hook thread")
    require_markers(
        trail_capture_code,
        (
            'captureTraceValue(traceCall(trail, "get_pressures"))',
            'captureTraceValue(traceCall(trail, "get_angles"))',
            'captureTraceValue(traceCall(trail, "get_timestamp"))',
            'captureTraceValue(traceCall(trail, "get_write_app_name"))',
            'captureTraceRect(rrd == null ? null : traceCall(rrd, "getRect"))',
            'captureTraceRect(traceCall(trail, "get_refresh_rect"))',
            'captureTraceRect(traceCall(trail, "get_m_before_shift_rect"))',
            'captureTraceRect(traceCall(trail, "get_m_after_shift_rect"))',
            'captureTraceContours(traceCall(trail, "get_m_contours_src"))',
        ),
        "immutable auxiliary trail-value capture",
    )

    trace_trail_start = module.find(
        "private static JSONObject traceTrail(", trace_list_start
    )
    if trace_trail_start < 0:
        fail("could not isolate trace trail-list fingerprinting")
    trace_list = module[trace_list_start:trace_trail_start]
    require_markers(
        trace_list,
        (
            "for (int index = 0; index < captured.trails.length; index++)",
            "String fingerprint = traceTrailFingerprint(trail)",
            "if (index < limit)",
            "items.put(traceTrail(trail, index, fingerprint))",
            "ordered.append(fingerprint).append(';')",
            "Math.max(0, captured.trails.length - limit)",
        ),
        "complete trail fingerprint with capped details",
    )

    fingerprint_start = module.find(
        "private static String traceTrailFingerprint(", trace_trail_start
    )
    point_description_start = module.find(
        "private static String capturedPointDescription(", fingerprint_start
    )
    if fingerprint_start < 0 or point_description_start < 0:
        fail("could not isolate complete trail fingerprint")
    require_markers(
        module[fingerprint_start:point_description_start],
        (
            ".append(trail.flagPenup).append('|')",
            ".append(trail.flagSpecial).append('|')",
            ".append(trail.layer).append('|')",
            ".append(trail.recMod).append('|')",
            ".append(trail.emrPointAxis).append('|')",
            ".append(trail.trailType).append('|')",
            ".append(trail.drawVersion).append('|')",
            ".append(trail.recognTrailType).append('|')",
            ".append(trail.rotation).append('|')",
            ".append(trail.redrawWidth).append('|')",
            ".append(trail.redrawHeight).append('|')",
            ".append(trail.maxX).append('|')",
            ".append(trail.maxY).append('|')",
            ".append(traceValueDescription(trail.rrdRect)).append('|')",
            ".append(traceValueDescription(trail.refreshRect)).append('|')",
            ".append(traceValueDescription(trail.beforeShiftRect)).append('|')",
            ".append(traceValueDescription(trail.afterShiftRect)).append('|')",
            ".append(traceValueDescription(trail.contours)).append('|')",
            ".append(traceValueDescription(trail.writeAppName)).append('|')",
        ),
        "complete production trail-identity fingerprint coverage",
    )

    hash_state_start = module.find(
        "private static String traceLastSnapshotHash("
    )
    snapshot_schedule_start = module.find(
        "private static void scheduleTraceWorkerTask(", hash_state_start
    )
    if hash_state_start < 0 or snapshot_schedule_start < 0:
        fail("could not isolate identity-aware boundary hash state")
    hash_state = module[hash_state_start:snapshot_schedule_start]
    require_markers(
        hash_state,
        (
            "FileIdentity.capture(mark)",
            "expected.lastSnapshotIdentity.sameAs(currentIdentity)",
            'return "pending"',
        ),
        "non-stale annotation boundary hash",
    )

    worker_start = module.find(
        "private static void scheduleTraceWorkerTask(",
        snapshot_schedule_start,
    )
    worker_end = module.find(
        "private static void scheduleTraceMarkSnapshot(", worker_start
    )
    if worker_start < 0 or worker_end < 0:
        fail("could not isolate trace worker admission logic")
    require_markers(
        module[worker_start:worker_end],
        (
            "final boolean allowWhenStopping",
            "expected.stopping && !allowWhenStopping",
        ),
        "trace-stop boundary worker admission",
    )

    event_start = module.find(
        "private static void traceEvent(\n        TraceSession expected"
    )
    event_queue_start = module.find(
        "private static void queueTraceEventRecord(", event_start
    )
    trace_log_start = module.find(
        "private static void traceLogMessage(", event_queue_start
    )
    trace_log_end = module.find(
        "private static int traceCurrentDocumentPage(", trace_log_start
    )
    if min(event_start, event_queue_start, trace_log_start, trace_log_end) < 0:
        fail("could not isolate serialized trace-event writer")
    event_capture = module[event_start:event_queue_start]
    require_markers(
        event_capture,
        (
            'final String record = entry.toString() + "\\n"',
            "queueTraceEventRecord(expected, event, record)",
        ),
        "immutable trace-event capture",
    )
    if "appendTraceRecord(" in event_capture or "FileOutputStream" in event_capture:
        fail("traceEvent still performs filesystem I/O on its caller thread")
    require_markers(
        module[event_queue_start:trace_log_start],
        (
            "expected.eventExecutor.execute(",
            "appendTraceRecord(expected.eventFile, record)",
            "expected.eventWriteFailure",
        ),
        "serialized background trace-event writer",
    )
    require_markers(
        module[trace_log_start:trace_log_end],
        ("traceEvent(expected, null, \"module_log\"",),
        "module-log event delegation",
    )
    require_markers(
        module,
        (
            "final ScheduledExecutorService eventExecutor;",
            '"SNSpreadTraceEvent-" + id',
        ),
        "per-session trace-event executor",
    )

    require_markers(
        trace_script,
        (
            "[ValidateSet('Start', 'Checkpoint', 'Stop', 'Status')]",
            "com.techrebbe.supernote.spreadprobe.TRACE_CONTROL",
            "SupernoteNativeSpreadTrace",
            "screencap -p",
            "Invoke-Adb pull",
            "Compress-Archive",
            "module-logcat.txt",
            "summary.md",
            "Write-TraceSummary",
            "function Wait-TraceFinalization",
            "function Reconcile-AbandonedTracePointer",
            "[string]$CurrentAction",
            "pidof '$documentPackage'",
            "grep -Fqx '$session'",
            "__TRACE_ABANDONED_REMOVED__",
            "$script:recoveredAbandonedTraceSession = $session",
            "Status retained active.txt",
            "Reconcile-AbandonedTracePointer -CurrentAction $Action",
            "Stop did not pull the preceding completed session.",
            "Read-IncompleteTraceState",
            "Read-RemotePointer -Name incomplete",
            "stable final annotation snapshot",
            "Read-PublicationFailedTraceState",
            "Read-RemotePointer `\n                    -Name publication-failed",
            "trustworthy completion pointer",
            "__TRACE_FINALIZED__",
            "Timed out waiting for trace",
        ),
        "Native Spread trace collection script",
    )

    helper_reconcile = trace_script.find(
        "function Reconcile-AbandonedTracePointer"
    )
    helper_wait = trace_script.find(
        "function Wait-TraceFinalization", helper_reconcile
    )
    action_switch = trace_script.find("switch ($Action)")
    helper_call = trace_script.rfind(
        "Reconcile-AbandonedTracePointer", 0, action_switch
    )
    if not 0 <= helper_reconcile < helper_wait < helper_call < action_switch:
        fail("trace helper does not reconcile abandoned pointers before actions")
    helper_reconcile_code = trace_script[helper_reconcile:helper_wait]
    recovered_check = helper_reconcile_code.find(
        "__TRACE_ABANDONED_REMOVED__"
    )
    recovered_identity = helper_reconcile_code.find(
        "$script:recoveredAbandonedTraceSession = $session",
        recovered_check,
    )
    if not 0 <= recovered_check < recovered_identity:
        fail("trace helper does not retain the recovered session identity")

    invalid_status_retention = helper_reconcile_code.find(
        "if ($CurrentAction -eq 'Status')"
    )
    status_retention = helper_reconcile_code.find(
        "if ($CurrentAction -eq 'Status')",
        invalid_status_retention + 1,
    )
    pointer_removal = helper_reconcile_code.find(
        '$result = Invoke-Adb shell (', status_retention
    )
    if not (
        0 <= invalid_status_retention < status_retention < pointer_removal
    ):
        fail("trace Status can consume an abandoned active pointer")

    stop_trace = trace_script.find("'Stop' {")
    status_trace = trace_script.find("'Status' {", stop_trace)
    if stop_trace < 0 or status_trace < 0:
        fail("could not isolate Native Spread trace Stop action")
    stop_action = trace_script[stop_trace:status_trace]
    status_action = trace_script[status_trace:]
    abandoned_guard = stop_action.find(
        "if ($recoveredAbandonedTraceSession)"
    )
    publication_failed_guard = stop_action.find(
        "if ($publicationFailedTraceSession)"
    )
    completed_fallback = stop_action.find("Read-RemotePointer -Name last")
    incomplete_guard = stop_action.find("if ($incompleteTraceSession)")
    wait_for_finalization = stop_action.find(
        "Wait-TraceFinalization -Session $session"
    )
    pull_bundle = stop_action.find('Invoke-Adb pull "$remoteRoot/$session"')
    if not (
        0 <= abandoned_guard < publication_failed_guard
        < incomplete_guard < completed_fallback < pull_bundle
    ):
        fail("trace Stop can substitute a prior session after crash recovery")
    if not 0 <= wait_for_finalization < pull_bundle:
        fail("trace bundle can be pulled before asynchronous finalization")
    if "Start-Sleep -Milliseconds 500" in stop_action:
        fail("trace Stop still relies on a fixed finalization delay")
    status_abandoned_guard = status_action.find(
        "if ($recoveredAbandonedTraceSession)"
    )
    status_reads_active = status_action.find(
        "Read-RemotePointer -Name active"
    )
    if not 0 <= status_abandoned_guard < status_reads_active:
        fail("trace Status can report an abandoned trace as recording")

    wait_start = trace_script.find("function Wait-TraceFinalization")
    safe_label_start = trace_script.find("function Get-SafeLabel", wait_start)
    if wait_start < 0 or safe_label_start < 0:
        fail("could not isolate trace finalization polling")
    wait_action = trace_script[wait_start:safe_label_start]
    publication_failed_result = wait_action.find(
        "Read-RemotePointer `\n                    -Name publication-failed"
    )
    incomplete_result = wait_action.find(
        "Read-RemotePointer -Name incomplete"
    )
    completed_result = wait_action.find("Read-RemotePointer -Name last")
    if not (
        0 <= publication_failed_result < incomplete_result < completed_result
    ):
        fail("trace helper can publish completion before checking incomplete.txt")

    if 'android:versionCode="118"' not in manifest:
        fail("companion manifest must use versionCode 118")
    if 'android:versionName="0.0.118"' not in manifest:
        fail("companion manifest must use versionName 0.0.118")

    manifest_version = re.search(
        r'android:versionCode="(\d+)"', manifest
    )
    handshake_version = re.search(
        r'private static final long MODULE_VERSION_CODE = (\d+)L;', module
    )
    plugin_minimum = re.search(
        r'NATIVE_SPREAD_MIN_VERSION_CODE = (\d+)L', plugin
    )
    if not manifest_version or not handshake_version or not plugin_minimum:
        fail("could not read packaged, handshake, and minimum module versions")
    reported_versions = {
        int(manifest_version.group(1)),
        int(handshake_version.group(1)),
        int(plugin_minimum.group(1)),
    }
    if len(reported_versions) != 1:
        fail(
            "packaged, handshake, and minimum module versions must match: "
            f"manifest={manifest_version.group(1)} "
            f"handshake={handshake_version.group(1)} "
            f"minimum={plugin_minimum.group(1)}"
        )

    print("Native Spread safety invariants: PASS")


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: check_native_spread_invariants.py <repo-root>")
    check(Path(sys.argv[1]).resolve())


if __name__ == "__main__":
    main()
