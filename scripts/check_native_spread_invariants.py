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
    pdf_view_path = repo_root / "native" / "PdfPageView.kt.template"
    pdf_view_manager_path = repo_root / "native" / "PdfPageViewManager.kt.template"
    direct_patch_path = repo_root / "scripts" / "patch_direct_view.py"

    plugin = plugin_path.read_text(encoding="utf-8")
    module = module_path.read_text(encoding="utf-8")
    manifest = manifest_path.read_text(encoding="utf-8")
    app = app_path.read_text(encoding="utf-8")
    pdf_view = pdf_view_path.read_text(encoding="utf-8")
    pdf_view_manager = pdf_view_manager_path.read_text(encoding="utf-8")
    direct_patch = direct_patch_path.read_text(encoding="utf-8")

    require_markers(
        plugin,
        (
            "NATIVE_SPREAD_MIN_VERSION_CODE = 83L",
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
            '"spreadSizing"',
            'putBoolean("showDivider", showDivider)',
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
            "const [spreadSizing, setSpreadSizing]",
            "setNativeSpreadAppearanceValue",
        ),
        "configured/runtime Native Spread state separation",
    )
    require_markers(
        module,
        (
            "final boolean showDivider;",
            "final boolean nativeFill;",
            'properties.getProperty("showDivider", "true")',
            'properties.getProperty("spreadSizing", "fit")',
            "LEFT_VISIBLE_BOUNDS",
            "RIGHT_VISIBLE_BOUNDS",
            "SpreadPageLayout",
            "drawPageBitmap(canvas, leftBitmap, leftLayout, bitmapPaint)",
            "canvas.clipRect(layout.visibleBounds)",
            "visibleBoundsOrDestination(activity, activeDestination)",
            "Math.max(",
        ),
        "native spread appearance geometry",
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
    if appearance_controls.count("nativeSpreadBusy ||") != 4:
        fail("all native spread appearance controls must be transition-safe")
    if appearance_controls.count(unavailable_guard) != 4:
        fail("native spread appearance controls ignore unavailable hooks")
    for required in (
        "showSpreadDivider",
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
            'phase="',
            '"contact" : "hover"',
            "activateDocumentPageFromPen(activity, requestedTarget);",
            "pen_page_activation_prearmed",
            "pen_activation_deferred",
            "completePendingPenPageActivation(",
            '"pen_up"',
            "cancelPendingPenPageActivation(",
            '"pen_left_screen"',
            "SN_SPREAD_PROBE pen page activation",
            'applySpreadMarkGeometry(',
            '"pen_page_activation"',
            "int targetMarkPage = targetPage + 1;",
            "capturePendingPenActivationTrails(",
            "normalizePendingPenTrail(",
            "pen_activation_native_save_bypassed",
            "persistPendingPenActivationTrails(",
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

    require_markers(
        module,
        (
            "REPLACE_ACTIVE_INK_MODES",
            "FORCE_REPLACE_ACTIVE_INK",
            'setReplaceActiveInkMode(',
            '"area_selection"',
            '"eraser:" + eraserType',
            '"pen"',
            'new String[] {"undo", "redo"}',
            "boolean replaceActiveSlot",
            "if (replaceActiveSlot && activeDestination != null)",
            '" mode=" + (replaceActiveSlot ? "replace" : "add")',
        ),
        "settled ink composition",
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

    if 'android:versionCode="83"' not in manifest:
        fail("companion manifest must use versionCode 83 for portrait rotation refresh")
    if 'android:versionName="0.0.83"' not in manifest:
        fail("companion manifest must use versionName 0.0.83")

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
