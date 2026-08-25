from pathlib import Path


root = Path(__file__).resolve().parents[1]
hook = (root / "src/com/techrebbe/supernote/virtualspread/VirtualSpreadHook.java").read_text(
    encoding="utf-8"
)

for forbidden in (
    "HandWriteView",
    "setImage",
    "checkLink",
    "setAreaSelection",
    "setPen",
    "receiveTrials",
    ".mark",
    "lasso",
    "eraser",
    "highlight",
    "undo",
    "redo",
):
    if forbidden in hook:
        raise SystemExit(f"forbidden annotation/render hook surface: {forbidden}")

expected_hooks = {
    '"onCreate"',
    '"screenChange"',
    '"onConfigurationChanged"',
    '"onDestroy"',
    '"turnPage"',
    '"onPageLoadedPart2"',
    '"setPageInfo"',
    '"showLinkJumpView"',
    '"getFirstBack"',
    '"getLastBack"',
}
for expected in expected_hooks:
    if expected not in hook:
        raise SystemExit(f"missing expected narrow hook: {expected}")

if hook.count("findAndHookMethod(") != len(expected_hooks):
    raise SystemExit("unexpected extra LSPosed method hook")

history_start = hook.find("private static void captureHistoryReturn")
history_end = hook.find("private static void captureLinkTarget", history_start)
if history_start < 0 or history_end < 0:
    raise SystemExit("missing native-link history return handling")
history_return = hook[history_start:history_end]
for required in (
    "currentPage < 0 || currentPage >= manifest.pageCount",
    "(!original && currentPage != targetPage)",
    "boolean hadRuntimeHistory = state.linkHistory.size() > 0",
    "state.linkHistory.takeOriginal(",
    "sourcePage, targetPage, currentPage",
    "state.linkHistory.takeBack(",
    "if (hadRuntimeHistory && visit == null)",
    '" origin=runtime"',
):
    if required not in history_return:
        raise SystemExit(
            f"native-link history return is missing fail-closed guard: {required}"
        )

refresh_start = hook.find("private static void scheduleConfigurationRefresh")
refresh_end = hook.find("private static boolean focusHalf", refresh_start)
if refresh_start < 0 or refresh_end < 0:
    raise SystemExit("missing configuration refresh implementation")
configuration_refresh = hook[refresh_start:refresh_end]
for required in (
    "activity != owner",
    'objectField(activity, "documentViewModel")',
    "!= viewModel",
    "currentManifest == null",
    "scheduledState.pageLoadGeneration",
    "currentState.pageLoadGeneration",
    '"screenChange"',
    "Boolean.TRUE",
    'orientation_refresh_skipped reason=native_reload',
):
    if required not in configuration_refresh:
        raise SystemExit(
            f"configuration refresh is missing fail-closed guard: {required}"
        )

focus_start = hook.find("private static void schedulePortraitFocus")
focus_end = hook.find("private static void scheduleConfigurationRefresh", focus_start)
if focus_start < 0 or focus_end < 0:
    raise SystemExit("missing portrait focus scheduler")
portrait_focus = hook[focus_start:focus_end]
for required in (
    "activity != owner",
    "scheduledState.pageLoadGeneration",
    "state.pageLoadGeneration",
    'portrait_focus_skipped reason=native_reload',
):
    if required not in portrait_focus:
        raise SystemExit(
            f"portrait focus retry is missing fail-closed guard: {required}"
        )

page_loaded_start = hook.find("private static void handlePageLoaded")
page_loaded_end = hook.find("private static void schedulePortraitFocus", page_loaded_start)
if page_loaded_start < 0 or page_loaded_end < 0:
    raise SystemExit("missing page-loaded viewport handling")
page_loaded = hook[page_loaded_start:page_loaded_end]
for required in (
    "shouldPreservePortraitLinkViewport(",
    '"internal_link".equals(targetReason)',
    "if (preserveLinkViewport)",
    'portrait_link_view_preserved',
):
    if required not in page_loaded:
        raise SystemExit(
            f"portrait internal-link viewport is not preserved: {required}"
        )

turn_start = hook.find("private static void handleTurn")
turn_end = hook.find("private static void handlePageLoaded", turn_start)
if turn_start < 0 or turn_end < 0:
    raise SystemExit("missing page-turn implementation")
page_turn = hook[turn_start:turn_end]
lookup_index = page_turn.find("ManifestLookup lookup = manifestLookupFor(viewModel)")
verification_block_index = page_turn.find(
    "if (manifest == null && lookup.verificationPending)"
)
passthrough_index = page_turn.find(
    "if (manifest == null)", verification_block_index + 1
)
if not (
    0 <= lookup_index < verification_block_index < passthrough_index
    and 'param.setResult(null);\n            log("turn_blocked '
        in page_turn[verification_block_index:passthrough_index]
):
    raise SystemExit(
        "native turns must fail closed while manifest verification is pending"
    )
save_index = page_turn.find("if (!saveNativeTrails(activity))")
pending_index = page_turn.find("state.pendingPage = plan.targetPage")
if save_index < 0 or pending_index < 0 or save_index >= pending_index:
    raise SystemExit("cross-page state must follow a successful native trail save")
cross_page = page_turn[save_index:pending_index]
for forbidden in (
    "state.half = plan.targetHalf",
    "state.lastPage = plan.targetPage",
):
    if forbidden in cross_page:
        raise SystemExit(
            "failed cross-page saves must preserve the current reader state"
        )

state_start = hook.find("private static ReaderState stateFor")
state_end = hook.find("private static VirtualSpreadNavigation.Half firstHalf", state_start)
if state_start < 0 or state_end < 0:
    raise SystemExit("missing reader-state revision implementation")
reader_state = hook[state_start:state_end]
for required in (
    "manifest.revision.equals(state.manifestRevision)",
    "state.manifestRevision = manifest.revision",
):
    if required not in reader_state:
        raise SystemExit(
            f"reader state is not bound to the manifest revision: {required}"
        )

lookup_start = hook.find("private static Manifest manifestFor")
lookup_end = hook.find(
    "private static boolean scheduleManifestVerification",
    lookup_start,
)
if lookup_start < 0 or lookup_end < 0:
    raise SystemExit("missing fail-closed manifest lookup implementation")
manifest_lookup = hook[lookup_start:lookup_end]
for required in (
    'objectField(current, "documentViewModel") == null',
    'objectField(activity, "documentViewModel") != viewModel',
    'manifest_lookup_skipped reason=stale_view_model',
    "observeDocumentKey(null)",
    "String key = pdf.getCanonicalPath()",
    "observeDocumentKey(key)",
    "cancelManifestVerificationForKey(key)",
    "FileIdentity pdfIdentity = FileIdentity.capture(pdf)",
    "FileIdentity sidecarIdentity = FileIdentity.capture(sidecar)",
    "cached.matches(pdfIdentity, sidecarIdentity)",
    "validateNativeSnapshot(viewModel, cached.manifest)",
    "scheduleManifestVerification(",
    "boolean verificationPending = scheduleManifestVerification(",
    "return new ManifestLookup(null, verificationPending)",
    "manifest_verification_pending",
    "Fail closed until the background verifier publishes",
    'observeDocumentKey(null);\n            logFailure("manifest_read_failed"',
):
    if required not in manifest_lookup:
        raise SystemExit(f"manifest lookup is missing fail-closed guard: {required}")
for forbidden in ("parseManifest(", "readBytes(", "sha256(", "sha256File("):
    if forbidden in manifest_lookup:
        raise SystemExit(
            f"manifest lookup performs expensive verification on a UI callback: {forbidden}"
        )

lookup_positions = (
    manifest_lookup.find("String key = pdf.getCanonicalPath()"),
    manifest_lookup.find("observeDocumentKey(key)"),
    manifest_lookup.find("if (!pdf.isFile() || !sidecar.isFile())"),
    manifest_lookup.find("cancelManifestVerificationForKey(key)"),
    manifest_lookup.find("CachedManifest cached = MANIFESTS.get(key)"),
)
if min(lookup_positions) < 0 or tuple(sorted(lookup_positions)) != (
    lookup_positions
):
    raise SystemExit(
        "document observation must precede sidecar and cache fast paths"
    )

for required in (
    "nativeSnapshotDocument",
    "manifestMatchesNativeSnapshot(",
    '"info:" + key',
    '"SNVirtualSpreadSourceSHA256"',
    '"SNVirtualSpreadLayoutSHA256"',
    '"SNVirtualSpreadLinksSHA256"',
    "!isSha256(nativeSource)",
    'manifest_rejected reason=native_snapshot_metadata',
    'objectField(currentPdfMupdf, "document") != nativeDocument',
    "state.nativeSnapshotDocument = nativeDocument",
):
    if required not in hook:
        raise SystemExit(
            f"native reader snapshot binding is missing: {required}"
        )

if hook.count("parseManifest(") != 2 or hook.count("sha256File(") != 2:
    raise SystemExit(
        "full PDF verification must have exactly one call site, inside the "
        "background manifest verifier"
    )

verification_start = lookup_end
verification_end = hook.find(
    "private static Manifest validatePageCount",
    verification_start,
)
if verification_end < 0:
    raise SystemExit("missing asynchronous manifest verification implementation")
manifest_verification = hook[verification_start:verification_end]
for required in (
    "MANIFEST_VERIFIER.execute",
    "VERIFYING.put(key, verificationId)",
    "if (verificationId.equals(VERIFYING.get(key))) {\n                return true;",
    "verificationId.equals(VERIFYING.get(key))",
    'RandomAccessFile pdfInput = new RandomAccessFile(pdf, "r")',
    "FileInputStream sidecarInput = new FileInputStream(sidecar)",
    "FileIdentity pdfOpened = FileIdentity.capture(pdfInput.getFD())",
    "FileIdentity sidecarOpened = FileIdentity.capture(",
    "!pdfBefore.matches(pdfOpened)",
    "!sidecarBefore.matches(sidecarOpened)",
    "byte[] sidecarData = readBytes(",
    "sidecarInput,",
    "String sidecarDigest = sha256(sidecarData)",
    "VirtualSpreadNavigation.decodeStrictUtf8(sidecarData)",
    'manifest_rejected reason=invalid_utf8',
    "Manifest parsed;",
    "pdfInput,",
    "FileIdentity pdfAfter = FileIdentity.capture(pdfInput.getFD())",
    "FileIdentity sidecarAfter = FileIdentity.capture(",
    "FileIdentity pdfPathAfter = FileIdentity.capture(pdf)",
    "FileIdentity sidecarPathAfter = FileIdentity.capture(sidecar)",
    "pdfOpened.matches(pdfAfter)",
    "sidecarOpened.matches(sidecarAfter)",
    "pdfAfter.matches(pdfPathAfter)",
    "sidecarAfter.matches(sidecarPathAfter)",
    "sidecarDigest.equals(currentSidecarDigest)",
    "MANIFESTS.put(key, published)",
    "scheduleManifestActivation(key, parsed.revision)",
    "new Handler(owner.getMainLooper()).post",
    "handlePageLoaded(viewModel)",
    '"manifest_verified"',
):
    if required not in manifest_verification:
        raise SystemExit(
            f"background manifest verification is missing guard: {required}"
        )

for required in (
    "new ArrayBlockingQueue<Runnable>(1)",
    "synchronized (MANIFEST_VERIFIER_LOCK)",
    "private static volatile String observedDocumentKey",
    "observedDocumentKey = key",
    "cancelManifestVerificationLocked()",
    "cancelManifestVerificationForKey(key)",
    "VERIFYING.clear()",
    "MANIFEST_VERIFIER.getQueue().poll()",
    "((ManifestVerificationTask) stale).cancelBeforeRun()",
    "new ManifestVerificationTask(",
    "requireCurrentVerification(key, verificationId)",
    "sha256File(pdfInput, key, verificationId)",
):
    if required not in hook:
        raise SystemExit(
            f"latest-only manifest verification is missing: {required}"
        )
if "Executors.newSingleThreadExecutor()" in hook:
    raise SystemExit("manifest verification must not use an unbounded queue")

observer_start = hook.find("private static void observeDocumentKey")
observer_end = hook.find(
    "private static void cancelManifestVerificationForKey", observer_start
)
cancellation_start = hook.find(
    "private static void cancelManifestVerificationLocked"
)
cancellation_end = hook.find(
    "private static boolean scheduleManifestVerification",
    cancellation_start,
)
if min(observer_start, observer_end, cancellation_start, cancellation_end) < 0:
    raise SystemExit("missing document-verification cancellation helpers")
observer = hook[observer_start:observer_end]
observer_positions = (
    observer.find("observedDocumentKey = key"),
    observer.find("cancelManifestVerificationLocked()"),
)
if min(observer_positions) < 0 or tuple(sorted(observer_positions)) != (
    observer_positions
):
    raise SystemExit(
        "document observation must publish the key before cancellation"
    )
cancellation = hook[cancellation_start:cancellation_end]
cancellation_positions = (
    cancellation.find("VERIFYING.clear()"),
    cancellation.find("MANIFEST_VERIFIER.getQueue().poll()"),
    cancellation.find(
        "((ManifestVerificationTask) stale).cancelBeforeRun()"
    ),
)
if min(cancellation_positions) < 0 or tuple(
    sorted(cancellation_positions)
) != cancellation_positions:
    raise SystemExit(
        "verification cancellation must invalidate, drain, then cancel"
    )

scheduler_start = hook.find("private static boolean scheduleManifestVerification")
scheduler_end = hook.find(
    "private static void requireCurrentVerification", scheduler_start
)
if scheduler_start < 0 or scheduler_end < 0:
    raise SystemExit("missing latest-only verification scheduler")
scheduler = hook[scheduler_start:scheduler_end]
scheduler_positions = (
    scheduler.find("if (!key.equals(observedDocumentKey))"),
    scheduler.find("cancelManifestVerificationLocked()"),
    scheduler.find("VERIFYING.put(key, verificationId)"),
    scheduler.find("MANIFEST_VERIFIER.execute"),
)
if min(scheduler_positions) < 0 or tuple(sorted(scheduler_positions)) != (
    scheduler_positions
):
    raise SystemExit(
        "manifest verification must check ownership, invalidate, publish, then enqueue"
    )

snapshot_guards = (
    "!pdfBefore.matches(pdfOpened)",
    "!sidecarBefore.matches(sidecarOpened)",
    "pdfOpened.matches(pdfAfter)",
    "sidecarOpened.matches(sidecarAfter)",
    "pdfAfter.matches(pdfPathAfter)",
    "sidecarAfter.matches(sidecarPathAfter)",
    "sidecarDigest.equals(currentSidecarDigest)",
)
snapshot_guard_positions = [
    manifest_verification.find(guard) for guard in snapshot_guards
]
publication = manifest_verification.find("MANIFESTS.put(key, published)")
if min(*snapshot_guard_positions, publication) < 0 or publication <= max(
    snapshot_guard_positions
):
    raise SystemExit("manifest publication must follow every snapshot check")

manifest_start = hook.find("private static Manifest manifestFor")
manifest_end = hook.find("private static boolean isPortrait", manifest_start)
if manifest_start < 0 or manifest_end < 0:
    raise SystemExit("missing manifest validation implementation")
manifest_validation = hook[manifest_start:manifest_end]
if "new String(sidecarData" in manifest_verification:
    raise SystemExit("manifest bytes must never use replacement UTF-8 decoding")
utf8_decode = manifest_verification.find("decodeStrictUtf8(sidecarData)")
manifest_parse = manifest_verification.find("parseManifest(")
if not (0 <= utf8_decode < manifest_parse):
    raise SystemExit("strict UTF-8 decoding must precede manifest parsing")

for required in (
    "FileIdentity sidecarIdentity = FileIdentity.capture(sidecar)",
    "cached.matches(pdfIdentity, sidecarIdentity)",
    "String sidecarDigest = sha256(sidecarData)",
    'output.optString("sha256", "")',
    "sha256File(pdfInput, key, verificationId)",
    "VirtualSpreadLinkAuthority.readPdfSourceDigest(pdfInput)",
    'manifest_rejected reason=output_hash',
    'manifest_rejected reason=snapshot_changed_during_read',
    'root.opt("coverSeparate")',
    "sourcePagesJson.length() != sourcePageCount",
    'JSONArray linksJson = root.optJSONArray("links")',
    "linksJson == null",
    "spreadEntryMatches(",
    "sourceEntryMatches(",
    "linkEndpointMatches(",
    "exactManifestInteger(",
    "VirtualSpreadNavigation.exactJsonInteger(",
    "exactNonnegativeJsonLong(",
    "exactFiniteJsonNumber(",
    "jsonObjectHasUniqueKeys(sidecarJson)",
    'manifest_rejected reason=duplicate_or_invalid_json',
    'spreadSize.opt(0)',
    'spreadSize.opt(1)',
    'output.opt("gutter")',
    'rect.opt(0)',
    'rect.opt(1)',
    'rect.opt(2)',
    'rect.opt(3)',
    'manifest_rejected reason=manifest_integer',
    '"targetSourcePage"',
    'link.opt("targetView")',
    '"fit-source-page".equals(targetView)',
    '!("internal".equals(kind) || "uri".equals(kind))',
    'if ("uri".equals(kind))',
    'link.opt("uri") instanceof String',
    '"linkAuthoritySha256"',
    "VirtualSpreadLinkAuthority.readPdfDigest(pdfInput)",
    '"layoutAuthoritySha256"',
    "VirtualSpreadLinkAuthority.readPdfLayoutDigest(pdfInput)",
    "VirtualSpreadLinkAuthority.layout(",
    "VirtualSpreadLinkAuthority.layoutDigest(",
    "VirtualSpreadLinkAuthority.uri(",
    "VirtualSpreadLinkAuthority.internal(",
    "VirtualSpreadLinkAuthority.digest(",
    'manifest_rejected reason=link_authority_records',
    'manifest_rejected reason=layout_authority',
    'manifest_rejected reason=layout_authority_records',
    'manifest_rejected reason=cover_layout',
    'manifest_rejected reason=source_layout',
    "VirtualSpreadNavigation.runtimeGeometryIsRepresentable(",
    "VirtualSpreadNavigation.nomadSpreadAspectIsSupported(",
    "VirtualSpreadNavigation.runtimeRectIsRepresentable(",
    "pageHeight, x0, y0, x1, y1",
    "length < 0L || length > MAX_MANIFEST_BYTES",
    'manifest_rejected reason=link_mapping',
    'manifest_rejected reason=link_record',
):
    if required not in manifest_validation:
        raise SystemExit(
            f"manifest validation is missing content authority: {required}"
        )

for forbidden in (
    "optInt(",
    "optLong(",
    "optDouble(",
    "getDouble(",
    "if (linksJson != null)",
    'link == null || !"internal".equals(link.optString("kind"))',
):
    if forbidden in manifest_validation:
        raise SystemExit(
            f"manifest parser still skips malformed link metadata: {forbidden}"
        )

duplicate_guard = manifest_validation.find(
    "jsonObjectHasUniqueKeys(sidecarJson)"
)
json_parse = manifest_validation.find("new JSONObject(sidecarJson)")
if not (0 <= duplicate_guard < json_parse):
    raise SystemExit(
        "duplicate-key validation must run before Android JSONObject parsing"
    )

manifest = (root / "AndroidManifest.xml").read_text(encoding="utf-8")
if 'android:versionCode="23"' not in manifest:
    raise SystemExit("unexpected virtual-spread package version code")
if 'android:versionName="0.0.23"' not in manifest:
    raise SystemExit("unexpected virtual-spread package version name")
if 'private static final String VERSION = "0.0.23"' not in hook:
    raise SystemExit("runtime and package versions must remain aligned")
for required in (
    "MAX_CACHED_MANIFESTS = 4",
    "VirtualSpreadNavigation.BoundedCache<",
    "MAX_CACHED_MANIFESTS",
):
    if required not in hook:
        raise SystemExit(f"manifest cache is not bounded: {required}")
for required in (
    "pendingLinkResetLandscapeFit",
    "matched.resetLandscapeFit",
    '"internal_link_fit_reset"',
    "scheduleConfigurationRefresh(",
):
    if required not in hook:
        raise SystemExit(
            f"runtime is missing authenticated Fit-view handling: {required}"
        )
if "MAX_MANIFEST_BYTES = 8L * 1024L * 1024L" not in hook:
    raise SystemExit(
        "runtime and generator manifest-size limits must remain aligned"
    )
scope = (root / "meta/META-INF/xposed/scope.list").read_text(
    encoding="utf-8"
).splitlines()
if scope != ["com.supernote.document"]:
    raise SystemExit(f"unexpected LSPosed scope: {scope}")
if "android.permission" in manifest:
    raise SystemExit("navigation-only module must not request Android permissions")

workflow = (root.parent / ".github/workflows/build.yml").read_text(
    encoding="utf-8"
)
if "run: ./virtual-spread-module/test.ps1" not in workflow:
    raise SystemExit(
        "CI must run the complete virtual-spread companion test script"
    )
if "run: ./virtual-spread-module/build.ps1" not in workflow:
    raise SystemExit(
        "CI must build and verify the virtual-spread companion APK"
    )

generator = (root.parent / "virtual_spread/generate_virtual_spread.py").read_text(
    encoding="utf-8"
)
for required in (
    'PUBLICATION_SCHEMA = "techrebbe.supernote.virtual-spread-publication/v2"',
    'SOURCE_AUTHORITY_MARKER = b"%SNVirtualSpreadSourceSHA256:"',
    "source_hash,",
    'LEGACY_PUBLICATION_SCHEMA = "techrebbe.supernote.virtual-spread-publication/v1"',
    "class AmbiguousPublicationMarkerError(",
    "object_pairs_hook=_publication_marker_object",
    "set(transaction) != expected_fields",
    "MOVEFILE_WRITE_THROUGH",
    "MAX_MANIFEST_BYTES = 8 * 1024 * 1024",
    "def _publication_file_evidence(",
    "maximum_bytes is not None and opened_before.size > maximum_bytes",
    "def _publication_output_evidence(",
    "def _publication_manifest_evidence(",
    "maximum_bytes=MAX_MANIFEST_BYTES",
    "expected_identity=expected_output_identity",
    "expected_hash=expected_output_hash",
    "expected_identity=expected_manifest_identity",
    "expected_hash=expected_manifest_hash",
    "def _require_publication_output_hash(",
    "def _publication_output_matches_sha256(",
    "def _require_publication_manifest_hash(",
    "def _publication_manifest_matches_sha256(",
    'transaction["_newOutputIdentity"] = new_output_identity',
    '"size": temporary_output_identity.size',
    '"sha256": temporary_output_hash',
    "def _transform_quad_points(",
    'if "/QuadPoints" in original:',
    "def _require_supported_direction(",
    "direction = _require_supported_direction(direction)",
    "def _finite_pdf_number(",
    "def _link_annotation_flags(",
    'copied[NameObject("/F")] = annotation_flags',
    "def _validate_link_annotation(",
    "def _transform_link_border(",
    "def _transform_link_border_style(",
    "def _copy_link_highlight_mode(",
    "def _validated_link_action(",
    'copied[NameObject("/Border")] = border',
    'copied_action[NameObject("/IsMap")] = BooleanObject(',
    "def _require_supported_document_catalog(",
    "def _require_runtime_float_geometry(",
    "NOMAD_LANDSCAPE_ASPECT = 4.0 / 3.0",
    "def _require_nomad_spread_aspect(",
    "_require_nomad_spread_aspect(spread_width, spread_height)",
    "def _require_runtime_float_rect(",
    "_require_runtime_float_rect(runtime_rect, page_height)",
    "SUPPORTED_DOCUMENT_CATALOG_KEYS",
    "SUPPORTED_PAGE_MODES",
    "SUPPORTED_PAGE_LAYOUTS",
    "def _require_supported_source_pages(",
    "SUPPORTED_SOURCE_PAGE_KEYS",
    "_require_supported_source_pages(reader)",
    "DOCUMENT_INFORMATION_TEXT_KEYS",
    "SUPPORTED_TRAPPED_NAMES",
    "def _write_document_information(",
    "writer._info = information",
    "writer.page_mode = str(document_catalog.page_mode)",
    "writer.page_layout = str(document_catalog.page_layout)",
    "def _publication_reserved_paths(",
    "def _require_source_outside_publication_namespace(",
    "_require_source_outside_publication_namespace(\n",
    "def _transformed_internal_destination(",
    "def _require_xyz_viewport_inside_target_half(",
    "_require_xyz_viewport_inside_target_half(",
    "def _require_fitr_viewport_inside_target_half(",
    "_require_fitr_viewport_inside_target_half(",
    "portrait_aspect = 1.0 / NOMAD_LANDSCAPE_ASPECT",
    "def _destination_axis_is_preserved(",
    "isinstance(mode_object, NameObject)",
    "isinstance(value, (FloatObject, NumberObject))",
    "def _raw_page_box_values(",
    "def _require_rectangle_contained(",
    "_require_rectangle_contained(\n            raw_crop_box,",
    "_require_rectangle_contained(\n            crop_box,",
    "def _require_nondegenerate_quadrilateral(",
    'mode in {"/FitB", "/FitH", "/FitBH", "/FitV", "/FitBV"}',
    'NameObject("/FitR")',
    '"targetView": (',
    "expected_output_identity=temporary_output_identity",
    "expected_output_hash=temporary_output_hash",
    "lexical_output = _require_unaliased_output_path(output_path)",
    "lexical_manifest = _require_runtime_manifest_path(",
    "with _publication_lock(lexical_output) as ownership_guard:",
    "yield ownership",
    "def _publication_lock_path(output_path: Path)",
    "manifest_path = _runtime_manifest_path(output_path)",
    "getattr(os, \"O_NOFOLLOW\", 0)",
    "lock_path, descriptor, directory_descriptor",
    "def _acquire_publication_directory_lock(",
    "_require_open_directory_identity(lock_path.parent, descriptor)",
    "directory_descriptor = _acquire_publication_directory_lock(",
    "self.directory_descriptor",
    "_validate_publication_ownership(ownership_guard)",
    "class _PublicationNamespace:",
    "src_dir_fd=self.directory_descriptor",
    "dst_dir_fd=self.directory_descriptor",
    "dir_fd=self.directory_descriptor",
    "def _publication_open_file(",
    "def _publication_unlink(",
    "def _temporary_neighbor(",
    "namespace.open_file(candidate, flags, 0o600)",
    "_write_json(temporary_manifest, manifest, ownership_guard)",
    "PdfReader(verification_stream, strict=True)",
    "with tempfile.TemporaryFile(",
    "_publication_sha256(path, ownership_guard)",
    "_require_regular_publication_targets(\n"
    "        output_path, manifest_path, ownership_guard",
    '"Staged output"',
    '"Staged manifest"',
    '"Published output"',
    '"Published manifest"',
    '"oldOutputSha256"',
    '"oldManifestSha256"',
    '"Publication marker"',
    '"Output backup"',
    '"Manifest backup"',
    '"Staged publication target"',
    "for final_path, backup, had_final, new_hash, old_hash, backup_label "
    "in entries:",
    "replace_existing=False",
    "temporary_manifest,\n"
    "            manifest_path,\n"
    "            ownership_guard=ownership_guard",
    "temporary_output,\n"
    "            output_path,\n"
    "            ownership_guard=ownership_guard",
    "replace_existing=False",
    "artifacts = (",
    "for path, _ in artifacts:",
    "_durably_remove(path, ownership_guard)",
    "_durably_remove(final_path, ownership_guard)",
    '"layoutAuthoritySha256": layout_authority_hash',
    '"/SNVirtualSpreadLayoutSHA256": layout_authority_hash',
):
    if required not in generator:
        raise SystemExit(
            f"generator is missing durable/layout authority invariant: {required}"
        )

generator_tests = (root.parent / "scripts/test_virtual_spread.py").read_text(
    encoding="utf-8"
)
for required in (
    "test_staged_output_swap_is_rejected_at_publication_boundary",
    "test_same_content_staged_output_replacement_is_rejected",
    "test_obsolete_marker_without_backups_is_discarded",
    "test_obsolete_marker_with_backup_fails_closed",
    "test_legacy_marker_with_duplicate_keys_fails_closed",
    "test_legacy_marker_with_unknown_fields_fails_closed",
    "test_obsolete_new_pair_partial_sidecar_fails_closed",
    "test_obsolete_new_pair_complete_publication_fails_closed",
    "test_representable_internal_destinations_are_transformed",
    "test_null_top_destination_survives_with_bounded_viewport",
    "test_xyz_viewport_must_stay_inside_target_half",
    "test_fitr_viewport_must_stay_inside_target_half",
    "test_fit_source_page_uses_authenticated_runtime_reset",
    "test_non_nomad_spread_aspect_is_rejected",
    "test_recovery_preserves_unexpected_target_in_front_of_backup",
    "test_published_hash_mismatch_preserves_unexpected_target",
    "test_unknown_xyz_left_fails_closed_even_matching_transform",
    "test_null_destination_coordinates_reject_different_transforms",
    "test_destination_operands_require_pdf_name_and_numbers",
    "test_link_quad_points_are_preserved_and_transformed",
    "test_malformed_link_quad_points_fail_closed",
    "test_ltr_generation_is_rejected_before_publication",
    "test_link_annotation_flags_are_preserved",
    "test_malformed_link_annotation_flags_fail_closed",
    "test_link_rect_requires_finite_pdf_numbers",
    "test_visible_link_border_and_highlight_are_preserved",
    "test_underlined_link_border_requires_preserved_bottom_edge",
    "test_implicit_default_link_border_is_scaled",
    "test_malformed_link_border_or_highlight_fails_closed",
    "test_link_geometry_must_remain_inside_effective_crop",
    "test_crop_box_must_be_contained_by_media_box",
    "test_uri_action_is_map_false_is_preserved",
    "test_uri_action_is_map_true_fails_closed",
    "test_uri_action_operands_and_chains_fail_closed",
    "test_unsupported_link_semantics_fail_closed",
    "test_document_outlines_fail_closed_before_publication",
    "test_document_open_action_fails_closed_before_publication",
    "test_supported_catalog_view_settings_are_preserved",
    "test_optional_content_catalog_fails_closed_before_publication",
    "test_unknown_document_catalog_entry_fails_closed",
    "test_page_behaviors_fail_closed_before_publication",
    "test_unknown_source_page_entry_fails_closed",
    "test_page_rotation_requires_exact_pdf_quarter_turn_integer",
    "test_typed_document_information_is_preserved",
    "test_unsupported_document_information_fails_closed",
    "test_invalid_standard_document_information_fails_closed",
    "test_source_reserved_artifact_collisions_fail_before_locking",
    "test_unsupported_internal_destination_mode_fails_closed",
    "test_invalid_marker_with_canonical_artifact_fails_closed",
    "test_runtime_float_link_rect_is_rejected",
):
    if required not in generator_tests:
        raise SystemExit(
            "generator is missing staged-output publication regression: "
            f"{required}"
        )

preflight_hash = generator.find('"Staged manifest"')
preflight_output_hash = generator.find('"Staged output"')
backup_move = generator.find(
    "for (\n"
    "            final_path,\n"
    "            backup,"
)
published_manifest_hash = generator.find('"Published manifest"')
published_output_hash = generator.find('"Published output"')
finish_transaction = generator.find(
    "_finish_publication_transaction(transaction, ownership_guard)"
)
if not (
    0 <= preflight_output_hash < backup_move
    and 0 <= preflight_hash < backup_move
    and backup_move < published_manifest_hash < finish_transaction
    and backup_move < published_output_hash < finish_transaction
):
    raise SystemExit(
        "staged and published pair hashes must bracket backup publication"
    )

build_start = generator.find("def build_virtual_spread(")
build_end = generator.find("def _parser()", build_start)
if build_start < 0 or build_end < 0:
    raise SystemExit("missing public virtual-spread build entry point")
public_build = generator[build_start:build_end]
alias_guard = public_build.find(
    "lexical_output = _require_unaliased_output_path(output_path)"
)
publication_lock = public_build.find(
    "with _publication_lock(lexical_output) as ownership_guard:"
)
if alias_guard < 0 or publication_lock < 0 or alias_guard >= publication_lock:
    raise SystemExit(
        "output alias rejection must run before publication ownership is acquired"
    )

locked_start = generator.find("def _build_virtual_spread_locked(")
locked_end = generator.find("def build_virtual_spread(", locked_start)
if locked_start < 0 or locked_end < 0:
    raise SystemExit("missing locked virtual-spread build implementation")
locked_build = generator[locked_start:locked_end]
locked_alias_guard = locked_build.find(
    "output_path = _require_unaliased_output_path(output_path)"
)
locked_recovery = locked_build.find(
    "_recover_pair_publication(output_path, manifest_path, ownership_guard)"
)
if (
    locked_alias_guard < 0
    or locked_recovery < 0
    or locked_alias_guard >= locked_recovery
):
    raise SystemExit(
        "output aliases must be rechecked under lock before recovery or mutation"
    )

generator_tests = (root.parent / "scripts/test_virtual_spread.py").read_text(
    encoding="utf-8"
)
for required in (
    "test_publication_lock_replacement_is_detected_while_held",
    "test_replaced_lock_path_does_not_admit_second_publisher",
    "test_same_content_staged_manifest_replacement_is_rejected",
    "test_parent_exchange_cannot_redirect_locked_publication",
    "test_parent_exchange_cannot_redirect_staged_write",
    "test_staged_manifest_swap_to_oversized_is_rejected_at_publication_boundary",
    "test_recovery_rejects_tampered_backup_without_restoring_it",
):
    if required not in generator_tests:
        raise SystemExit("generator transaction regression missing: " + required)

print("VirtualSpread hook scope PASS")
