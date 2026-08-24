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

refresh_start = hook.find("private static void scheduleConfigurationRefresh")
refresh_end = hook.find("private static boolean focusHalf", refresh_start)
if refresh_start < 0 or refresh_end < 0:
    raise SystemExit("missing configuration refresh implementation")
configuration_refresh = hook[refresh_start:refresh_end]
for required in (
    "activity != owner",
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
if "activity != owner" not in portrait_focus:
    raise SystemExit("portrait focus retries must not mutate a replaced activity")

turn_start = hook.find("private static void handleTurn")
turn_end = hook.find("private static void handlePageLoaded", turn_start)
if turn_start < 0 or turn_end < 0:
    raise SystemExit("missing page-turn implementation")
page_turn = hook[turn_start:turn_end]
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
    "FileIdentity pdfIdentity = FileIdentity.capture(pdf)",
    "FileIdentity sidecarIdentity = FileIdentity.capture(sidecar)",
    "cached.matches(pdfIdentity, sidecarIdentity)",
    "scheduleManifestVerification(",
    "manifest_verification_pending",
    "Fail closed until the background verifier publishes",
):
    if required not in manifest_lookup:
        raise SystemExit(f"manifest lookup is missing fail-closed guard: {required}")
for forbidden in ("parseManifest(", "readBytes(", "sha256(", "sha256File("):
    if forbidden in manifest_lookup:
        raise SystemExit(
            f"manifest lookup performs expensive verification on a UI callback: {forbidden}"
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
    "Manifest parsed = parseManifest(",
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
for required in (
    "FileIdentity sidecarIdentity = FileIdentity.capture(sidecar)",
    "cached.matches(pdfIdentity, sidecarIdentity)",
    "String sidecarDigest = sha256(sidecarData)",
    'output.optString("sha256", "")',
    "expectedHash.equalsIgnoreCase(sha256File(pdfInput))",
    'manifest_rejected reason=output_hash',
    'manifest_rejected reason=snapshot_changed_during_read',
    'root.opt("coverSeparate")',
    "sourcePagesJson.length() != sourcePageCount",
    'JSONArray linksJson = root.optJSONArray("links")',
    "linksJson == null",
    "spreadEntryMatches(",
    "sourceEntryMatches(",
    "linkEndpointMatches(",
    'link.optInt("sourcePage", -1)',
    '"targetSourcePage"',
    '!("internal".equals(kind) || "uri".equals(kind))',
    'if ("uri".equals(kind))',
    'link.opt("uri") instanceof String',
    '"linkAuthoritySha256"',
    "VirtualSpreadLinkAuthority.readPdfDigest(pdfInput)",
    '"layoutAuthoritySha256"',
    "VirtualSpreadLinkAuthority.readPdfLayoutDigest(pdfInput)",
    "VirtualSpreadLinkAuthority.layout(",
    "VirtualSpreadLinkAuthority.layoutDigest(",
    'output.optDouble("gutter", Double.NaN)',
    "VirtualSpreadLinkAuthority.uri(",
    "VirtualSpreadLinkAuthority.internal(",
    "VirtualSpreadLinkAuthority.digest(",
    'manifest_rejected reason=link_authority_records',
    'manifest_rejected reason=layout_authority',
    'manifest_rejected reason=layout_authority_records',
    'manifest_rejected reason=cover_layout',
    'manifest_rejected reason=source_layout',
    "x0 > x1",
    "y0 > y1",
    "length < 0L || length > MAX_MANIFEST_BYTES",
    'manifest_rejected reason=link_mapping',
    'manifest_rejected reason=link_record',
):
    if required not in manifest_validation:
        raise SystemExit(
            f"manifest validation is missing content authority: {required}"
        )

for forbidden in (
    "if (linksJson != null)",
    'link == null || !"internal".equals(link.optString("kind"))',
):
    if forbidden in manifest_validation:
        raise SystemExit(
            f"manifest parser still skips malformed link metadata: {forbidden}"
        )

manifest = (root / "AndroidManifest.xml").read_text(encoding="utf-8")
if 'android:versionCode="15"' not in manifest:
    raise SystemExit("unexpected virtual-spread package version code")
if 'android:versionName="0.0.15"' not in manifest:
    raise SystemExit("unexpected virtual-spread package version name")
if 'private static final String VERSION = "0.0.15"' not in hook:
    raise SystemExit("runtime and package versions must remain aligned")
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
    "SUPPORTED_DOCUMENT_CATALOG_KEYS",
    "SUPPORTED_PAGE_MODES",
    "SUPPORTED_PAGE_LAYOUTS",
    "def _require_supported_source_pages(",
    "SUPPORTED_SOURCE_PAGE_KEYS",
    "_require_supported_source_pages(reader)",
    "writer.page_mode = str(document_catalog.page_mode)",
    "writer.page_layout = str(document_catalog.page_layout)",
    "def _publication_reserved_paths(",
    "def _require_source_outside_publication_namespace(",
    "_require_source_outside_publication_namespace(\n",
    "def _transformed_internal_destination(",
    "def _destination_axis_is_preserved(",
    "isinstance(mode_object, NameObject)",
    "isinstance(value, (FloatObject, NumberObject))",
    'mode in {"/FitH", "/FitBH"}',
    'mode in {"/FitV", "/FitBV"}',
    'mode == "/FitR"',
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
    "test_internal_destination_modes_are_preserved_and_transformed",
    "test_null_destination_coordinates_survive_matching_transform",
    "test_null_destination_coordinates_reject_different_transforms",
    "test_destination_operands_require_pdf_name_and_numbers",
    "test_link_quad_points_are_preserved_and_transformed",
    "test_malformed_link_quad_points_fail_closed",
    "test_ltr_generation_is_rejected_before_publication",
    "test_link_annotation_flags_are_preserved",
    "test_malformed_link_annotation_flags_fail_closed",
    "test_link_rect_requires_finite_pdf_numbers",
    "test_visible_link_border_and_highlight_are_preserved",
    "test_malformed_link_border_or_highlight_fails_closed",
    "test_uri_action_is_map_is_preserved",
    "test_uri_action_operands_and_chains_fail_closed",
    "test_unsupported_link_semantics_fail_closed",
    "test_document_outlines_fail_closed_before_publication",
    "test_document_open_action_fails_closed_before_publication",
    "test_supported_catalog_view_settings_are_preserved",
    "test_optional_content_catalog_fails_closed_before_publication",
    "test_unknown_document_catalog_entry_fails_closed",
    "test_page_behaviors_fail_closed_before_publication",
    "test_unknown_source_page_entry_fails_closed",
    "test_source_reserved_artifact_collisions_fail_before_locking",
    "test_unsupported_internal_destination_mode_fails_closed",
    "test_invalid_marker_with_canonical_artifact_fails_closed",
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
