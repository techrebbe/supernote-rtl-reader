from pathlib import Path

import re

import yaml


root = Path(__file__).resolve().parents[1]
hook = (root / "src/com/techrebbe/supernote/virtualspread/VirtualSpreadHook.java").read_text(
    encoding="utf-8"
)
link_authority = (
    root
    / "src/com/techrebbe/supernote/virtualspread/VirtualSpreadLinkAuthority.java"
).read_text(encoding="utf-8")
navigation = (
    root
    / "src/com/techrebbe/supernote/virtualspread/VirtualSpreadNavigation.java"
).read_text(encoding="utf-8")

for required in (
    "sha256(strictUtf8(uri))",
    "digest.update(strictUtf8(record))",
    "Character.isHighSurrogate(current)",
    "Character.isLowSurrogate(current)",
):
    if required not in link_authority:
        raise SystemExit(
            "link authority must reject malformed UTF-16 before UTF-8 hashing: "
            + required
        )

if ('private static final String SCHEMA =\n'
        '        "techrebbe.supernote.virtual-spread/v3";' not in hook):
    raise SystemExit(
        "runtime must require the v3 authenticated-mapping manifest schema"
    )

for required in (
    "private static final Map<String, VerificationOwner> VERIFYING",
    "private static final AtomicLong VERIFICATION_GENERATION",
    "private static final class VerificationOwner",
    "final long generation;",
    "final VerificationOwner owner;",
):
    if required not in hook:
        raise SystemExit(
            "manifest verification lacks unique task ownership: " + required
        )
for forbidden in (
    "Map<String, String> VERIFYING",
    "VERIFYING.put(key, snapshotId)",
    "VERIFYING.remove(key, snapshotId)",
):
    if forbidden in hook:
        raise SystemExit(
            "filesystem snapshot IDs must not act as verifier task identity: "
            + forbidden
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
    '"onPageLoaded"',
    '"onPageLoadedPart2"',
    '"setPageInfo"',
    '"showLinkJumpView"',
    '"jumpLink"',
    '"getFirstBack"',
    '"getLastBack"',
    '"onBackClick"',
    '"onOriginalBackClick"',
    '"saveMarkData"',
    '"loadPage"',
}
for expected in expected_hooks:
    if expected not in hook:
        raise SystemExit(f"missing expected narrow hook: {expected}")

# loadPage has one narrow navigation/history guard and one private-overload
# viewport lifecycle fence. Every other expected name is hooked once.
if hook.count("findAndHookMethod(") != len(expected_hooks) + 1:
    raise SystemExit("unexpected extra LSPosed method hook")

for required in (
    "private static final String TARGET_LOAD_PAGE_TASK",
    "loadPageTaskClass.getDeclaredConstructor(",
    'loadPageTaskClass.getDeclaredMethod(\n                "mainThreadCall"',
    "XposedBridge.hookMethod(",
    '"this$0"',
    'int page = intField(param.thisObject, "val$page", -1)',
    "NATIVE_VIEWPORT_TASK_BINDINGS.put(",
    "NATIVE_VIEWPORT_PAGE_INFO_BINDINGS.put(",
    "Never reuse an in-flight identity.",
    "NATIVE_VIEWPORT_LOAD_BINDING_LOCK",
    "return latest;",
):
    if required not in hook:
        raise SystemExit(
            "native page completion lacks initiating-task binding: "
            + required
        )
if hook.count("loadPageTaskClass.getDeclaredConstructor(") != 1:
    raise SystemExit("unexpected extra LSPosed task-constructor hook")

load_start = hook.find("public void handleLoadPackage(")
load_end = hook.find("private static void hookActivity", load_start)
if load_start < 0 or load_end < 0:
    raise SystemExit("missing atomic required-hook activation")
load_package = hook[load_start:load_end]
required_hook_order = (
    "hooksReady = false;",
    "try {",
    "hookActivity(loadPackageParam.classLoader);",
    "hookViewModel(loadPackageParam.classLoader);",
    "hookPageBar(loadPackageParam.classLoader);",
    "hookLinkTarget(loadPackageParam.classLoader);",
    "hookLinkHistory(loadPackageParam.classLoader);",
    "hookLinkHistoryActions(loadPackageParam.classLoader);",
    "hookNativeSaveAcknowledgement(loadPackageParam.classLoader);",
    'logFailure("disabled reason=required_hook_failed", throwable);',
    "return;",
    "hooksReady = true;",
)
last_required = -1
for required in required_hook_order:
    current = load_package.find(required, last_required + 1)
    if current < 0:
        raise SystemExit(
            "required hooks must activate atomically and fail closed: "
            + required
        )
    last_required = current
if "private static volatile boolean hooksReady;" not in hook:
    raise SystemExit("required-hook readiness gate is missing")
lookup_start = hook.find("private static ManifestLookup manifestLookupFor(")
lookup_end = hook.find(
    "private static void discardQueuedLinkForDifferentSnapshot(",
    lookup_start,
)
if lookup_start < 0 or lookup_end < 0:
    raise SystemExit("missing manifest lookup readiness gate")
lookup = hook[lookup_start:lookup_end]
for required in (
    "if (!hooksReady)",
    "return new ManifestLookup(null, false, false, null);",
):
    if required not in lookup:
        raise SystemExit(
            "partially installed hooks can still activate virtual behavior: "
            + required
        )

for required in (
    "private static ManifestLookup rejectedManifestLookup(",
    'manifest_rejected_cached reason=',
):
    if required not in hook:
        raise SystemExit(
            "stable manifest rejection caching is missing: " + required
        )

history_start = hook.find("private static void captureHistoryReturn")
history_end = hook.find("private static void handleLinkTarget", history_start)
if history_start < 0 or history_end < 0:
    raise SystemExit("missing native-link history return handling")
history_return = hook[history_start:history_end]
for required in (
    "if (action == null)",
    "if (action.expectedBackInfo != backInfo)",
    "Object viewModel = action.viewModel",
    "Manifest manifest = action.manifest",
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

if "param.setResult(null)" in history_return:
    raise SystemExit(
        "BackLinkUtils getters must retain the firmware's non-null result"
    )
if "manifestLookupFor(" in history_return:
    raise SystemExit(
        "history capture must retain its preflight manifest after native mutation"
    )
history_action_start = hook.find("private static void hookLinkHistoryActions")
history_action_end = hook.find(
    "private static void hookNativeSaveAcknowledgement",
    history_action_start,
)
if history_action_start < 0 or history_action_end < 0:
    raise SystemExit("missing safe Back/Original Back action guards")
history_actions = hook[history_action_start:history_action_end]
for required in (
    '"onBackClick"',
    '"onOriginalBackClick"',
    "clearQueuedLinkInvocation(viewModel)",
    "clearMixedLinkCandidate(viewModel)",
    "lockHistoryAction()",
    "ManifestLookup lookup = manifestLookupFor(viewModel)",
    "noteReaderIntent(viewModel)",
    "if (lookup.navigationBlocked())",
    "param.setResult(null)",
    'link_history_action_blocked reason=',
    "Object backInfo = peekNativeBackInfo(original)",
    "preflightSameDocumentHistory(",
    "state.linkHistory.peekOriginal(",
    "state.linkHistory.peekBack(",
    '"unresolved_same_document_history"',
    "HISTORY_ACTION.set(new HistoryActionContext(",
    "backInfo,\n                        viewModel,\n                        manifest",
    '"loadPage",\n            int.class',
    "if (context != null && !context.pageLoadAuthorized)",
    'link_history_page_load_blocked ',
    "finally {\n                    unlockHistoryAction()",
):
    if required not in history_actions:
        raise SystemExit("history action guard is missing: " + required)

history_queue_clear = history_actions.find("clearQueuedLinkInvocation(viewModel)")
history_candidate_clear = history_actions.find("clearMixedLinkCandidate(viewModel)")
history_lookup = history_actions.find(
    "ManifestLookup lookup = manifestLookupFor(viewModel)"
)
history_intent = history_actions.find("noteReaderIntent(viewModel)", history_lookup)
history_blocked = history_actions.find("if (lookup.navigationBlocked())", history_intent)
if not (
    0 <= history_queue_clear < history_candidate_clear < history_lookup
    < history_intent < history_blocked
):
    raise SystemExit(
        "Back must supersede queued and mixed-menu link intent before every "
        "blocked or native return"
    )

for required in (
    "private static final ReentrantLock HISTORY_SERIALIZATION",
    "private static void hookBackLinkSerialization()",
    "backLinkClass.getDeclaredMethods()",
    "Modifier.isStatic(modifiers)",
    "Modifier.isAbstract(modifiers)",
    "Modifier.isNative(modifiers)",
    "XposedBridge.hookMethod(method, new XC_MethodHook()",
    "HISTORY_SERIALIZATION.lock()",
    "HISTORY_SERIALIZATION.unlock()",
    'link_history_serialization_ready methods=',
):
    if required not in hook:
        raise SystemExit("native Back transaction is not serialized: " + required)
lock_index = history_actions.find("lockHistoryAction()")
external_index = history_actions.find(
    'link_history_action_native_external original='
)
unlock_index = history_actions.find("unlockHistoryAction()", external_index)
if not (0 <= lock_index < external_index < unlock_index):
    raise SystemExit("external native Back must remain inside serialization")

save_hook_start = hook.find("private static void hookNativeSaveAcknowledgement")
save_hook_end = hook.find("private static void captureHistoryReturn", save_hook_start)
if save_hook_start < 0 or save_hook_end < 0:
    raise SystemExit("missing native save acknowledgement hook")
save_hook = hook[save_hook_start:save_hook_end]
for required in (
    '"saveMarkData"',
    "String.class,\n            String.class,\n            int.class,\n            boolean.class",
    "SaveObservation observation = SAVE_OBSERVATION.get()",
    "observation.callbackObserved = true",
    "Boolean.TRUE.equals(\n                        param.getResult()",
    "param.thisObject\n                        == observation.expectedNote",
    "observation.observedPage = param.args[2]",
    "observation.sameMarkPath = sameText(",
):
    if required not in save_hook:
        raise SystemExit("native save acknowledgement hook is incomplete: " + required)

save_method_start = hook.find("private static boolean saveNativeTrails")
save_method_end = hook.find("private static void clearPendingLink", save_method_start)
if save_method_start < 0 or save_method_end < 0:
    raise SystemExit("missing native trail save gate")
save_method = hook[save_method_start:save_method_end]
for required in (
    'getBooleanField(\n                presenter,\n                "hasTrails"',
    "if (!hadTrails)",
    'objectField(presenter, "superNoteNote")',
    'intField(presenter, "currentPage", -1)',
    'objectField(presenter, "markPath")',
    "SAVE_OBSERVATION.set(observation)",
    '"saveTrails",\n                Boolean.FALSE,\n                Boolean.FALSE',
    "if (!observation.accepted())",
    'setBooleanField(presenter, "hasTrails", true)',
    'native_save_rejected reason=missing_or_failed_ack',
    'native_save_acknowledged page=',
    "SAVE_OBSERVATION.remove()",
):
    if required not in save_method:
        raise SystemExit("native trail save gate is incomplete: " + required)
save_observation_index = save_method.find("SAVE_OBSERVATION.set(observation)")
save_call_index = save_method.find('"saveTrails"', save_observation_index)
save_ack_index = save_method.find("if (!observation.accepted())", save_call_index)
save_success_log_index = save_method.find(
    'log("native_save_acknowledged page="', save_ack_index
)
save_success_index = save_method.find("return true;", save_success_log_index)
if not (
    0 <= save_observation_index < save_call_index < save_ack_index
    < save_success_log_index < save_success_index
):
    raise SystemExit("dirty trail saves can succeed before native acknowledgement")

link_hook_start = hook.find("private static void hookLinkTarget")
link_hook_end = hook.find("private static void hookViewModel", link_hook_start)
if link_hook_start < 0 or link_hook_end < 0:
    raise SystemExit("missing deferred native-link handling")
link_hook = hook[link_hook_start:link_hook_end]
for required in (
    "if (superNoteLink == null)",
    "lookup.manifest == null && !lookup.navigationBlocked()",
    "classifyLinkInvocation(superNoteLink, targetPage)",
    "VirtualSpreadNavigation.isImmediateLinkInvocation(",
    "rememberMixedLinkCandidate(",
    "private static void handleMixedLinkJump(",
    "PURE_LINK_DISPATCH.set(Boolean.TRUE)",
    "!Boolean.TRUE.equals(PURE_LINK_DISPATCH.get())",
    "state.mixedLinkCandidate = new MixedLinkCandidate(",
    "candidate.verificationGeneration",
    "lookup.verificationGeneration,\n                state.pageLoadGeneration",
    "state.mixedLinkCandidate = null",
    'mixed_link_jump_blocked reason=missing_menu_context',
    "queuedDirectJump ? \"jumpLink\" : \"showLinkJumpView\"",
    "directJumpArgumentsMatchLink(",
    'link_jump_discarded reason=direct_arguments_changed',
    "routing == VirtualSpreadNavigation.LinkRouting.NON_LINK",
    "routing == VirtualSpreadNavigation.LinkRouting.EXTERNAL",
    "authenticatedExternalLink(",
    'link_jump_passthrough kind=external authority=matched',
    'link_jump_blocked reason=unmatched_authenticated_uri',
    "ManifestLookup lookup = manifestLookupFor(viewModel)",
    "if (lookup.verificationPending)",
    "lookup.snapshotId,\n                lookup.verificationGeneration,\n                routing",
    "param.setResult(Boolean.TRUE)",
    "state.queuedLinkArguments = arguments.clone()",
    "state.queuedLinkSnapshotId = snapshotId",
    "state.queuedLinkVerificationGeneration = verificationGeneration",
    "state.queuedLinkPageLoadGeneration = state.pageLoadGeneration",
    "state.queuedLinkRouting = routing",
    "state.queuedLinkNativeDocument = nativeDocument",
    "state.queuedLinkNativeSourceAuthority = nativeSourceAuthority",
    "state.queuedLinkNativeLayoutAuthority = nativeLayoutAuthority",
    "state.queuedLinkNativeLinkAuthority = nativeLinkAuthority",
    "queuedLinkBelongsToVerification(",
    'link_jump_replay_deferred reason=verification_generation',
    "currentNativeDocument == queuedNativeDocument",
    "queuedNativeSourceAuthority.equals(nativePdfMetadata(",
    "queuedVerificationGeneration\n                        == verificationOwner.generation",
    "queuedPageLoadGeneration == currentPageLoadGeneration",
    "pendingLinkReplayIsCurrent(",
    "sameCanonicalPath(manifest.key, documentPath)",
    "snapshotId.equals(verificationOwner.snapshotId)",
    "currentRouting != queuedRouting",
    "currentRouting == VirtualSpreadNavigation.LinkRouting.INTERNAL",
    "if (!captureLinkTarget(",
    "currentRouting == VirtualSpreadNavigation.LinkRouting.EXTERNAL",
    'link_jump_discarded reason=unmatched_authenticated_uri',
    'link_jump_blocked reason=unmatched_authenticated_link',
    "REPLAYING_LINK.set(Boolean.TRUE)",
    "REPLAYING_LINK.remove()",
):
    if required not in link_hook:
        raise SystemExit(
            f"pending native link is missing authority guard: {required}"
        )
if "withPageLoadGeneration(state.pageLoadGeneration)" not in hook:
    raise SystemExit(
        "mixed native-link menu must survive verification-only state binding"
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
    "if (hasPreservedLinkViewport(viewModel))",
    "if (hasPreservedLinkViewport(state, currentPage))",
    "reason=preserved_link_viewport stage=schedule",
    "reason=preserved_link_viewport stage=retry",
):
    if required not in portrait_focus:
        raise SystemExit(
            f"portrait focus retry is missing fail-closed guard: {required}"
        )

activity_start = hook.find("private static void hookActivity")
activity_end = hook.find("private static void hookViewModel", activity_start)
if activity_start < 0 or activity_end < 0:
    raise SystemExit("missing activity hook implementation")
activity_hooks = hook[activity_start:activity_end]
screen_change_start = activity_hooks.find('"screenChange"')
configuration_start = activity_hooks.find(
    '"onConfigurationChanged"',
    screen_change_start,
)
if screen_change_start < 0 or configuration_start < 0:
    raise SystemExit("missing screen-change hook implementation")
screen_change = activity_hooks[screen_change_start:configuration_start]
for required in (
    "if (hasPreservedLinkViewport(viewModel))",
    "reason=preserved_link_viewport",
    "stage=screen_change",
    'schedulePortraitFocus(\n                                viewModel,\n                                "screen_change"',
):
    if required not in screen_change:
        raise SystemExit(
            "screen-change focus can overwrite a preserved link viewport: "
            + required
        )

page_loaded_start = hook.find("private static void handlePageLoaded")
page_loaded_end = hook.find("private static void schedulePortraitFocus", page_loaded_start)
if page_loaded_start < 0 or page_loaded_end < 0:
    raise SystemExit("missing page-loaded viewport handling")
page_loaded = hook[page_loaded_start:page_loaded_end]
page_load_state = page_loaded.find("state = readerStateLocked(viewModel)")
page_load_generation = page_loaded.find(
    "state.pageLoadGeneration++", page_load_state
)
page_load_intent_policy = page_loaded.find(
    "pageLoadPreservesDeferredLinkIntent(", page_load_generation
)
page_load_queue_clear = page_loaded.find(
    "clearQueuedLinkInvocation(state)", page_load_intent_policy
)
page_load_candidate_clear = page_loaded.find(
    "state.mixedLinkCandidate = null", page_load_queue_clear
)
page_load_manifest = page_loaded.find(
    "Manifest manifest = manifestFor(viewModel)", page_load_state
)
if not (
    0 <= page_load_state < page_load_generation < page_load_intent_policy
    < page_load_queue_clear < page_load_candidate_clear < page_load_manifest
):
    raise SystemExit(
        "real native page loads must invalidate deferred link intent before "
        "the first published-manifest binding"
    )
if (
    "private static void handleManifestActivationInitialization("
        not in page_loaded
    or "handlePageLoaded(viewModel, true, completion)" not in page_loaded
    or "handlePageLoaded(viewModel, false, completion)" not in page_loaded
    or "pageLoadPreservesDeferredLinkIntent(" not in page_loaded
    or "clearQueuedLinkInvocation(state)" not in page_loaded
    or "state.mixedLinkCandidate = null" not in page_loaded
):
    raise SystemExit(
        "synthetic manifest initialization must rebind a mixed menu while "
        "real native page loads invalidate it"
    )
for required in (
    "shouldPreservePortraitLinkViewport(",
    '"internal_link".equals(targetReason)',
    '"existing_state".equals(targetReason)',
    "state.preservedLinkViewportPage == currentPage",
    "state.preservedLinkViewportHalf == target",
    "state.preservedLinkViewportPage = currentPage",
    "state.preservedLinkViewportHalf = target",
    "clearPreservedLinkViewport(state)",
    "retainedLinkViewport",
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
    "if (manifest == null && lookup.navigationBlocked())"
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
        "native turns must fail closed while manifest authority is unresolved"
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
if "String documentKey;" not in hook:
    raise SystemExit("reader state must remember its bound canonical document")
for required in (
    "manifest.revision.equals(state.manifestRevision)",
    "state.manifestRevision = manifest.revision",
    "state.manifestVerificationGeneration",
    "verificationGeneration",
    "private static void clearManifestTransientState(",
    "private static void bindReaderStateToDocument(",
    "state.nativeSnapshotDocument = null",
    "state.nativeSnapshotRevision = null",
    "state.nativeSnapshotAccepted = false",
    "state.lastPage = -1",
    "state.pendingPage = -1",
    "state.pendingHalf = null",
    "clearPendingLink(state)",
    "clearPendingHistory(state)",
    "clearPreservedLinkViewport(state)",
    "clearQueuedLinkInvocation(state)",
    "state.linkHistory.clear()",
    "state.pageLoadGeneration++",
    "queuedLinkSurvivesVerificationBinding(",
    "mixedLinkSurvivesVerificationBinding(",
    "state.queuedLinkPageLoadGeneration = state.pageLoadGeneration",
    "retainedMixedLink",
    ".withPageLoadGeneration(state.pageLoadGeneration)",
):
    if required not in reader_state:
        raise SystemExit(
            f"reader state is not bound to the manifest revision: {required}"
        )
if "state.pageLoadGeneration = 0L" in reader_state:
    raise SystemExit(
        "reader-state generation must remain monotonic across manifest changes"
    )

lookup_start = hook.find("private static Manifest manifestFor")
lookup_end = hook.find(
    "private static void discardQueuedLinkForDifferentSnapshot",
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
    "String key = lexicalAbsolutePath(uri.getPath())",
    "observeDocumentKey(key)",
    "bindReaderStateToDocument(viewModel, key)",
    "bindReaderStateToDocument(viewModel, null)",
    "Object nativeDocument = nativePdfDocument(viewModel)",
    "Boolean nativeAuthority = nativeSnapshotClaimsVirtualSpread(",
    "if (Boolean.FALSE.equals(nativeAuthority))",
    "return new ManifestLookup(null, false, false, null)",
    "cached.nativeDocument == nativeDocument",
    "cached.verifiedAtElapsed",
    "MAX_MANIFEST_FRESHNESS_AGE_MS",
    "scheduleManifestFreshness(",
    "if (cached.manifest == null)",
    "nativeSnapshotClaimsVirtualSpread(viewModel)",
    "generatedDocumentBlocked",
    'manifest_rejected_cached ',
    "validateNativeSnapshot(viewModel, cached.manifest)",
    "validated == null",
    "scheduleManifestVerification(",
    "VerificationOwner verificationOwner = scheduleManifestVerification(",
    "boolean verificationPending = verificationOwner != null",
    "discardQueuedLinkForDifferentSnapshot(",
    "verificationOwner.snapshotId",
    "manifest_verification_pending",
    "Fail closed until the background verifier publishes",
    '"lookup_failed"',
    'observeDocumentKey(null);\n            logFailure("manifest_read_failed"',
    'return supersededManifestLookup("stale_view_model")',
    '"manifest_verification_superseded"',
    '"manifest_retry_backoff"',
    "cached.verificationGeneration",
):
    if required not in manifest_lookup:
        raise SystemExit(f"manifest lookup is missing fail-closed guard: {required}")
if '"native_snapshot_mismatch"' not in hook:
    raise SystemExit("native snapshot mismatch is missing its blocked-turn reason")
for forbidden in (
    "parseManifest(",
    "readBytes(",
    "sha256(",
    "sha256File(",
    "getCanonicalPath(",
    ".isFile()",
    "FileIdentity.capture(",
    "FileIdentity.captureRegularPath(",
    "Os.stat(",
    "Os.lstat(",
):
    if forbidden in manifest_lookup:
        raise SystemExit(
            f"manifest lookup performs expensive verification on a UI callback: {forbidden}"
        )

turn_start = hook.find("private static void handleTurn(")
turn_end = hook.find("private static void handlePageLoaded(", turn_start)
if turn_start < 0 or turn_end < 0:
    raise SystemExit("missing native turn handler")
turn_handler = hook[turn_start:turn_end]
turn_lookup = turn_handler.find("ManifestLookup lookup = manifestLookupFor(viewModel)")
turn_intent = turn_handler.find("noteReaderIntent(viewModel)", turn_lookup)
state_lookup = turn_handler.find("ReaderState state = stateFor(viewModel, manifest)")
queued_clear = turn_handler.find("clearQueuedLinkInvocation(viewModel)")
candidate_clear = turn_handler.find("clearMixedLinkCandidate(viewModel)")
pending_clear = turn_handler.find("clearPendingLink(state)", state_lookup)
activity_null = turn_handler.find("if (activity == null)", turn_lookup)
activity_block = turn_handler.find("param.setResult(null)", activity_null)
orientation_read = turn_handler.find(
    "int orientation = activity.getResources()", activity_block
)
orientation_unknown = turn_handler.find(
    "orientation != Configuration.ORIENTATION_PORTRAIT", orientation_read
)
orientation_unknown_block = turn_handler.find(
    "param.setResult(null)", orientation_unknown
)
orientation_branch = turn_handler.find(
    "if (orientation == Configuration.ORIENTATION_LANDSCAPE)", state_lookup
)
if not (
    0 <= queued_clear < candidate_clear < turn_lookup < turn_intent
    < activity_null < activity_block
    < orientation_read < orientation_unknown < orientation_unknown_block
    < state_lookup < pending_clear
    < orientation_branch
):
    raise SystemExit(
        "manual navigation must discard older queued and mixed-menu intent "
        "and fail closed until activity/orientation authority is available"
    )
if "turn_passthrough reason=no_activity" in turn_handler:
    raise SystemExit("verified turns must not pass through without an activity")

link_start = hook.find("private static void handleLinkTarget(")
link_end = hook.find("private static boolean immediateLinkArguments", link_start)
if link_start < 0 or link_end < 0:
    raise SystemExit("missing authenticated link handler")
link_handler = hook[link_start:link_end]
null_link_branch = link_handler.find("if (superNoteLink == null)")
null_link_return = link_handler.find("return;", null_link_branch)
null_link_queued_clear = link_handler.find(
    "clearQueuedLinkInvocation(viewModel)", null_link_branch
)
null_link_candidate_clear = link_handler.find(
    "clearMixedLinkCandidate(viewModel)", null_link_branch
)
if not (
    0 <= null_link_branch < null_link_queued_clear
    < null_link_candidate_clear < null_link_return
):
    raise SystemExit(
        "a newer annotation/digest-only action must cancel older queued and "
        "mixed link intent before remaining native"
    )
blocked_branch = link_handler.find(
    "if (routing == VirtualSpreadNavigation.LinkRouting.BLOCKED)"
)
blocked_branch_end = link_handler.find(
    "if (lookup.manifest != null)", blocked_branch
)
blocked_handler = link_handler[blocked_branch:blocked_branch_end]
blocked_queued_clear = blocked_handler.find(
    "clearQueuedLinkInvocation(viewModel)"
)
blocked_result = blocked_handler.find("param.setResult(Boolean.TRUE)")
if not (
    0 <= blocked_branch < blocked_branch_end
    and 0 <= blocked_queued_clear < blocked_result
):
    raise SystemExit(
        "an uninspectable current link must discard an older queued link "
        "before returning"
    )
if "param.setResult(null)" in link_handler:
    raise SystemExit(
        "blocked showLinkJumpView calls must return primitive boolean true, "
        "not a null result that crashes the firmware caller during unboxing"
    )
if "param.setResult(Boolean.FALSE)" in link_handler:
    raise SystemExit(
        "blocked showLinkJumpView calls must consume the tap; false falls "
        "through into the firmware page-turn branch"
    )
verified_branch = link_handler.find("if (lookup.manifest != null)")
verified_clear = link_handler.find(
    "clearQueuedLinkInvocation(viewModel)", verified_branch
)
external_branch = link_handler.find(
    "if (routing == VirtualSpreadNavigation.LinkRouting.EXTERNAL)",
    verified_branch,
)
capture_branch = link_handler.find("if (!captureLinkTarget(", verified_branch)
if not (
    0 <= verified_branch < verified_clear < external_branch < capture_branch
):
    raise SystemExit(
        "a newly verified link must discard an older queued invocation before "
        "external passthrough or internal capture"
    )

lookup_positions = (
    manifest_lookup.find("String key = lexicalAbsolutePath(uri.getPath())"),
    manifest_lookup.find("observeDocumentKey(key)"),
    manifest_lookup.find("bindReaderStateToDocument(viewModel, key)"),
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
    "private static Object nativePdfDocument(Object viewModel)",
    "private static Boolean nativeSnapshotClaimsVirtualSpread(",
    "VirtualSpreadNavigation.nativeMetadataClaimsVirtualSpread(",
    "nativeAuthority == null",
    "nativeAuthority.booleanValue()",
    'native_snapshot_metadata_probe_failed',
    "manifestMatchesNativeSnapshot(",
    '"info:" + key',
    '"SNVirtualSpreadSourceSHA256"',
    '"SNVirtualSpreadLayoutSHA256"',
    '"SNVirtualSpreadLinksSHA256"',
    '"SNVirtualSpreadMappingSHA256"',
    '"SNVirtualSpreadViewID"',
    '"SNVirtualSpreadGeneratorVersion"',
    "!isSha256(nativeSource)",
    "!isSha256(nativeMapping)",
    "manifest.viewId.equals(nativeViewId)",
    "GENERATOR_VERSION.equals(nativeGenerator)",
    'manifest_rejected reason=native_snapshot_metadata',
    'objectField(currentPdfMupdf, "document") != nativeDocument',
    "state.nativeSnapshotDocument = nativeDocument",
):
    if required not in hook:
        raise SystemExit(
            f"native reader snapshot binding is missing: {required}"
        )

for required in (
    "public static boolean nativeMetadataClaimsVirtualSpread(",
    "return !((String) value).trim().isEmpty();",
    "if (!(value instanceof String))",
):
    if required not in navigation:
        raise SystemExit(
            "native metadata absence/authority classification is missing: "
            + required
        )

if "nativePageCount <= 0" not in hook:
    raise SystemExit(
        "manifest activation must wait for a positive native page count"
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
    "VERIFYING.put(key, owner)",
    "existing.nativeDocument == nativeDocument",
    "VERIFYING.get(key) == owner",
    "VERIFYING.get(key) != owner",
    "VERIFYING.remove(key, owner)",
    "VERIFICATION_GENERATION.incrementAndGet()",
    "FileIdentity.captureRegularPath(pdf)",
    "FileIdentity.captureRegularPath(\n                sidecar",
    "FileInputStream pdfInput = openRegularFile(",
    "FileInputStream sidecarInput = openRegularFile(",
    "OsConstants.O_NOFOLLOW",
    "OsConstants.O_NONBLOCK",
    "OsConstants.S_ISREG(opened.st_mode)",
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
    "Throwable deterministicParseFailure = null",
    "org.json.JSONException | IllegalArgumentException error",
    "deterministicParseFailure = error",
    "pdfInput,",
    "FileIdentity pdfAfter = FileIdentity.capture(pdfInput.getFD())",
    "FileIdentity sidecarAfter = FileIdentity.capture(",
    "FileIdentity pdfPathAfter = FileIdentity.captureRegularPath(",
    "FileIdentity.captureRegularPath(sidecar)",
    "pdfOpened.matches(pdfAfter)",
    "sidecarOpened.matches(sidecarAfter)",
    "pdfAfter.matches(pdfPathAfter)",
    "sidecarAfter.matches(sidecarPathAfter)",
    "sidecarDigest.equals(currentSidecarDigest)",
    "MANIFESTS.put(key, published)",
    "LATEST_VERIFICATION_OWNER.put(key, owner)",
    "owner.nativeDocument",
    "pdfAfter.token() + \":\" + sidecarAfter.token()",
    'manifest_rejected reason=deterministic_parse path=',
    "scheduleManifestActivation(\n                            key,",
    '"manifest_rejected"',
    '"snapshot_changed_before_read"',
    '"snapshot_changed_during_read"',
    "VirtualSpreadNavigation.LinkRouting replayedRouting =",
    "replayQueuedLink(\n                        owner,",
    "manifestActivationBelongsToVerification(",
    'manifest_activation_superseded path=',
    "replayRequiresImmediateInitialization(replayedRouting)",
    "manifestActivationRequiresInitialization(\n                        viewModel,",
    'manifest_activation_deferred reason=',
    "new Handler(owner.getMainLooper()).post",
    "handleManifestActivationInitialization(viewModel)",
    '"manifest_verified"',
    "FRESHNESS_CHECKING.putIfAbsent(key, expected)",
    "private static void verifyManifestFreshness(",
    "new ManifestFreshnessTask(",
    "expected.pdfIdentity.matches(pdfCurrent)",
    "expected.sidecarIdentity.matches(sidecarCurrent)",
    "MANIFESTS.replace(key, expected, refreshed)",
    "if (refreshed.manifest != null)",
    "scheduleManifestFreshnessWakeup(key, refreshed)",
    "scheduleManifestStateInvalidation(",
    "manifestInvalidationMayClear(",
    'manifest_state_invalidation_superseded reason=',
    "VERIFICATION_RETRY_AFTER.put(key, retryToken)",
    "VERIFICATION_RETRY_AFTER.remove(key, retryToken)",
    'log("manifest_retry_ready path=" + key)',
    "deferManifestRetry(key)",
):
    if required not in manifest_verification:
        raise SystemExit(
            f"background manifest verification is missing guard: {required}"
        )

freshness_schedule_start = manifest_verification.find(
    "private static void scheduleManifestFreshness("
)
freshness_start = manifest_verification.find(
    "private static void verifyManifestFreshness("
)
freshness_end = manifest_verification.find(
    "private static void scheduleManifestStateInvalidation(",
    freshness_start,
)
if (
    freshness_schedule_start < 0
    or freshness_start < 0
    or freshness_end < 0
):
    raise SystemExit("missing freshness-verification invalidation boundary")
freshness_schedule = manifest_verification[
    freshness_schedule_start:freshness_start
]
freshness_method = manifest_verification[freshness_start:freshness_end]
invalidation_token = freshness_schedule.find(
    "captureManifestInvalidationToken("
)
freshness_task = freshness_schedule.find(
    "new ManifestFreshnessTask("
)
cache_remove = freshness_method.find("MANIFESTS.remove(key, expected)")
invalidation_schedule = freshness_method.find(
    "scheduleManifestStateInvalidation(", cache_remove
)
if not (
    0 <= invalidation_token < freshness_task
    and 0 <= cache_remove < invalidation_schedule
    and "invalidationToken" in freshness_method
):
    raise SystemExit(
        "freshness invalidation must capture the old intent token before "
        "worker dispatch and carry it across cache removal"
    )
if hook.count("noteReaderIntent(state)") < 4:
    raise SystemExit(
        "turn, link, history, queue, and mixed-menu intent must invalidate "
        "older worker tokens"
    )

verification_method_start = manifest_verification.find(
    "private static void verifyManifestSnapshot("
)
verification_method_end = manifest_verification.find(
    "private static FileInputStream openRegularFile(",
    verification_method_start,
)
if verification_method_start < 0 or verification_method_end < 0:
    raise SystemExit("missing bounded manifest-verification method")
verification_method = manifest_verification[
    verification_method_start:verification_method_end
]
verification_catch = verification_method.find(
    "} catch (Throwable throwable) {",
    verification_method.find("} catch (ManifestVerificationSuperseded"),
)
verification_finally = verification_method.find(
    "} finally {", verification_catch
)
if verification_catch < 0 or verification_finally < 0:
    raise SystemExit("missing transient manifest-verification failure path")
transient_failure = verification_method[
    verification_catch:verification_finally
]
if "new CachedManifest(" in transient_failure:
    raise SystemExit(
        "transient manifest failures must not become permanent cache entries"
    )
for required in (
    "MANIFESTS.remove(key)",
    "deferManifestRetry(key)",
    '"verification_failed"',
):
    if required not in transient_failure:
        raise SystemExit(
            "transient manifest failure is not retryable: " + required
        )

for required in (
    "new ArrayBlockingQueue<Runnable>(1)",
    "synchronized (MANIFEST_VERIFIER_LOCK)",
    "private static volatile String observedDocumentKey",
    "observedDocumentKey = key",
    "cancelManifestVerificationLocked()",
    "VERIFYING.clear()",
    "FRESHNESS_CHECKING.clear()",
    "VERIFICATION_RETRY_AFTER.clear()",
    "MANIFEST_VERIFIER.getQueue().poll()",
    "((ManifestVerificationTask) stale).cancelBeforeRun()",
    "((ManifestFreshnessTask) stale).cancelBeforeRun()",
    "new ManifestVerificationTask(",
    "requireCurrentVerification(key, owner)",
    "sha256File(pdfInput, key, owner)",
):
    if required not in hook:
        raise SystemExit(
            f"latest-only manifest verification is missing: {required}"
        )
if "Executors.newSingleThreadExecutor()" in hook:
    raise SystemExit("manifest verification must not use an unbounded queue")

observer_start = hook.find("private static void observeDocumentKey")
observer_end = hook.find(
    "private static void cancelManifestVerificationLocked", observer_start
)
cancellation_start = hook.find(
    "private static void cancelManifestVerificationLocked"
)
cancellation_end = hook.find(
    "private static VerificationOwner scheduleManifestVerification",
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

retry_start = hook.find("private static void deferManifestRetry(")
retry_end = hook.find(
    "private static VerificationOwner scheduleManifestVerification(",
    retry_start,
)
if retry_start < 0 or retry_end < 0:
    raise SystemExit("missing demand-driven manifest retry cooldown")
retry_method = hook[retry_start:retry_end]
remove_index = retry_method.find(
    "VERIFICATION_RETRY_AFTER.remove(key, retryToken)"
)
lifecycle_index = retry_method.find("if (activeActivity.get() != owner")
if not (0 <= remove_index < lifecycle_index):
    raise SystemExit("manifest retry token must retire before lifecycle checks")
if "manifestLookupFor(" in retry_method:
    raise SystemExit("manifest retry cooldown must not create an automatic loop")

scheduler_start = hook.find(
    "private static VerificationOwner scheduleManifestVerification"
)
scheduler_end = hook.find(
    "private static void requireCurrentVerification", scheduler_start
)
if scheduler_start < 0 or scheduler_end < 0:
    raise SystemExit("missing latest-only verification scheduler")
scheduler = hook[scheduler_start:scheduler_end]
scheduler_positions = (
    scheduler.find("if (!key.equals(observedDocumentKey))"),
    scheduler.find("cancelManifestVerificationLocked()"),
    scheduler.find("VERIFYING.put(key, owner)"),
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
    "key.equals(pdf.getCanonicalPath())",
    '(key + ".json").equals(sidecar.getCanonicalPath())',
)
snapshot_guard_positions = [
    manifest_verification.find(guard) for guard in snapshot_guards
]
publication = manifest_verification.find("MANIFESTS.put(key, published)")
if min(*snapshot_guard_positions, publication) < 0 or publication <= max(
    snapshot_guard_positions
):
    raise SystemExit("manifest publication must follow every snapshot check")
deterministic_parse = manifest_verification.find(
    "deterministicParseFailure = error"
)
deterministic_cache = manifest_verification.find(
    "MANIFESTS.put(key, published)", deterministic_parse
)
deterministic_log = manifest_verification.find(
    'manifest_rejected reason=deterministic_parse path=', deterministic_cache
)
if not (
    0 <= deterministic_parse < max(snapshot_guard_positions)
    < deterministic_cache < deterministic_log
):
    raise SystemExit(
        "deterministic manifest failures must be cached only after every "
        "snapshot identity check"
    )

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
    "FileIdentity sidecarBefore = FileIdentity.captureRegularPath(",
    "FileInputStream sidecarInput = openRegularFile(",
    "String sidecarDigest = sha256(sidecarData)",
    'exactManifestString(output, "sha256")',
    "sha256File(pdfInput, key, owner)",
    "VirtualSpreadLinkAuthority.readPdfSourceDigest(pdfInput)",
    'manifest_rejected reason=output_hash',
    'manifest_rejected reason=snapshot_changed_during_read',
    'root.opt("coverSeparate")',
    "sourcePagesJson.length() != sourcePageCount",
    'JSONArray linksJson = root.optJSONArray("links")',
    "linksJson == null",
    "spreadEntryMatches(",
    "parseMappingRecord(",
    "mappingHasFrozenFieldSet(",
    "linkEndpointMatches(",
    "exactManifestInteger(",
    "VirtualSpreadNavigation.exactJsonInteger(",
    "VirtualSpreadNavigation.exactJsonString(",
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
    '"mappingAuthoritySha256"',
    "VirtualSpreadLinkAuthority.readPdfMappingDigest(pdfInput)",
    'exactManifestString(output, "viewId")',
    'exactManifestString(\n            output, "cacheBasename"',
    'manifest_rejected reason=cache_basename',
    "VirtualSpreadLinkAuthority.readPdfViewDigest(pdfInput)",
    "VirtualSpreadLinkAuthority.mapping(",
    "VirtualSpreadLinkAuthority.mappingDigest(",
    "VirtualSpreadLinkAuthority.viewId(",
    "VirtualSpreadLinkAuthority.outputBasename(",
    'expectedCacheBasename.equals(new File(key).getName())',
    'manifest_rejected reason=cache_basename_path',
    "VirtualSpreadLinkAuthority.layout(",
    "VirtualSpreadLinkAuthority.layoutDigest(",
    "VirtualSpreadLinkAuthority.uri(",
    "ArrayList<VirtualSpreadNavigation.UriTarget> uriLinks",
    "uriLinks.add(new VirtualSpreadNavigation.UriTarget(",
    "uriLinks.toArray(",
    "VirtualSpreadLinkAuthority.internal(",
    "VirtualSpreadLinkAuthority.digest(",
    'manifest_rejected reason=link_authority_records',
    'manifest_rejected reason=layout_authority',
    'manifest_rejected reason=layout_authority_records',
    'manifest_rejected reason=cover_layout',
    'manifest_rejected reason=source_mapping',
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

cache_basename_read = manifest_validation.find(
    'String expectedCacheBasename = exactManifestString('
)
cache_basename_guard = manifest_validation.find(
    "if (expectedCacheBasename == null)", cache_basename_read
)
cache_basename_dereference = manifest_validation.find(
    "expectedCacheBasename.", cache_basename_read
)
if not (
    0 <= cache_basename_read
    < cache_basename_guard
    < cache_basename_dereference
):
    raise SystemExit(
        "missing/non-string cacheBasename must be rejected before any "
        "dereference"
    )
cache_basename_guard_region = manifest_validation[
    cache_basename_guard:cache_basename_dereference
]
for required in (
    'manifest_rejected reason=cache_basename',
    "return null;",
):
    if required not in cache_basename_guard_region:
        raise SystemExit(
            "malformed cacheBasename guard must deterministically reject: "
            + required
        )

sha256_start = hook.find("private static boolean isSha256(String value)")
sha256_end = hook.find("private static boolean isPortrait", sha256_start)
if sha256_start < 0 or sha256_end < 0:
    raise SystemExit("missing manifest SHA-256 validator")
sha256_validation = hook[sha256_start:sha256_end]
for required in (
    "value == null || value.length() != 64",
    "current >= '0' && current <= '9'",
    "current >= 'a' && current <= 'f'",
):
    if required not in sha256_validation:
        raise SystemExit(
            "manifest SHA-256 validation must require lowercase hex: "
            + required
        )
for forbidden in ("current >= 'A'", "current <= 'F'"):
    if forbidden in sha256_validation:
        raise SystemExit(
            "manifest SHA-256 validation must reject uppercase hex: "
            + forbidden
        )

for required in (
    "PDF_MIN_PAGE_DIMENSION = 3.0",
    "PDF_MAX_PAGE_DIMENSION = 14400.0",
    "pageWidth < PDF_MIN_PAGE_DIMENSION",
    "pageWidth > PDF_MAX_PAGE_DIMENSION",
    "pageHeight < PDF_MIN_PAGE_DIMENSION",
    "pageHeight > PDF_MAX_PAGE_DIMENSION",
):
    if required not in navigation:
        raise SystemExit(
            f"runtime PDF page-size validation is missing: {required}"
        )

for required in (
    "determinant <= 0.0",
    "sameRawDouble(a, expectedA)",
    "Double.doubleToRawLongBits(left)",
    "mappingRoundTripsAreStable(",
    "Math.abs(spreadX - expectedSpreadX) > 1.0e-12",
    "Math.abs(restoredNormalizedX - normalizedX) > 1.0e-12",
):
    if required not in navigation:
        raise SystemExit(
            "runtime mapping-contract parity is missing: " + required
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
if 'android:versionCode="28"' not in manifest:
    raise SystemExit("unexpected virtual-spread package version code")
if 'android:versionName="0.0.26"' not in manifest:
    raise SystemExit("unexpected virtual-spread package version name")
if 'private static final String VERSION = "0.0.26"' not in hook:
    raise SystemExit("runtime and package versions must remain aligned")
if (
    'android:name="xposedscope"' not in manifest
    or 'android:value="com.supernote.document"' not in manifest
):
    raise SystemExit("legacy LSPosed scope metadata is missing")
if "RandomAccessFile" in hook:
    raise SystemExit("runtime verification must not reopen paths with RandomAccessFile")

build_script = (root / "build.ps1").read_text(encoding="utf-8")
payload_update = build_script.find("& jar uf $unsignedApk")
payload_failure = build_script.find(
    'throw "APK payload injection failed with exit code $LASTEXITCODE"'
)
zipalign = build_script.find("& $zipalign", payload_update)
if not (0 <= payload_update < payload_failure < zipalign):
    raise SystemExit("APK payload injection must fail before zip alignment")
for required in (
    "$archiveEntries = @(& jar tf $unsignedApk)",
    "'classes.dex'",
    "'assets/xposed_init'",
    "'META-INF/xposed/scope.list'",
    'throw "APK payload is missing required entry: $requiredEntry"',
):
    if required not in build_script[payload_update:zipalign]:
        raise SystemExit(f"APK payload verification is missing: {required}")
for required in (
    "[switch]$SkipTests",
    "[switch]$AlignedOnly",
    "if ($SkipTests -and -not $AlignedOnly)",
    "if (-not $SkipTests)",
):
    if required not in build_script:
        raise SystemExit(f"clean release assembly guard is missing: {required}")
aligned_return = build_script.find("if ($AlignedOnly) {", zipalign)
signing = build_script.find("& $apksigner sign", aligned_return)
if not (
    0 <= zipalign < aligned_return < signing
    and "return" in build_script[aligned_return:signing]
):
    raise SystemExit("aligned-only assembly must return before signing")
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

viewport_authority = (
    root
    / "src/com/techrebbe/supernote/virtualspread/NativeViewportAuthority.java"
).read_text(encoding="utf-8")
viewport_provider = (
    root
    / "src/com/techrebbe/supernote/virtualspread/NativeViewportProvider.java"
).read_text(encoding="utf-8")
viewport_generation_fence = (
    root
    / "src/com/techrebbe/supernote/virtualspread/NativeViewportGenerationFence.java"
).read_text(encoding="utf-8")
viewport_completion_authority = (
    root
    / "src/com/techrebbe/supernote/virtualspread/NativeViewportCompletionAuthority.java"
).read_text(encoding="utf-8")
for required in (
    '"rtl-reader-native-viewport-v1"',
    '\\"schemaVersion\\":1',
    '\\"nativePageSize\\"',
    '\\"spreadToNative\\"',
    "positiveZero(coefficients[index])",
    "requireStable(coefficients)",
    "requireSpreadInsideNative(",
    "requireNumericRenderOffset(",
):
    if required not in viewport_authority:
        raise SystemExit(
            "native viewport authority is missing a frozen invariant: "
            + required
        )
for required in (
    "boundViewModel == liveViewModel",
    "boundPageInfo == livePageInfo",
    "boundGeneration == currentGeneration",
):
    if required not in viewport_completion_authority:
        raise SystemExit(
            "native viewport completion binding is incomplete: " + required
        )
for forbidden in (
    '"nativeToSpread"',
    "invert",
    "inverse",
):
    if forbidden in viewport_authority:
        raise SystemExit(
            "native viewport authority must publish only the forward transform: "
            + forbidden
        )
for required in (
    '"com.supernote.document"',
    '"com.ratta.supernote.pluginhost"',
    "Binder.getCallingUid() != Process.SYSTEM_UID",
    "getCallingPackage()",
    "sessionToken.linkToDeath(this, 0)",
    'response.putString("status", "unavailable")',
    'sidecarPath.equals(documentPath + ".json")',
    'snapshotId.equals(pdfIdentity + ":" + sidecarIdentity)',
    'request.getString("generatedPdfSha256")',
    'request.getString("sidecarSha256")',
    'request.getString("mappingAuthoritySha256")',
    'METHOD_BEGIN_LOAD = "begin_load_v1"',
    "LOAD_FENCE.accepts(",
    "LOAD_FENCE.begin(",
    "LOAD_FENCE.clear(",
):
    if required not in viewport_provider:
        raise SystemExit(
            "native viewport provider is missing a fail-closed invariant: "
            + required
        )
for required in (
    "requestedGeneration <= generation",
    "requestedGeneration == generation",
    "session.equals(requestedSession)",
):
    if required not in viewport_generation_fence:
        raise SystemExit(
            "native viewport page-load fence is incomplete: " + required
        )
for required in (
    'android:name="com.techrebbe.supernote.virtualspread.NativeViewportProvider"',
    'android:authorities="com.techrebbe.supernote.virtualspread.viewport"',
    'android:exported="true"',
    'android:grantUriPermissions="false"',
):
    if required not in manifest:
        raise SystemExit(
            "native viewport provider manifest declaration is missing: "
            + required
        )
for required in (
    "NativeViewportAuthority.fromNativeRender(",
    "NativeViewportAuthority\n                .requireNumericRenderOffset(",
    "private static volatile boolean nativeViewportMayBePublished;",
    "nativeViewportMayBePublished = true;",
    "activity == null || !nativeViewportMayBePublished",
    "nativeViewportMayBePublished = false;",
    'publication.putBinder(\n                "sessionToken", NATIVE_VIEWPORT_SESSION',
    '"loadPage",\n            int.class,\n            Integer.class',
    '"onPageLoaded",\n            TARGET_PAGE_INFO',
    "NativeViewportProvider.METHOD_BEGIN_LOAD",
    "NATIVE_VIEWPORT_COMPLETION = new ThreadLocal<>();",
    "NativeViewportCompletionAuthority.isCurrent(",
    "NativeViewportCompletionAuthority\n"
    "                            .isCurrentWorkerPage(page, livePage)",
    '"current_page_worker"',
    "pageInfo != completedPageInfo",
    '"reason=unmatched_before_state"',
    '"native_viewport_completion_rejected reason=stale "',
    'state.nativeViewportLoadPending = true;',
    "NativeViewportLifecycleAuthority.pendingAfterStateBinding(",
    "NativeViewportLifecycleAuthority\n"
    "                        .pendingAfterUnpublishedCompletion(",
    '"native_viewport_completion_deferred "',
    "NativeViewportLifecycleAuthority\n                        .mayClearForDestroyedActivity(",
    'clearNativeViewport(activity, "activity_destroyed")',
    'log("activity_destroyed active_owner=" + activeOwner)',
    'clearNativeViewport(activeActivity.get(), reason)',
):
    if required not in hook:
        raise SystemExit(
            "runtime viewport publication lifecycle is incomplete: "
            + required
        )
unbound_guard = hook.find("if (completion == null) {")
pending_clear = hook.find(
    "state.nativeViewportLoadPending = false;",
    unbound_guard + 1,
)
if unbound_guard < 0 or pending_clear < 0 or unbound_guard > pending_clear:
    raise SystemExit(
        "unbound native viewport completions must return before load state "
        "is cleared"
    )
for forbidden in (
    'intMethod(pageInfo, "getOffsetX", 0)',
    'intMethod(pageInfo, "getOffsetY", 0)',
):
    if forbidden in hook:
        raise SystemExit(
            "native viewport render offsets must not use fallback values: "
            + forbidden
        )

workflow = (root.parent / ".github/workflows/build.yml").read_text(
    encoding="utf-8"
)
if "run: ./virtual-spread-module/test.ps1" not in workflow:
    raise SystemExit(
        "CI must run the complete virtual-spread companion test script"
    )
if "run: python scripts/test_mapping_contract.py" not in workflow:
    raise SystemExit("CI must run the frozen mapping contract tests")
if (
    "./virtual-spread-module/build.ps1" not in workflow
    or "-DebugKeystore $env:VIRTUAL_SPREAD_KEYSTORE" not in workflow
):
    raise SystemExit(
        "CI must build and verify the virtual-spread companion APK with "
        "the selected signing key"
    )
parsed_workflow = yaml.safe_load(workflow)
if not isinstance(parsed_workflow, dict):
    raise SystemExit("workflow YAML must decode to an object")
if parsed_workflow.get("permissions") != {"contents": "read"}:
    raise SystemExit("workflow token permissions must be explicitly read-only")
jobs = parsed_workflow.get("jobs")
if not isinstance(jobs, dict):
    raise SystemExit("workflow jobs must decode to an object")
test_job = jobs.get("virtual-spread-tests")
assembly_job = jobs.get("virtual-spread-release-assembly")
release_job = jobs.get("virtual-spread-release-apk")
if any(
    not isinstance(job, dict)
    for job in (test_job, assembly_job, release_job)
):
    raise SystemExit(
        "workflow must contain test, clean assembly, and release jobs"
    )
assert isinstance(assembly_job, dict)
if release_job.get("if") != (
    "github.event_name == 'push' && github.ref == 'refs/heads/main'"
):
    raise SystemExit("protected release job is not restricted to main pushes")
if assembly_job.get("if") != (
    "github.event_name == 'push' && github.ref == 'refs/heads/main'"
) or assembly_job.get("needs") != "virtual-spread-tests":
    raise SystemExit("clean assembly must follow tests on trusted main only")
if release_job.get("needs") != "virtual-spread-release-assembly":
    raise SystemExit("protected release job must depend on clean assembly")
if release_job.get("environment") != "virtual-spread-release":
    raise SystemExit("protected release job must use its signing environment")
test_steps = test_job.get("steps")
assembly_steps = assembly_job.get("steps")
release_steps = release_job.get("steps")
if any(
    not isinstance(steps, list)
    for steps in (test_steps, assembly_steps, release_steps)
):
    raise SystemExit("workflow job steps must be lists")
assert isinstance(assembly_steps, list)


def require_named_step(steps: list[object], name: str) -> dict[str, object]:
    matches = [
        step
        for step in steps
        if isinstance(step, dict) and step.get("name") == name
    ]
    if len(matches) != 1:
        raise SystemExit(f"workflow must contain one step named {name!r}")
    return matches[0]


all_steps: list[dict[str, object]] = []
for job_name, job in jobs.items():
    if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
        raise SystemExit(f"workflow job has invalid steps: {job_name}")
    for step in job["steps"]:
        if not isinstance(step, dict):
            raise SystemExit(f"workflow job has a non-object step: {job_name}")
        all_steps.append(step)
        uses = step.get("uses")
        if uses is not None and (
            not isinstance(uses, str)
            or re.fullmatch(r"[^/@]+/[^@]+@[0-9a-f]{40}", uses) is None
        ):
            raise SystemExit(f"workflow action is not commit-pinned: {uses}")
        if isinstance(uses, str) and uses.startswith("actions/checkout@"):
            settings = step.get("with")
            if not isinstance(settings, dict) or settings.get(
                "persist-credentials"
            ) is not False:
                raise SystemExit("workflow checkout must not persist credentials")

ephemeral_step = require_named_step(
    test_steps, "Prepare ephemeral companion signing key"
)
ephemeral_run = str(ephemeral_step.get("run", ""))
if (
    ephemeral_step.get("id") != "companion-signing"
    or "-validity 2" not in ephemeral_run
    or 'echo "sha256=$fingerprint" >> "$GITHUB_OUTPUT"' not in ephemeral_run
):
    raise SystemExit("pull-request CI must identify its two-day ephemeral signer")
test_build_step = require_named_step(
    test_steps, "Build and verify virtual-spread companion APK"
)
test_build_run = str(test_build_step.get("run", ""))
test_build_env = test_build_step.get("env")
if (
    "-ExpectedSignerSha256 $env:EXPECTED_SIGNER_SHA256"
    not in test_build_run
    or not isinstance(test_build_env, dict)
    or "steps.companion-signing.outputs.sha256"
    not in str(test_build_env.get("EXPECTED_SIGNER_SHA256", ""))
):
    raise SystemExit("pull-request CI must verify its selected APK certificate")
mismatch_step = require_named_step(
    test_steps, "Reject mismatched virtual-spread companion signer"
)
if (
    "-ExpectedSignerSha256 ('0' * 64)"
    not in str(mismatch_step.get("run", ""))
    or "certificate does not match the expected release signer"
    not in str(mismatch_step.get("run", ""))
):
    raise SystemExit("pull-request CI must reject a mismatched APK certificate")
prepare_input = require_named_step(
    assembly_steps, "Prepare clean aligned APK evidence"
)
upload_input = require_named_step(
    assembly_steps, "Upload clean aligned APK for protected signing"
)
assembly_build = require_named_step(
    assembly_steps,
    "Assemble aligned APK without Python or signing credentials",
)
if (
    "-SkipTests -AlignedOnly" not in str(assembly_build.get("run", ""))
    or "virtual-spread-aligned.apk.sha256"
    not in str(prepare_input.get("run", ""))
    or upload_input.get("uses")
    != "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
    or "virtual-spread-release-input-${{ github.sha }}"
    not in str(upload_input.get("with", {}))
):
    raise SystemExit("clean no-Python assembly must publish release input")
assembly_text = str(assembly_job)
if any(
    forbidden in assembly_text
    for forbidden in (
        "actions/setup-python@",
        "pip install",
        "VIRTUAL_SPREAD_APK_KEYSTORE_BASE64",
    )
):
    raise SystemExit(
        "clean assembly must not load Python packages or signing secrets"
    )
release_text = str(release_job)
if any(
    forbidden in release_text
    for forbidden in (
        "actions/checkout@",
        "actions/setup-python@",
        "pip install",
        "build.ps1",
    )
):
    raise SystemExit(
        "protected signer job must not checkout or execute project code"
    )
download_input = require_named_step(
    release_steps, "Download tested aligned APK"
)
verify_input = require_named_step(
    release_steps, "Verify tested aligned APK digest"
)
if (
    download_input.get("uses")
    != "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093"
    or "virtual-spread-release-input-${{ github.sha }}"
    not in str(download_input.get("with", {}))
    or "sha256sum --check --strict"
    not in str(verify_input.get("run", ""))
):
    raise SystemExit(
        "protected signer must verify the tested aligned APK artifact"
    )
secret_reference = "secrets.VIRTUAL_SPREAD_APK_KEYSTORE_BASE64"
if secret_reference in str(test_job):
    raise SystemExit("pull-request-controlled CI can access the stable signer")
signer_step = require_named_step(
    release_steps, "Sign, verify, and remove protected signing key"
)
signer_env = signer_step.get("env")
signer_run = signer_step.get("run")
if not isinstance(signer_env, dict) or secret_reference not in str(
    signer_env.get("KEYSTORE_BASE64", "")
):
    raise SystemExit("stable signer secret must be scoped to the signing step")
if not isinstance(signer_run, str) or any(
    marker not in signer_run
    for marker in (
        "try {",
        "finally {",
        "$env:KEYSTORE_BASE64 = $null",
        "[Array]::Clear($bytes, 0, $bytes.Length)",
        "[Guid]::NewGuid().ToString('N')",
        "Remove-Item -LiteralPath $stablePath -Force",
        "& $apksigner sign",
        "virtual-spread-aligned.apk",
        "Expected exactly one APK signer certificate",
        "APK signer certificate does not match the expected release signer",
    )
):
    raise SystemExit("protected signer must be verified and deleted in one step")
if not (
    signer_run.find("$env:KEYSTORE_BASE64 = $null")
    < signer_run.find("& $apksigner sign")
):
    raise SystemExit("stable credential must leave environment before signing")
if [step for step in all_steps if secret_reference in str(step)] != [signer_step]:
    raise SystemExit("stable signer must appear only in its protected step")
upload_step = require_named_step(
    release_steps, "Upload upgrade-compatible companion APK"
)
if upload_step.get("uses") != (
    "actions/upload-artifact@"
    "ea165f8d65b6e75b540449e92b4886f43607fa02"
):
    raise SystemExit("protected APK upload action must remain commit-pinned")

generator = (root.parent / "virtual_spread/generate_virtual_spread.py").read_text(
    encoding="utf-8"
)
for required in (
    'SCHEMA = MANIFEST_SCHEMA',
    'PUBLICATION_SCHEMA = "techrebbe.supernote.virtual-spread-publication/v2"',
    '"techrebbe.supernote.virtual-spread-source-commit/v1"',
    'SOURCE_AUTHORITY_MARKER = b"%SNVirtualSpreadSourceSHA256:"',
    'MAPPING_AUTHORITY_MARKER = b"%SNVirtualSpreadMappingSHA256:"',
    'VIEW_AUTHORITY_MARKER = b"%SNVirtualSpreadViewSHA256:"',
    "source_hash,",
    'LEGACY_PUBLICATION_SCHEMA = "techrebbe.supernote.virtual-spread-publication/v1"',
    "class AmbiguousPublicationMarkerError(",
    "object_pairs_hook=_publication_marker_object",
    "def _publication_path_matches(",
    "os.path.normcase(actual)",
    "os.path.normcase(str(_lexical_absolute(expected)))",
    "def _filesystem_paths_collide(",
    "os.path.samefile(first, second)",
    "def _require_distinct_publication_paths(",
    "not _publication_path_matches(transaction.get(key), value)",
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
    "def _require_publication_manifest_hash(",
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
    "PDF_MIN_PAGE_DIMENSION = 3.0",
    "PDF_MAX_PAGE_DIMENSION = 14400.0",
    "Spread dimensions must remain within the PDF page-size bounds",
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
    "writer.pdf_header = reader.pdf_header",
    "verification.pdf_header != reader.pdf_header",
    '"Written PDF did not preserve the source PDF version"',
    "def _publication_reserved_paths(",
    "def _publication_staging_artifacts(",
    'output_path.with_name(f".{output_path.name}.tmp")',
    'manifest_path.with_name(f".{manifest_path.name}.tmp")',
    "active_staged_paths: tuple[Path, ...] = ()",
    "Orphaned virtual-spread staged artifact requires recovery",
    "Authenticate the entire cleanup set before deleting any entry.",
    "return expected",
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
    "if len(set(points)) != 4:",
    "perimeter = (points[0], points[1], points[3], points[2])",
    'mode in {"/FitB", "/FitH", "/FitBH", "/FitV", "/FitBV"}',
    'NameObject("/FitR")',
    '"targetView": (',
    "expected_output_identity=temporary_output_identity",
    "expected_output_hash=temporary_output_hash",
    "expected_output_state=expected_output_state",
    "expected_manifest_state=expected_manifest_state",
    "replace_authorized=force",
    "source_commit_evidence: PublicationSourceEvidence | None = None",
    "def _publication_source_commit_artifacts(",
    "def _write_source_commit_record(",
    "def _validated_source_commit_record(",
    "source_validation_required: bool = False",
    "commit_allowed = source_commit_evidence is None",
    "and source_commit_authorizes",
    "def _recover_orphaned_source_commit(",
    "allow_commit=commit_allowed",
    "source_commit_evidence=PublicationSourceEvidence(",
    'transaction["_oldOutputIdentity"] = expected_output_state.identity',
    'transaction["_oldManifestIdentity"] = expected_manifest_state.identity',
    'transaction["_markerIdentity"] = marker_identity',
    'transaction["_markerSha256"] = marker_hash',
    "lexical_output = _require_unaliased_output_path(output_path)",
    "lexical_manifest = _require_runtime_manifest_path(",
    "with _publication_lock(lexical_output) as ownership_guard:",
    "yield ownership",
    "def _publication_lock_path(output_path: Path)",
    "manifest_path = _runtime_manifest_path(output_path)",
    "getattr(os, \"O_NOFOLLOW\", 0)",
    "getattr(os, \"O_NONBLOCK\", 0)",
    "lock_path, descriptor, directory_descriptor",
    "def _acquire_publication_directory_lock(",
    "_require_open_directory_identity(lock_path.parent, descriptor)",
    "directory_descriptor = _acquire_publication_directory_lock(",
    "self.directory_descriptor",
    "_validate_publication_ownership(ownership_guard)",
    "class _PublicationNamespace:",
    "source_dir_fd=self.directory_descriptor",
    "target_dir_fd=self.directory_descriptor",
    "dir_fd=self.directory_descriptor",
    "def _publication_open_file(",
    "def _publication_unlink(",
    "Never expose the marker name until a complete, fsynced JSON record",
    'staged_marker = _temporary_neighbor(',
    '".publish-marker.tmp"',
    "def _posix_rename_noreplace(",
    "RENAME_NOREPLACE = 1",
    "renameat2(RENAME_NOREPLACE)",
    "The post-move mismatch is inherently ambiguous",
    "Preserve the ambiguous target exactly where it is",
    "def _publication_paths_share_inode(",
    "Interrupted publication target",
    "def _temporary_neighbor(",
    "namespace.open_file(candidate, flags, 0o600)",
    "class StagedPublicationFile:",
    "descriptor = os.dup(retained_descriptor)",
    "retained_descriptor=temporary_manifest.descriptor",
    "_require_staged_path_identity(",
    "def _release_staged_artifact_for_move(",
    "_close_staged_artifact(",
    "PdfReader(verification_stream, strict=True)",
    "with tempfile.TemporaryFile(",
    "_publication_sha256(path, ownership_guard)",
    "opened_before_stat = os.fstat(stream.fileno())",
    "if not stat.S_ISREG(opened_before_stat.st_mode)",
    "_sha256_open_file_exact(\n            stream,\n            opened_before.size,",
    "opened_after = _identity(os.fstat(stream.fileno()))",
    "opened_before != opened_after",
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
    "        final_evidence,\n    ) in entries:",
    "replace_existing=False",
    "temporary_manifest,\n"
    "            manifest_path,\n"
    "            replace_existing=False,\n"
    "            ownership_guard=ownership_guard,\n"
    "            expected_source_identity=published_manifest_identity",
    "published_manifest_identity = _durable_replace(",
    "temporary_output,\n"
    "            output_path,\n"
    "            replace_existing=False,\n"
    "            ownership_guard=ownership_guard,\n"
    "            expected_source_identity=published_output_identity",
    "published_output_identity = _durable_replace(",
    "backup,\n"
    "                    final_path,\n"
    "                    replace_existing=False,\n"
    "                    ownership_guard=ownership_guard,\n"
    "                    expected_source_identity=backup_identity",
    "replace_existing=False",
    "def _retired_publication_artifacts(",
    "secrets.token_hex(RETIREMENT_TOKEN_BYTES)",
    "Publication removal requires authenticated identity",
    "expected_identity=identity",
    "outcome not in {\"committed\", \"rolled_back\", \"discarded\"}",
    "current_marker_identity, _ = _publication_file_evidence(",
    "def _read_publication_marker(",
    "marker_bytes = stream.read(MAX_MANIFEST_BYTES + 1)",
    "marker_bytes.decode(\"utf-8\")",
    "transaction, marker_identity, marker_hash = _read_publication_marker(",
    "committed_output_identity=published_output_identity",
    "committed_manifest_identity=published_manifest_identity",
    "def _legacy_publication_pre_mutation_states(",
    "def require_settled_pair()",
    '"Missing authenticated settled-pair evidence"',
    "settled_output_state = PublicationTargetState(",
    "settled_manifest_state = PublicationTargetState(",
    "settled_states[final_path] = PublicationTargetState(",
    "path_identity.changed_ns == open_identity.changed_ns",
    "_same_file_after_namespace_move(\n"
    "                            final_identity, restored_identity",
    '"layoutAuthoritySha256": layout_authority_hash',
    '"/SNVirtualSpreadLayoutSHA256": layout_authority_hash',
    '"mappingAuthoritySha256": mapping_authority_hash',
    '"/SNVirtualSpreadMappingSHA256": mapping_authority_hash',
    '"viewId": spread_view_id',
    '"/SNVirtualSpreadViewID": spread_view_id',
):
    if required not in generator:
        raise SystemExit(
            f"generator is missing durable/layout authority invariant: {required}"
        )

generator_tests = (root.parent / "scripts/test_virtual_spread.py").read_text(
    encoding="utf-8"
)
for required in (
    "test_source_pdf_version_is_preserved",
    "test_staged_output_swap_is_rejected_at_publication_boundary",
    "test_same_content_staged_output_replacement_is_rejected",
    "test_obsolete_marker_without_backups_is_discarded",
    "test_discarded_marker_revalidates_pair_before_retirement",
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
    "test_pdf_page_dimension_bounds_are_enforced",
    "test_posix_identity_comparison_includes_ctime",
    "test_recovery_preserves_unexpected_target_in_front_of_backup",
    "test_staged_tamper_before_move_preserves_original_pair",
    "test_retained_staging_inode_prevents_source_hardlink_write",
    "test_no_force_preserves_targets_that_appear_during_generation",
    "test_force_late_targets_require_explicit_replacement_layout",
    "test_final_publication_never_replaces_a_late_target",
    "test_recovery_never_replaces_a_target_that_appears_before_restore",
    "test_recovery_never_deletes_a_replaced_new_target",
    "test_rollback_revalidates_pair_before_retiring_evidence",
    "test_unknown_xyz_left_fails_closed_even_matching_transform",
    "test_null_destination_coordinates_reject_different_transforms",
    "test_destination_operands_require_pdf_name_and_numbers",
    "test_link_quad_points_are_preserved_and_transformed",
    "test_malformed_link_quad_points_fail_closed",
    "test_ltr_generation_is_rejected_before_publication",
    "test_link_annotation_flags_are_preserved",
    "test_no_rotate_link_on_rotated_page_fails_closed",
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
    "test_relative_uri_action_fails_closed",
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
    "test_publication_marker_paths_use_filesystem_case_semantics",
    "test_runtime_manifest_uses_output_derived_case_spelling",
    "test_case_equivalent_manifest_is_republished_with_exact_name",
    "test_distinct_paths_follow_host_case_semantics",
    "test_existing_hardlink_source_output_is_rejected_without_mutation",
    "test_path_identity_inspection_error_fails_closed",
    "test_case_equivalent_source_output_is_rejected_without_mutation",
    "test_cli_reports_output_derived_manifest_spelling",
    "test_forced_replacement_requires_all_layout_options",
    "test_recovery_rejects_unauthenticated_retired_artifacts",
    "test_cleanup_carries_identity_for_every_removed_artifact",
    "test_cleanup_never_deletes_a_replaced_backup",
    "test_cleanup_never_deletes_replaced_stage_or_marker",
    "test_cleanup_rejects_backup_for_absent_original",
    "test_unique_retirement_preserves_a_replaced_entry",
    "test_retirement_keeps_identity_bound_bytes_in_inert_retention",
    "test_retirement_preserves_a_late_path_replacement",
    "test_retirement_never_mutates_a_late_hardlink_alias",
    "test_no_zoom_link_on_scaled_page_fails_closed",
    "test_publication_staging_paths_are_deterministic",
    "test_recovery_preserves_orphaned_deterministic_staging",
    "test_recovery_removes_authenticated_deterministic_staging",
    "test_recovery_preserves_mismatched_deterministic_staging",
    "test_interrupted_marker_write_never_exposes_partial_record",
    "test_marker_parse_is_bound_to_authenticated_handle",
    "test_unguarded_marker_publication_is_atomically_exclusive",
    "test_unguarded_posix_no_replace_uses_atomic_rename",
    "test_posix_no_replace_never_unlinks_recreated_source",
    "test_posix_no_replace_preserves_ambiguous_target_after_source_swap",
    "test_posix_no_replace_never_moves_a_replaced_destination_back",
    "test_recovery_accepts_interrupted_posix_backup_hard_link",
    "test_committed_cleanup_revalidates_pair_before_backup_retirement",
    "test_runtime_float_link_rect_is_rejected",
    "test_source_replacement_at_publication_commit_rolls_back_pair",
):
    if required not in generator_tests:
        raise SystemExit(
            "generator is missing staged-output publication regression: "
            f"{required}"
        )

for required in (
    "ANNOTATION_FLAG_NO_ZOOM = 0x0008",
    "Cannot preserve NoZoom link annotation flag through page scaling",
    'path.name + ".retained."',
    "Never truncate or",
    "late hard link remains byte-for-byte intact",
    "expected_source_identity=retired_identity",
):
    if required not in generator:
        raise SystemExit(
            "generator is missing reviewed fail-closed cleanup/link behavior: "
            + required
        )
if "_publication_unlink(retired," in generator:
    raise SystemExit(
        "retired publication cleanup must not delete an untrusted pathname"
    )
if "os.ftruncate(" in generator:
    raise SystemExit(
        "retired publication cleanup must not mutate an inode that may gain "
        "a late hard-link alias"
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
    "_finish_publication_transaction(", published_output_hash
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
if generator.count("_require_distinct_publication_paths(") != 4:
    raise SystemExit(
        "filesystem-aware path distinctness must be enforced at all three "
        "publication layers"
    )
if "len({source_path, output_path, manifest_path})" in generator or (
    "len({resolved_source, lexical_output, lexical_manifest})" in generator
):
    raise SystemExit(
        "case-sensitive Path sets must not guard publication distinctness"
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
for required in (
    "_resolve_layout_options(",
    "replacing=force and (",
    "expected_output_state.exists or expected_manifest_state.exists",
    "Forced replacement requires explicit cover, spread width",
):
    if required not in generator:
        raise SystemExit(
            "forced regeneration can reset persisted layout state: " + required
        )
for required in (
    "def _reject_retired_publication_artifacts(",
    "_reject_retired_publication_artifacts(\n        output_path,",
    "Retired publication artifact requires manual recovery",
    "replace_existing=False,\n            ownership_guard=ownership_guard",
):
    if required not in generator:
        raise SystemExit(
            "publication recovery does not preserve untrusted retired artifacts: "
            + required
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
