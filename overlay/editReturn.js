'use strict';
// Pure page-selection and Edit/Return logic for RTL Reader. No React Native,
// device, or filesystem access: everything here is host-testable
// (scripts/test_edit_return.js). App.js owns rendering and native calls.
//
// Model: "Edit page N" saves lastPageIndex=N plus an editReturn record, then
// takes the ordinary Close path. The existing handoffLastSavedPage() writes N
// into Supernote's native config and restarts the stock reader on N. When the
// user relaunches RTL Reader, a valid editReturn makes the page the stock
// reader is showing authoritative, so RTL follows what the user last saw.

const EDIT_RETURN_VERSION = 1;
const EDIT_RETURN_MAX_AGE_MS = 72 * 60 * 60 * 1000;
const EDIT_RETURN_MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;

function isPageIndex(value) {
  return Number.isInteger(value) && value >= 0;
}

function isPageCount(value) {
  return Number.isInteger(value) && value >= 1;
}

function buildEditReturnRecord({filePath, editPage, totalPages, nativePageAtOpen, now}) {
  if (typeof filePath !== 'string' || filePath.length === 0) return null;
  if (!isPageIndex(editPage)) return null;
  if (!isPageCount(totalPages) || editPage >= totalPages) return null;
  if (!Number.isFinite(now)) return null;
  return {
    version: EDIT_RETURN_VERSION,
    filePath,
    editPage,
    totalPages,
    nativePageAtOpen: isPageIndex(nativePageAtOpen) ? nativePageAtOpen : null,
    createdAt: now,
  };
}

// Returns {valid, reason}. Anything doubtful is invalid. A valid record never
// supplies a page: it only makes the stock reader's current page authoritative.
function validateEditReturn(record, context, now) {
  if (record === undefined || record === null) return {valid: false, reason: 'absent'};
  if (typeof record !== 'object' || Array.isArray(record)) return {valid: false, reason: 'malformed'};
  if (record.version !== EDIT_RETURN_VERSION) return {valid: false, reason: 'version'};
  if (!isPageIndex(record.editPage) || !Number.isFinite(record.createdAt)) {
    return {valid: false, reason: 'malformed'};
  }
  if (record.filePath !== context.filePath) return {valid: false, reason: 'document'};
  if (!isPageCount(record.totalPages) || !isPageCount(context.totalPages)) {
    return {valid: false, reason: 'page_count_unknown'};
  }
  if (record.totalPages !== context.totalPages) {
    return {valid: false, reason: 'page_count_changed'};
  }
  if (record.editPage >= context.totalPages) {
    return {valid: false, reason: 'page_out_of_range'};
  }
  const age = now - record.createdAt;
  if (age < -EDIT_RETURN_MAX_FUTURE_SKEW_MS) return {valid: false, reason: 'clock'};
  if (age > EDIT_RETURN_MAX_AGE_MS) return {valid: false, reason: 'stale'};
  return {valid: true, reason: 'ok'};
}

// Returns {rawPage, source, editReturnStatus}; the caller clamps rawPage.
// Absent a record this is exactly the pre-existing rule: the saved RTL page
// wins unless the native page differs from the page at last open. A record
// that is present but rejected (stale, other document, changed page count,
// malformed) drops ALL saved-page state and uses the stock reader's page: a
// rejected record means the saved page cannot be trusted either.
function chooseInitialPage(saved, context, now) {
  const edit = validateEditReturn(saved?.editReturn, context, now);
  if (edit.valid) {
    return {rawPage: context.pageIndex, source: 'edit-return', editReturnStatus: 'applied'};
  }
  if (edit.reason !== 'absent') {
    return {
      rawPage: context.pageIndex,
      source: 'native-edit-rejected',
      editReturnStatus: `ignored:${edit.reason}`,
    };
  }

  const hasSavedPage = Number.isInteger(saved?.lastPageIndex);
  const hasPriorNativeAnchor = Number.isInteger(saved?.nativePageIndexAtOpen);
  const nativePositionChanged =
    hasPriorNativeAnchor && saved.nativePageIndexAtOpen !== context.pageIndex;
  const useSavedPage = hasSavedPage && !nativePositionChanged;
  return {
    rawPage: useSavedPage ? saved.lastPageIndex : context.pageIndex,
    source: useSavedPage ? 'saved' : nativePositionChanged ? 'native-changed' : 'native',
    editReturnStatus: 'none',
  };
}

// Edit buttons for the current view. `expectedVisual` is App.js
// getVisualSpread() for the requested page: {left, right} slots, null for blank.
// `settled` is true only when the last COMPLETED render is exactly the view the
// buttons name: same mode, same page ids, and no render in flight. Callers
// disable the buttons and re-evaluate at tap time from live refs.
function listEditTargets({mode, pageIndex, expectedVisual, display, rendering}) {
  const targets = [];
  let settled = false;
  if (mode === 'single') {
    if (isPageIndex(pageIndex)) {
      targets.push({side: 'single', page: pageIndex, label: `Edit p.${pageIndex + 1}`});
    }
    settled =
      !rendering &&
      display?.kind === 'single' &&
      isPageIndex(pageIndex) &&
      display.singlePageIndex === pageIndex &&
      Boolean(display.single);
  } else {
    for (const side of ['left', 'right']) {
      const page = expectedVisual?.[side];
      if (isPageIndex(page)) targets.push({side, page, label: `Edit p.${page + 1}`});
    }
    settled =
      !rendering &&
      display?.kind === 'spread' &&
      Boolean(expectedVisual) &&
      display.leftPageIndex === expectedVisual.left &&
      display.rightPageIndex === expectedVisual.right &&
      targets.length > 0;
  }
  return {targets, settled};
}

function editAvailability({
  ready,
  busy,
  editInFlight,
  fatalError,
  authorityResolved,
  nativeSpreadConfigured,
  nativeSpreadEnabled,
  displaySettled,
}) {
  if (!ready || fatalError) return {allowed: false, reason: 'not_ready'};
  if (editInFlight) return {allowed: false, reason: 'edit_in_progress'};
  if (busy) return {allowed: false, reason: 'busy'};
  if (!authorityResolved) return {allowed: false, reason: 'authority_unresolved'};
  // Configured covers read-only Native Spread (enabled=false but handwriting
  // disabled by mode); enabled covers the live editable case.
  if (nativeSpreadConfigured || nativeSpreadEnabled) {
    return {allowed: false, reason: 'native_spread_active'};
  }
  if (!displaySettled) return {allowed: false, reason: 'page_unsettled'};
  return {allowed: true, reason: 'ok'};
}

// Did the native handoff open the requested page? Resolution alone is not
// success: the native side resolves {annotationRecovery:true} when it skipped
// the handoff. The restart itself is delayed and unacknowledged, so "ok" means
// "config rewritten and restart scheduled", nothing more.
function evaluateHandoff(result, editPage) {
  if (!result || typeof result !== 'object') return {ok: false, reason: 'no_result'};
  if (result.annotationRecovery === true) return {ok: false, reason: 'recovery_skipped'};
  if (result.pageIndex !== editPage) return {ok: false, reason: 'page_mismatch'};
  return {ok: true, reason: 'ok'};
}

const EDIT_BLOCKED_MESSAGES = {
  not_ready: 'The reader is not ready to hand off yet.',
  busy: 'Wait for the native reader change to finish before editing.',
  authority_unresolved:
    'Native reader state is unresolved. Editing is locked until it is resolved.',
  native_spread_active:
    'Native Spread is configured for this document. Use the native reader directly.',
  page_unsettled: 'Wait for the page to finish displaying, then try again.',
  edit_in_progress: 'An edit hand-off is already in progress.',
  handoff_failed: 'The stock reader hand-off did not complete; editing was not started.',
  save_failed: 'Could not save the reader position; editing was not started.',
  no_page: 'This page cannot be opened for editing.',
};

// New prefs payload for an Edit. Pure: does not mutate `latest`.
function buildEditPayload(latest, record, now) {
  if (!latest || !record) return null;
  return {...latest, lastPageIndex: record.editPage, editReturn: record, updatedAt: now};
}

module.exports = {
  EDIT_RETURN_VERSION,
  EDIT_RETURN_MAX_AGE_MS,
  EDIT_RETURN_MAX_FUTURE_SKEW_MS,
  EDIT_BLOCKED_MESSAGES,
  buildEditReturnRecord,
  validateEditReturn,
  chooseInitialPage,
  listEditTargets,
  editAvailability,
  evaluateHandoff,
  buildEditPayload,
};
