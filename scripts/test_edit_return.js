'use strict';
// Deterministic host tests for the RTL Reader Close / native-handoff / reopen
// page-selection logic. Run: node scripts/test_edit_return.js
// No device, ADB, or React Native runtime is used.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');

const er = require(path.join(ROOT, 'overlay/editReturn.js'));

// --- Subject under test -----------------------------------------------------
// Evaluate the real pure helpers from overlay/App.js (a JSX file that cannot be
// required directly) so the tests exercise the shipped text, not a copy.
function loadHelpersFromAppJs() {
  const src = fs.readFileSync(path.join(ROOT, 'overlay/App.js'), 'utf8');
  const grab = (startMarker, endMarker) => {
    const s = src.indexOf(startMarker);
    const e = src.indexOf(endMarker, s);
    assert.ok(s >= 0 && e > s, `marker not found: ${startMarker}`);
    return src.slice(s, e);
  };
  const code =
    grab('function clampPage(', 'function cacheKey(') +
    grab('function normalizePage(', 'function viewModeLabel(') +
    grab('function decodePreferences(', 'function SegmentedButton(') +
    '\nreturn {decodePreferences, getSpreadPair, getVisualSpread};';
  const noop = () => {};
  return new Function('console', 'chooseInitialPage', code)(
    {warn: noop, log: noop, error: noop},
    er.chooseInitialPage,
  );
}

const {decodePreferences: decode, getSpreadPair, getVisualSpread} = loadHelpersFromAppJs();
const ctx = (pageIndex, totalPages = 100) => ({filePath: '/doc/a.pdf', pageIndex, totalPages});
const prefs = o => JSON.stringify({version: 1, ...o});

// --- Existing behavior: page selection --------------------------------------
test('no saved prefs: native page wins, defaults applied', () => {
  const r = decode(null, ctx(7));
  assert.equal(r.pageIndex, 7);
  assert.equal(r.source, 'native');
  assert.deepEqual(
    [r.direction, r.viewMode, r.coverSeparate, r.showSpreadDivider, r.showNativeSpreadHeader, r.spreadSizing],
    ['rtl', 'auto', false, true, true, 'fit'],
  );
});

test('corrupt JSON behaves like no saved prefs', () => {
  const r = decode('{not json', ctx(3));
  assert.equal(r.pageIndex, 3);
  assert.equal(r.source, 'native');
});

test('saved page wins when native page equals the page at last open', () => {
  const r = decode(prefs({lastPageIndex: 30, nativePageIndexAtOpen: 10}), ctx(10));
  assert.equal(r.pageIndex, 30);
  assert.equal(r.source, 'saved');
});

test('saved page wins when there is no prior native anchor (older prefs)', () => {
  const r = decode(prefs({lastPageIndex: 30}), ctx(10));
  assert.equal(r.pageIndex, 30);
  assert.equal(r.source, 'saved');
});

test('user paged inside the stock reader: native page wins', () => {
  const r = decode(prefs({lastPageIndex: 30, nativePageIndexAtOpen: 10}), ctx(55));
  assert.equal(r.pageIndex, 55);
  assert.equal(r.source, 'native-changed');
});

test('after a successful Close handoff (native == saved page) the same page results', () => {
  // Close wrote lastPageIndex=30 into the native config; user did not page.
  const r = decode(prefs({lastPageIndex: 30, nativePageIndexAtOpen: 10}), ctx(30));
  assert.equal(r.pageIndex, 30);
  assert.equal(r.source, 'native-changed');
});

test('handoff failed/skipped and user did not page: saved RTL page wins', () => {
  const r = decode(prefs({lastPageIndex: 30, nativePageIndexAtOpen: 10}), ctx(10));
  assert.equal(r.pageIndex, 30);
  assert.equal(r.source, 'saved');
});

test('KNOWN LIMITATION L1: paging in stock back to the exact open-time page is treated as "did not page"', () => {
  // Stock reader was at 10 when RTL opened; user reads on, then returns to 10
  // and reopens RTL. Page-only comparison cannot tell this from "never moved".
  const r = decode(prefs({lastPageIndex: 30, nativePageIndexAtOpen: 10}), ctx(10));
  assert.equal(r.pageIndex, 30, 'current behavior: saved page overrides the user position');
});

test('saved page is clamped to the document', () => {
  assert.equal(decode(prefs({lastPageIndex: 500, nativePageIndexAtOpen: 10}), ctx(10, 100)).pageIndex, 99);
  assert.equal(decode(prefs({lastPageIndex: 5, nativePageIndexAtOpen: 10}), ctx(10, null)).pageIndex, 5);
});

test('non-integer lastPageIndex is ignored', () => {
  const r = decode(prefs({lastPageIndex: '30', nativePageIndexAtOpen: 10}), ctx(10));
  assert.equal(r.pageIndex, 10);
  assert.equal(r.source, 'native');
});

// --- Existing behavior: appearance settings ---------------------------------
test('settings are validated individually', () => {
  const r = decode(
    prefs({direction: 'ltr', viewMode: 'bogus', coverSeparate: 'yes', showSpreadDivider: false, showNativeSpreadHeader: false, spreadSizing: 'native_fill'}),
    ctx(0),
  );
  assert.deepEqual(
    [r.direction, r.viewMode, r.coverSeparate, r.showSpreadDivider, r.showNativeSpreadHeader, r.spreadSizing],
    ['ltr', 'auto', false, false, false, 'native_fill'],
  );
  assert.equal(decode(prefs({direction: 'weird'}), ctx(0)).direction, 'rtl');
});

// --- Differential test: refactor preserves legacy page selection ------------
// Frozen copy of the page-selection rule at base commit 69e2aa2.
function legacySelect(saved, context) {
  const hasSavedPage = Number.isInteger(saved?.lastPageIndex);
  const hasPriorNativeAnchor = Number.isInteger(saved?.nativePageIndexAtOpen);
  const nativePositionChanged =
    hasPriorNativeAnchor && saved.nativePageIndexAtOpen !== context.pageIndex;
  const useSavedPage = hasSavedPage && !nativePositionChanged;
  return {
    rawPage: useSavedPage ? saved.lastPageIndex : context.pageIndex,
    source: useSavedPage ? 'saved' : nativePositionChanged ? 'native-changed' : 'native',
  };
}

test('without an editReturn, selection equals the frozen legacy rule on a grid', () => {
  const vals = [undefined, null, 0, 1, 10, 30, '7', 2.5];
  let n = 0;
  for (const lastPageIndex of vals) {
    for (const nativePageIndexAtOpen of vals) {
      for (const nativePage of [0, 1, 10, 30, 99]) {
        const saved = {lastPageIndex, nativePageIndexAtOpen};
        const got = er.chooseInitialPage(saved, ctx(nativePage), 0);
        const want = legacySelect(saved, ctx(nativePage));
        assert.equal(got.rawPage, want.rawPage);
        assert.equal(got.source, want.source);
        assert.equal(got.editReturnStatus, 'none');
        n += 1;
      }
    }
  }
  assert.equal(n, 320);
});

// --- Edit/Return: record validation -----------------------------------------
const NOW = 1_000_000_000_000;
const rec = (o = {}) => ({...er.buildEditReturnRecord({filePath: '/doc/a.pdf', editPage: 31, totalPages: 100, nativePageAtOpen: 10, now: NOW}), ...o});
const verdict = (record, context = ctx(31), now = NOW + 1000) => er.validateEditReturn(record, context, now);

test('valid record is accepted', () => assert.deepEqual(verdict(rec()), {valid: true, reason: 'ok'}));

test('stale, mismatched, or malformed records are rejected with a reason', () => {
  assert.equal(verdict(undefined).reason, 'absent');
  assert.equal(verdict('x').reason, 'malformed');
  assert.equal(verdict(rec({version: 2})).reason, 'version');
  assert.equal(verdict(rec({editPage: -1})).reason, 'malformed');
  assert.equal(verdict(rec({createdAt: 'now'})).reason, 'malformed');
  assert.equal(verdict(rec({filePath: '/doc/b.pdf'})).reason, 'document');
  assert.equal(verdict(rec(), ctx(31, 120)).reason, 'page_count_changed');
  assert.equal(verdict(rec({editPage: 150, totalPages: null}), ctx(31, 100)).reason, 'page_out_of_range');
  assert.equal(verdict(rec(), ctx(31), NOW + er.EDIT_RETURN_MAX_AGE_MS + 1).reason, 'stale');
  assert.equal(verdict(rec(), ctx(31), NOW - er.EDIT_RETURN_MAX_FUTURE_SKEW_MS - 1).reason, 'clock');
  assert.equal(verdict(rec(), ctx(31), NOW + er.EDIT_RETURN_MAX_AGE_MS).valid, true);
});

test('record builder rejects impossible pages', () => {
  const b = o => er.buildEditReturnRecord({filePath: '/d.pdf', editPage: 3, totalPages: 10, nativePageAtOpen: 0, now: NOW, ...o});
  assert.equal(b({editPage: -1}), null);
  assert.equal(b({editPage: 10}), null);
  assert.equal(b({editPage: 1.5}), null);
  assert.equal(b({filePath: ''}), null);
  assert.equal(b({totalPages: null}).totalPages, null);
});

// --- Edit/Return: state table -----------------------------------------------
const edited = (nativeAtOpen = 10, editPage = 31) =>
  er.buildEditPayload(
    {version: 1, direction: 'rtl', lastPageIndex: 30, nativePageIndexAtOpen: nativeAtOpen, coverSeparate: true},
    er.buildEditReturnRecord({filePath: '/doc/a.pdf', editPage, totalPages: 100, nativePageAtOpen: nativeAtOpen, now: NOW}),
    NOW,
  );
const reopen = (payload, nativePage, now = NOW + 60_000, total = 100) =>
  decode(JSON.stringify(payload), ctx(nativePage, total), now);

test('E1 normal: stock reader is on the edited page -> RTL resumes there', () => {
  const r = reopen(edited(), 31);
  assert.deepEqual([r.pageIndex, r.source, r.editReturnStatus], [31, 'edit-return', 'applied']);
});

test('E2 user paged inside the stock reader -> RTL follows the stock page', () => {
  const r = reopen(edited(), 77);
  assert.deepEqual([r.pageIndex, r.source], [77, 'edit-return']);
});

test('E3 fixes L1: user paged back to the RTL open-time page -> stock page still wins', () => {
  const r = reopen(edited(10), 10);
  assert.deepEqual([r.pageIndex, r.source], [10, 'edit-return']);
});

test('E4 handoff did not happen (stock still at old page) -> RTL follows what stock shows', () => {
  const r = reopen(edited(10), 10);
  assert.equal(r.pageIndex, 10);
});

test('E5 stale record (older than max age) -> legacy rule, record ignored', () => {
  const r = reopen(edited(10), 10, NOW + er.EDIT_RETURN_MAX_AGE_MS + 1);
  assert.deepEqual([r.pageIndex, r.source, r.editReturnStatus], [31, 'saved', 'ignored:stale']);
});

test('E6 document replaced (page count differs) -> record ignored, legacy rule', () => {
  const r = reopen(edited(10), 5, NOW + 60_000, 40);
  assert.equal(r.editReturnStatus, 'ignored:page_count_changed');
  assert.equal(r.pageIndex, 5);
});

test('E7 record for another path is ignored', () => {
  const p = edited();
  p.editReturn.filePath = '/doc/other.pdf';
  assert.equal(reopen(p, 31).editReturnStatus, 'ignored:document');
});

test('E8 the record is consumed: a payload saved after reopen carries none', () => {
  const next = {version: 1, lastPageIndex: 31, nativePageIndexAtOpen: 31};
  const r = decode(JSON.stringify(next), ctx(31), NOW);
  assert.equal(r.editReturnStatus, 'none');
});

test('edit payload keeps other settings, sets page + record, does not mutate input', () => {
  const latest = {version: 1, direction: 'ltr', coverSeparate: true, lastPageIndex: 4};
  const copy = JSON.stringify(latest);
  const record = er.buildEditReturnRecord({filePath: '/d.pdf', editPage: 9, totalPages: 20, nativePageAtOpen: 4, now: NOW});
  const p = er.buildEditPayload(latest, record, NOW);
  assert.equal(JSON.stringify(latest), copy);
  assert.deepEqual([p.lastPageIndex, p.direction, p.coverSeparate, p.editReturn.editPage], [9, 'ltr', true, 9]);
  assert.equal(er.buildEditPayload(null, record, NOW), null);
  assert.equal(er.buildEditPayload(latest, null, NOW), null);
});

// --- Rotation / spread geometry ---------------------------------------------
test('Edit targets map to the page shown in each physical slot; blank slots offer none', () => {
  for (const cover of [false, true]) {
    for (const direction of ['rtl', 'ltr']) {
      for (const total of [1, 2, 3, 10, 11]) {
        for (let page = 0; page < total; page += 1) {
          const visual = getVisualSpread(page, cover, total, direction);
          const spread = er.listEditTargets({mode: 'spread', pageIndex: page, visual});
          for (const t of spread) assert.equal(t.page, visual[t.side]);
          assert.equal(spread.length, [visual.left, visual.right].filter(v => v !== null).length);
          assert.ok(spread.some(t => t.page === page), 'current page is editable in spread');
          const single = er.listEditTargets({mode: 'single', pageIndex: page, visual: null});
          assert.deepEqual(single.map(t => t.page), [page]);
        }
      }
    }
  }
  assert.deepEqual(er.listEditTargets({mode: 'single', pageIndex: null, visual: null}), []);
});

test('Rotation between Edit and return cannot change the resume page; pairing always contains it', () => {
  // decodePreferences has no orientation input: the page is the same for
  // portrait (single) and landscape (spread); only the pair derived at render differs.
  for (const cover of [false, true]) {
    for (const direction of ['rtl', 'ltr']) {
      for (let editPage = 0; editPage < 40; editPage += 1) {
        const payload = edited(3, editPage);
        const r = reopen(payload, editPage, NOW + 1, 100);
        assert.equal(r.pageIndex, editPage);
        const pair = getSpreadPair(r.pageIndex, cover, 100);
        assert.ok([pair.earlier, pair.later].includes(editPage), `pair contains page ${editPage} (cover=${cover})`);
        const visual = getVisualSpread(r.pageIndex, cover, 100, direction);
        assert.ok([visual.left, visual.right].includes(editPage));
      }
    }
  }
});

// --- Availability gate (mirrors Close, plus native-spread) ------------------
test('Edit availability fails closed', () => {
  const ok = {ready: true, busy: false, fatalError: null, authorityResolved: true, nativeSpreadEnabled: false};
  assert.deepEqual(er.editAvailability(ok), {allowed: true, reason: 'ok'});
  assert.equal(er.editAvailability({...ok, ready: false}).reason, 'not_ready');
  assert.equal(er.editAvailability({...ok, fatalError: 'x'}).reason, 'not_ready');
  assert.equal(er.editAvailability({...ok, busy: true}).reason, 'busy');
  assert.equal(er.editAvailability({...ok, authorityResolved: false}).reason, 'authority_unresolved');
  assert.equal(er.editAvailability({...ok, nativeSpreadEnabled: true}).reason, 'native_spread_active');
  for (const reason of ['not_ready', 'busy', 'authority_unresolved', 'native_spread_active']) {
    assert.ok(er.EDIT_BLOCKED_MESSAGES[reason]);
  }
});
