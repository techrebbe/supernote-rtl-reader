'use strict';
// Deterministic host tests for the RTL Reader Close / native-handoff / reopen
// page-selection logic. Run: node scripts/test_edit_return.js
// No device, ADB, or React Native runtime is used.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');

// --- Subject under test -----------------------------------------------------
// Characterization of the EXISTING behavior: evaluate the real decodePreferences
// text from overlay/App.js (JSX file, cannot be required directly).
function loadDecodePreferencesFromAppJs() {
  const src = fs.readFileSync(path.join(ROOT, 'overlay/App.js'), 'utf8');
  const grab = (startMarker, endMarker) => {
    const s = src.indexOf(startMarker);
    const e = src.indexOf(endMarker, s);
    assert.ok(s >= 0 && e > s, `marker not found: ${startMarker}`);
    return src.slice(s, e);
  };
  const code =
    grab('function clampPage(', 'function cacheKey(') +
    grab('function decodePreferences(', 'function SegmentedButton(') +
    '\nreturn decodePreferences;';
  const noop = () => {};
  return new Function('console', code)({warn: noop, log: noop, error: noop});
}

const decode = loadDecodePreferencesFromAppJs();
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
