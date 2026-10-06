'use strict';
// Deterministic host tests for the RTL Reader Close / native-handoff / reopen
// page-selection logic. Run: node scripts/test_edit_return.js
// Generated-source tests require Python 3 (or its path in PYTHON_BIN).
// No device, ADB, or React Native runtime is used.
const test = require('node:test');
const assert = require('node:assert/strict');
const {spawnSync} = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');

const er = require(path.join(ROOT, 'overlay/editReturn.js'));

// --- Subject under test -----------------------------------------------------
// Evaluate the real pure helpers from overlay/App.js (a JSX file that cannot be
// required directly) so the tests exercise the shipped text, not a copy.
function loadHelpersFromAppJs(src = fs.readFileSync(path.join(ROOT, 'overlay/App.js'), 'utf8')) {
  const grab = (startMarker, endMarker) => {
    const s = src.indexOf(startMarker);
    const e = src.indexOf(endMarker, s);
    assert.ok(s >= 0 && e > s, `marker not found: ${startMarker}`);
    return src.slice(s, e);
  };
  const code =
    grab('function clampPage(', 'function normalizePage(') +
    grab('function normalizePage(', 'function viewModeLabel(') +
    grab('function decodePreferences(', 'function SegmentedButton(') +
    '\nreturn {decodePreferences, cacheKey, normalizePage, getSpreadPair, getVisualSpread};';
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

test('page turner is per-document explicit opt-in; malformed profile never claims keys', () => {
  for (const value of [undefined, false, null, 1, 'true', {}, []]) {
    assert.equal(decode(prefs({pageTurnerEnabled: value}), ctx(3)).pageTurnerEnabled, false);
  }
  for (const profile of ['navigation', 'volume', 'volume_reversed']) {
    const r = decode(prefs({pageTurnerEnabled: true, pageTurnerProfile: profile}), ctx(3));
    assert.equal(r.pageTurnerEnabled, true); assert.equal(r.pageTurnerProfile, profile);
  }
  for (const profile of [null, false, 24, {}, [], 'anything', 'toString', '__proto__']) {
    const r = decode(prefs({pageTurnerEnabled: true, pageTurnerProfile: profile}), ctx(3));
    assert.equal(r.pageTurnerEnabled, false); assert.equal(r.pageTurnerProfile, 'navigation');
  }
  const off = er.buildEditPayload({pageTurnerEnabled: false, pageTurnerProfile: 'volume'},
    {editPage: 3}, 1);
  assert.equal(off.pageTurnerEnabled, false); assert.equal(off.pageTurnerProfile, 'volume');
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
  assert.equal(verdict(rec({editPage: 150, totalPages: 100}), ctx(31, 100)).reason, 'page_out_of_range');
  for (const bad of [null, undefined, 0, -3, 2.5, '100', NaN]) {
    assert.equal(verdict(rec({totalPages: bad})).reason, 'page_count_unknown', `record totalPages=${bad}`);
  }
  assert.equal(verdict(rec(), ctx(31, null)).reason, 'page_count_unknown');
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
  assert.equal(b({totalPages: null}), null);
  assert.equal(b({totalPages: 0}), null);
  assert.equal(b({now: NaN}), null);
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

test('E5 stale record (older than max age) -> dropped: native page, NOT the saved page', () => {
  const r = reopen(edited(10), 10, NOW + er.EDIT_RETURN_MAX_AGE_MS + 1);
  assert.deepEqual([r.pageIndex, r.source, r.editReturnStatus], [10, 'native-edit-rejected', 'ignored:stale']);
});

test('E6 document replaced (page count differs) -> record dropped, native page wins', () => {
  const r = reopen(edited(10), 5, NOW + 60_000, 40);
  assert.equal(r.editReturnStatus, 'ignored:page_count_changed');
  assert.deepEqual([r.pageIndex, r.source], [5, 'native-edit-rejected']);
});

test('E7 record for another path is ignored', () => {
  const p = edited();
  p.editReturn.filePath = '/doc/other.pdf';
  const r = reopen(p, 7);
  assert.equal(r.editReturnStatus, 'ignored:document');
  assert.deepEqual([r.pageIndex, r.source], [7, 'native-edit-rejected']);
});

test('E7b unknown page count on reopen -> record dropped, saved page not restored', () => {
  const r = decode(JSON.stringify(edited(10)), ctx(4, null), NOW + 60_000);
  assert.deepEqual([r.pageIndex, r.source, r.editReturnStatus], [4, 'native-edit-rejected', 'ignored:page_count_unknown']);
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
test('Edit targets map to the page shown in each physical slot; settled only when the completed render matches', () => {
  for (const cover of [false, true]) {
    for (const direction of ['rtl', 'ltr']) {
      for (const total of [1, 2, 3, 10, 11]) {
        for (let page = 0; page < total; page += 1) {
          const visual = getVisualSpread(page, cover, total, direction);
          const shown = {kind: 'spread', leftPageIndex: visual.left, rightPageIndex: visual.right};
          const spread = er.listEditTargets({mode: 'spread', pageIndex: page, expectedVisual: visual, display: shown, rendering: false});
          for (const t of spread.targets) assert.equal(t.page, visual[t.side]);
          assert.equal(spread.targets.length, [visual.left, visual.right].filter(v => v !== null).length);
          assert.ok(spread.targets.some(t => t.page === page), 'current page is editable in spread');
          assert.equal(spread.settled, true);
          const single = er.listEditTargets({mode: 'single', pageIndex: page, display: {kind: 'single', single: 'u', singlePageIndex: page}, rendering: false});
          assert.deepEqual(single.targets.map(t => t.page), [page]);
          assert.equal(single.settled, true);
        }
      }
    }
  }
  assert.deepEqual(er.listEditTargets({mode: 'single', pageIndex: null, display: null, rendering: false}), {targets: [], settled: false});
});

test('Edit is unsettled whenever the completed render is not the requested view (finding 1)', () => {
  const v = getVisualSpread(4, true, 20, 'rtl');
  const shown = {kind: 'spread', leftPageIndex: v.left, rightPageIndex: v.right};
  const args = {mode: 'spread', pageIndex: 4, expectedVisual: v, display: shown, rendering: false};
  assert.equal(er.listEditTargets(args).settled, true);
  assert.equal(er.listEditTargets({...args, rendering: true}).settled, false, 'render in flight');
  const next = getVisualSpread(6, true, 20, 'rtl');
  assert.equal(er.listEditTargets({...args, pageIndex: 6, expectedVisual: next}).settled, false, 'page turned, old render still shown');
  assert.equal(er.listEditTargets({...args, expectedVisual: getVisualSpread(4, true, 20, 'ltr')}).settled, false, 'direction flipped');
  assert.equal(er.listEditTargets({...args, mode: 'single', display: shown}).settled, false, 'rotated to single, spread still shown');
  assert.equal(er.listEditTargets({mode: 'single', pageIndex: 3, display: {kind: 'single', single: 'u', singlePageIndex: 2}, rendering: false}).settled, false);
  assert.equal(er.listEditTargets({mode: 'single', pageIndex: 3, display: {kind: 'spread'}, rendering: false}).settled, false, 'rotated to portrait, spread still shown');
  assert.equal(er.listEditTargets({...args, display: null}).settled, false);
  assert.equal(er.listEditTargets({...args, display: {...shown, leftPageIndex: 99}}).settled, false, 'left slot differs');
  assert.equal(er.listEditTargets({...args, display: {...shown, rightPageIndex: 99}}).settled, false, 'right slot differs');
});

// Run the real App.js build transforms, then execute the actual render effect
// and completion callback with host-only dependencies. Synthetic display shapes
// miss the packaged native single-page path, which has no bitmap URI field.
function generateNativeAppSource(t) {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'rtl-edit-display-'));
  t.after(() => fs.rmSync(temp, {recursive: true, force: true}));
  const generatedPath = path.join(temp, 'App.js');
  fs.copyFileSync(path.join(ROOT, 'overlay/App.js'), generatedPath);

  const candidates = process.env.PYTHON_BIN
    ? [{command: process.env.PYTHON_BIN, args: []}]
    : [
        {command: 'python3', args: []},
        {command: 'python', args: []},
        {command: 'py', args: ['-3']},
      ];
  const python = candidates.find(candidate =>
    spawnSync(candidate.command, [...candidate.args, '--version'], {encoding: 'utf8'}).status === 0,
  );
  assert.ok(python, 'Python 3 is required for generated App.js regression tests; set PYTHON_BIN');

  const build = fs.readFileSync(path.join(ROOT, 'build.sh'), 'utf8');
  const patches = ['patch_direct_view.py', 'install_native.py', 'patch_initial_layout.py'];
  const positions = patches.map(script => build.indexOf(`scripts/${script}`));
  assert.ok(
    positions.every((position, index) => position >= 0 && (index === 0 || position > positions[index - 1])),
    'test must follow the build\'s native display and measured-layout transforms',
  );
  for (const script of patches) {
    // Native installation also patches App.js prefetch state. Call its actual
    // App-only transform without materializing unrelated Android project files.
    const args = script === 'install_native.py'
      ? [
          '-B', '-c',
          'import sys; from pathlib import Path; sys.path.insert(0, sys.argv[1]); ' +
            'from install_native import patch_app_prefetch_direction; ' +
            'patch_app_prefetch_direction(Path(sys.argv[2]))',
          path.join(ROOT, 'scripts'), generatedPath,
        ]
      : [path.join(ROOT, 'scripts', script), generatedPath];
    const result = spawnSync(
      python.command,
      [...python.args, ...args],
      {encoding: 'utf8'},
    );
    assert.equal(result.status, 0, `${script} failed: ${result.error ?? result.stderr}`);
  }
  const source = fs.readFileSync(generatedPath, 'utf8').replace(/\r\n/g, '\n');
  assert.ok(source.includes('const pageAreaReady = pageAreaLayout.width > 0 && pageAreaLayout.height > 0;'));
  assert.ok(source.includes('requestedWidth={Math.max(600, measuredPageWidth)}'));
  return source;
}

async function runDisplayProducer(source, options = {}) {
  const src = source.replace(/\r\n/g, '\n');
  const token = src.indexOf('    const token = ++renderTokenRef.current;');
  const start = src.lastIndexOf('  useEffect(() => {', token);
  const end = src.indexOf('\n\n  const close = async () => {', token);
  assert.ok(token >= 0 && start >= 0 && end > token, 'actual render-effect markers must exist');

  const mode = src.match(/  const effectiveMode =\n[\s\S]*?;/);
  assert.ok(mode, 'actual view-mode expression must exist');
  const layoutStart = src.indexOf('  const pageAreaReady =');
  const modeSource = layoutStart >= 0
    ? src.slice(layoutStart, mode.index + mode[0].length)
    : mode[0];

  const captured = {display: null, rendering: false, fatalError: null};
  const effects = [];
  const environment = {
    ...loadHelpersFromAppJs(src),
    viewMode: 'auto',
    isLandscape: false,
    pageAreaLayout: {width: 600, height: 1000},
    preferencesReady: true,
    documentContext: ctx(4, 20),
    pageIndex: 4,
    direction: 'rtl',
    coverSeparate: true,
    window: {width: 600},
    totalPagesRef: {current: 20},
    renderTokenRef: {current: 0},
    mountedRef: {current: true},
    cacheRef: {current: new Map()},
    nativeRenderRef: {current: {expected: new Set(), loaded: new Set()}},
    interactionTimingRef: {current: {pageIndex: null, startedAtMs: 0}},
    lastNavigationDeltaRef: {current: 1},
    renderPdfPage: async page => ({imageUri: `bitmap://${page}`, pageCount: 20}),
    prefetchAround: () => {},
    setDisplay: value => { captured.display = value; },
    setRendering: value => { captured.rendering = value; },
    setFatalError: value => { captured.fatalError = value; },
    setTotalPages: () => {},
    useEffect: effect => effects.push(effect),
    console: {log() {}, warn() {}, error() {}},
    ...options,
  };
  const producer = new Function(
    ...Object.keys(environment),
    `${modeSource}\n${src.slice(start, end)}\n` +
      'return {effectiveMode, complete: typeof handleNativeRendered === "function" ? handleNativeRendered : null, fail: typeof handleNativeError === "function" ? handleNativeError : null};',
  )(...Object.values(environment));
  assert.equal(effects.length, 1, 'execute only the shipped foreground render effect');
  effects[0]();
  // The legacy effect launches its asynchronous bitmap renderer without awaiting
  // it. Let its real promise continuation settle before inspecting the result.
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(captured.fatalError, null, 'producer must not fail behind the settlement assertions');
  return {...producer, captured, request: environment.nativeRenderRef.current};
}

test('generated key gate rearms sizing/height changes without inventing a new display generation', async t => {
  const src = generateNativeAppSource(t);
  const gateStart = src.indexOf('  const readerKeyGeometry =');
  const gateEnd = src.indexOf('  const savedInkProfile =', gateStart);
  assert.ok(gateStart > 0 && gateEnd > gateStart);
  const refs = {readerKeyPresentationRef: {current: null}, readerKeyUiRef: {current: null},
    filePathRef: {current: '/doc/a.pdf'}, pageIndexRef: {current: 4}, totalPagesRef: {current: 20},
    effectiveModeRef: {current: 'spread'}, directionRef: {current: 'rtl'}, coverSeparateRef: {current: true},
    spreadSizingRef: {current: 'fit'}, renderTokenRef: {current: 0}, readerKeyFenceEpochRef: {current: 0},
    pageAreaWidthRef: {current: 1872}, displayRef: {current: {}}, renderingRef: {current: true},
    mountedRef: {current: true}, nativeSpreadBusyRef: {current: false}, nativeRenderRef: {current: {}}};
  const ui = {preferencesReady: true, settingsOpen: false, jumpOpen: false, nativeEditableConfirmOpen: false,
    editBusy: false, fatalError: null, nativeSpreadConfigured: false, nativeSpreadEnabled: false,
    pageTurnerEnabled: true, pageTurnerProfile: 'navigation', pageIndex: 4, effectiveMode: 'spread',
    direction: 'rtl', coverSeparate: true, spreadSizing: 'fit', window: {width: 1872, height: 1404}};
  function read() {
    const scope = {...refs, ...ui, ...loadHelpersFromAppJs(src), listEditTargets: er.listEditTargets,
      globalThis: {}, documentContext: ctx(4, 20), readerTransitionLocked: () => false};
    return new Function(...Object.keys(scope), src.slice(gateStart, gateEnd) + '\nreturn getReaderKeyContext();')(...Object.values(scope));
  }
  assert.equal(read().blocked, true);
  const rendered = await runDisplayProducer(src, {...refs, pageIndex: 4, viewMode: 'spread',
    pageAreaLayout: {width: 1872, height: 1404}, coverSeparate: true});
  for (const page of [3, 4]) rendered.complete({nativeEvent: {pageIndex: page}}, rendered.request.token);
  refs.displayRef.current = rendered.captured.display; refs.renderingRef.current = rendered.captured.rendering;
  assert.equal(read().blocked, false);
  const token = refs.renderTokenRef.current;
  for (const sizing of ['native_fill', 'fit']) {
    ui.spreadSizing = sizing; refs.spreadSizingRef.current = sizing;
    assert.equal(read().blocked, false, 'Native contentMode changes do not mint a JS display generation');
    assert.equal(refs.renderTokenRef.current, token);
  }
  ui.window = {width: 1800, height: 1000}; // measured page width/mode is unchanged
  assert.equal(read().blocked, false, 'Window/height update must not wait for a nonexistent foreground request');
  assert.equal(refs.renderTokenRef.current, token);
});

test('hardware CoverOff regression: unchanged right page gets a fresh native view identity', async t => {
  const source = generateNativeAppSource(t);
  const slots = [...source.matchAll(/<NativePdfPageView\b([\s\S]*?)\/>/g)];
  assert.equal(slots.length, 3, 'actual generated left/right/single native slots');
  const keys = slots.map(slot => {
    const expression = slot[1].match(/\bkey=\{(`[^`]+`)\}/);
    assert.ok(expression, 'every actual native slot requires a generation-bound React key');
    assert.equal((slot[1].match(/onPdfRendered=\{event => handleNativeRendered\(event, display\.renderToken\)\}/g) || []).length, 1);
    assert.equal((slot[1].match(/onPdfError=\{event => handleNativeError\(event, display\.renderToken\)\}/g) || []).length, 1);
    return new Function('display', `return ${expression[1]};`);
  });
  const shared = {renderTokenRef: {current: 0}, nativeRenderRef: {current: {}}};
  const config = {...shared, pageIndex: 0, totalPagesRef: {current: 2}, viewMode: 'spread',
    isLandscape: true, pageAreaLayout: {width: 1872, height: 1404},
    lastNavigationDeltaRef: {current: -1}};
  const cover = await runDisplayProducer(source, {...config, coverSeparate: true});
  cover.complete({nativeEvent: {pageIndex: 0}}, cover.request.token);
  assert.equal(cover.captured.rendering, false);
  const paired = await runDisplayProducer(source, {...config, coverSeparate: false});
  assert.equal(cover.captured.display.rightPageIndex, 0);
  assert.equal(paired.captured.display.rightPageIndex, 0, 'same native source page in same right slot');
  assert.deepEqual(cover.captured.display.prefetchPageIndexes, paired.captured.display.prefetchPageIndexes,
    'observed PAGE1 native render props can remain unchanged after cover Previous');
  assert.equal(paired.captured.rendering, true);
  assert.notEqual(keys[1](cover.captured.display), keys[1](paired.captured.display),
    'React must mount a fresh native view rather than wait for unchanged-view callback');
  assert.equal(new Set(keys.map(key => key(paired.captured.display))).size, 3, 'slot identities distinct');
  paired.complete({nativeEvent: {pageIndex: 1}}, paired.request.token);
  assert.equal(paired.captured.rendering, true, 'new PAGE2 alone cannot declare both pages ready');
  paired.complete({nativeEvent: {pageIndex: 0}}, paired.request.token);
  assert.equal(paired.captured.rendering, false, 'both fresh native draws actually complete');
});

test('native completion/error authority rejects old same-page generations and ABA', async t => {
  const source = generateNativeAppSource(t);
  const shared = {renderTokenRef: {current: 0}, nativeRenderRef: {current: {}}};
  const config = {...shared, pageIndex: 0, totalPagesRef: {current: 2}, viewMode: 'spread',
    isLandscape: true, pageAreaLayout: {width: 1872, height: 1404}};
  const first = await runDisplayProducer(source, {...config, coverSeparate: false});
  const second = await runDisplayProducer(source, {...config, coverSeparate: true});
  const third = await runDisplayProducer(source, {...config, coverSeparate: false});
  assert.ok(first.request.token < second.request.token && second.request.token < third.request.token);
  for (const stale of [first.request.token, second.request.token, undefined, null, NaN, '3']) {
    third.complete({nativeEvent: {pageIndex: 0}}, stale);
    third.fail({nativeEvent: {pageIndex: 0, message: 'stale error'}}, stale);
    assert.equal(third.request.loaded.size, 0, 'same-page stale event cannot mark current presentation drawn');
    assert.equal(third.captured.rendering, true);
    assert.equal(third.captured.fatalError, null);
  }
  first.complete({nativeEvent: {pageIndex: 0}}, first.request.token);
  assert.equal(third.request.loaded.size, 0, 'retired callback cannot mutate current request');
  third.complete({nativeEvent: {pageIndex: 1}}, third.request.token);
  third.complete({nativeEvent: {pageIndex: 1}}, third.request.token);
  assert.equal(third.captured.rendering, true, 'duplicate is not a second page');
  third.complete({nativeEvent: {pageIndex: 0}}, third.request.token);
  assert.equal(third.captured.rendering, false);
});

test('Edit settlement accepts actual legacy and generated portrait/Single displays', async t => {
  const sources = [
    ['legacy bitmap', fs.readFileSync(path.join(ROOT, 'overlay/App.js'), 'utf8'), false],
    ['generated native', generateNativeAppSource(t), true],
  ];
  for (const [label, source, native] of sources) {
    for (const [view, options] of [
      ['portrait Auto', {}],
      ['explicit Single in landscape', {viewMode: 'single', isLandscape: true, pageAreaLayout: {width: 1000, height: 600}}],
    ]) {
      await t.test(`${label}: ${view}`, async () => {
        const state = await runDisplayProducer(source, options);
        assert.equal(state.effectiveMode, 'single');
        assert.equal(Object.hasOwn(state.captured.display, 'single'), !native,
          'native display deliberately carries page identity without a bitmap URI');
        const args = {mode: 'single', pageIndex: 4, display: state.captured.display, rendering: state.captured.rendering};
        if (native) {
          assert.equal(args.rendering, true);
          assert.equal(er.listEditTargets(args).settled, false, 'native completion is still in flight');
          state.complete({nativeEvent: {pageIndex: 3, pageCount: 20}}, state.request.token);
          assert.equal(state.captured.rendering, true, 'unrelated completion cannot settle this page');
          state.complete({nativeEvent: {pageIndex: 4, pageCount: 20}}, state.request.token);
        }
        args.rendering = state.captured.rendering;
        assert.equal(args.rendering, false, 'actual producer completed the requested page');
        assert.deepEqual(er.listEditTargets(args), {targets: [{side: 'single', page: 4, label: 'Edit p.5'}], settled: true});
        assert.equal(er.listEditTargets({...args, pageIndex: 5}).settled, false, 'different requested page');
        assert.equal(er.listEditTargets({...args, mode: 'spread', expectedVisual: getVisualSpread(4, true, 20, 'rtl')}).settled, false, 'rotation before the new render');
        assert.equal(er.listEditTargets({...args, rendering: true}).settled, false, 'next render in flight');
      });
    }

    await t.test(`${label}: spread slots remain authoritative`, async () => {
      const state = await runDisplayProducer(source, {isLandscape: true, pageAreaLayout: {width: 1000, height: 600}});
      const visual = getVisualSpread(4, true, 20, 'rtl');
      assert.equal(state.effectiveMode, 'spread');
      const args = {mode: 'spread', pageIndex: 4, expectedVisual: visual, display: state.captured.display, rendering: state.captured.rendering};
      if (native) {
        const expected = [visual.left, visual.right].filter(Number.isInteger);
        for (const page of expected) {
          assert.equal(er.listEditTargets({...args, rendering: state.captured.rendering}).settled, false);
          state.complete({nativeEvent: {pageIndex: page, pageCount: 20}}, state.request.token);
        }
      }
      args.rendering = state.captured.rendering;
      assert.equal(args.rendering, false);
      assert.equal(er.listEditTargets(args).settled, true);
      assert.equal(er.listEditTargets({...args, expectedVisual: getVisualSpread(6, true, 20, 'rtl')}).settled, false);
      assert.equal(er.listEditTargets({...args, mode: 'single'}).settled, false);
    });
  }

  await t.test('generated native request waits for measured page-area layout', async () => {
    const generated = sources[1][1];
    const beforeLayout = await runDisplayProducer(generated, {pageAreaLayout: {width: 0, height: 0}});
    assert.equal(beforeLayout.captured.display, null);
    assert.equal(er.listEditTargets({mode: 'single', pageIndex: 4, ...beforeLayout.captured}).settled, false);
    const measured = await runDisplayProducer(generated, {isLandscape: false, pageAreaLayout: {width: 1000, height: 600}});
    assert.equal(measured.effectiveMode, 'spread', 'measured layout overrides stale portrait window mode');
    assert.equal(measured.captured.display.kind, 'spread');
  });
});

test('Handoff result must name the requested document and page and not be a skip (finding 2)', () => {
  const filePath = '/doc/a.pdf';
  const result = {filePath, pageIndex: 31, uid: 1000};
  assert.deepEqual(er.evaluateHandoff(result, 31, filePath), {ok: true, reason: 'ok'});
  assert.equal(er.evaluateHandoff({annotationRecovery: true, uid: 1000}, 31, filePath).reason, 'recovery_skipped');
  assert.equal(er.evaluateHandoff({...result, pageIndex: 30}, 31, filePath).reason, 'page_mismatch');
  assert.equal(er.evaluateHandoff({filePath}, 31, filePath).reason, 'page_mismatch');
  assert.equal(er.evaluateHandoff({...result, filePath: '/doc/b.pdf'}, 31, filePath).reason, 'document_mismatch');
  for (const missing of [undefined, null, '']) {
    assert.equal(er.evaluateHandoff({...result, filePath: missing}, 31, filePath).reason, 'document_mismatch');
    assert.equal(er.evaluateHandoff(result, 31, missing).reason, 'document_mismatch');
  }
  assert.equal(er.evaluateHandoff(null, 31, filePath).reason, 'no_result');
  assert.equal(er.evaluateHandoff(undefined, 31, filePath).reason, 'no_result');
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
  const ok = {ready: true, busy: false, editInFlight: false, fatalError: null, authorityResolved: true, nativeSpreadConfigured: false, nativeSpreadEnabled: false, displaySettled: true};
  assert.deepEqual(er.editAvailability(ok), {allowed: true, reason: 'ok'});
  assert.equal(er.editAvailability({...ok, ready: false}).reason, 'not_ready');
  assert.equal(er.editAvailability({...ok, fatalError: 'x'}).reason, 'not_ready');
  assert.equal(er.editAvailability({...ok, editInFlight: true}).reason, 'edit_in_progress');
  assert.equal(er.editAvailability({...ok, busy: true}).reason, 'busy');
  assert.equal(er.editAvailability({...ok, authorityResolved: false}).reason, 'authority_unresolved');
  assert.equal(er.editAvailability({...ok, nativeSpreadEnabled: true}).reason, 'native_spread_active');
  // Finding 4: configured read-only Native Spread reports enabled=false but must still block.
  assert.equal(er.editAvailability({...ok, nativeSpreadConfigured: true, nativeSpreadEnabled: false}).reason, 'native_spread_active');
  assert.equal(er.editAvailability({...ok, displaySettled: false}).reason, 'page_unsettled');
  for (const reason of ['not_ready', 'busy', 'authority_unresolved', 'native_spread_active', 'page_unsettled', 'edit_in_progress', 'handoff_failed', 'save_failed', 'no_page']) {
    assert.ok(er.EDIT_BLOCKED_MESSAGES[reason], reason);
  }
});
