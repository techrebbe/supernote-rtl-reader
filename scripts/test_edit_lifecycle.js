#!/usr/bin/env node
'use strict';

// These are host integration tests of App.js's actual callback closures. The
// harness evaluates its pre-JSX body unchanged, including save/rollback/close
// helpers, against small React hook and native-module mocks. It does NOT copy
// the Edit state machine. Most cases supply ready state and completed images;
// initialization cases run the real extracted initialize() closure too. PDF
// rendering is not run. The real initialization-effect cleanup is extracted
// and run for every unmount test, and index integration uses its real wrapper
// and asynchronous button-listener source.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.resolve(__dirname, '..');
const APP = fs.readFileSync(path.join(ROOT, 'overlay/App.js'), 'utf8').replace(/\r\n/g, '\n');
const INDEX = fs.readFileSync(path.join(ROOT, 'overlay/index.js'), 'utf8').replace(/\r\n/g, '\n');
const er = require(path.join(ROOT, 'overlay/editReturn.js'));
const FILE = '/doc/a.pdf';
const NATIVE_OPEN_PAGE = 2;
const READER_PAGE = 10;
const EDIT_PAGE = 11;

const appStart = APP.indexOf('export default function App() {');
const appEnd = APP.indexOf('  const footerLabel =', appStart);
const helperStart = APP.indexOf('const {PdfRendererModule, ReaderPreferencesModule} = NativeModules;');
const helperEnd = APP.indexOf('function SegmentedButton(', helperStart);
assert.ok(appStart >= 0 && appEnd > appStart, 'App callback extraction boundaries changed');
assert.ok(helperStart >= 0 && helperEnd > helperStart, 'App helper extraction boundaries changed');
const body = APP.slice(appStart, appEnd).replace('export default function App()', 'function App()');
const stateNames = [...body.matchAll(/const\s+\[\s*(\w+)\s*,\s*(\w+)\s*\]\s*=\s*useState\(/g)].map(m => m[1]);
const localNames = [...body.matchAll(/^  const (\w+)\b/gm)].map(m => m[1]);
const stateLocals = [...body.matchAll(/const\s+\[\s*(\w+)\s*,\s*(\w+)\s*\]\s*=\s*useState\(/g)].flatMap(m => [m[1], m[2]]);
const exposed = [...new Set([...localNames, ...stateLocals])];
const cleanup = body.match(/return (\(\) => \{\s*mountedRef\.current = false;[\s\S]*?\n    \});\s*\n  \}, \[\]\);/);
assert.ok(cleanup, 'Could not extract the real initialization-effect unmount cleanup');
const initialize = body.match(/(async function initialize\(\) \{[\s\S]*?\n    \})\s*\n\s*initialize\(\);/);
assert.ok(initialize, 'Could not extract the actual initialize() closure');
const program = `${APP.slice(helperStart, helperEnd)}\n${body}\n` +
  `  return {${exposed.join(',')}, unmountCleanup: ${cleanup[1]}, initialize: ${initialize[1]}};\n}\nApp;`;
const wrapperStart = INDEX.indexOf('const originalClosePluginView =');
const wrapperEnd = INDEX.indexOf('function ReaderRoot()', wrapperStart);
assert.ok(wrapperStart >= 0 && wrapperEnd > wrapperStart, 'index.js close-wrapper extraction boundaries changed');
const wrapper = INDEX.slice(wrapperStart, wrapperEnd);
const buttonConstantsStart = INDEX.indexOf('const RTL_READER_BUTTON_ID =');
const buttonConstantsEnd = INDEX.indexOf('const icon =', buttonConstantsStart);
const buttonListenerStart = INDEX.indexOf('PluginManager.registerButtonListener({');
assert.ok(buttonConstantsStart >= 0 && buttonConstantsEnd > buttonConstantsStart && buttonListenerStart > wrapperEnd,
  'index.js button-listener extraction boundaries changed');
const buttonConstants = INDEX.slice(buttonConstantsStart, buttonConstantsEnd);
const buttonListener = INDEX.slice(buttonListenerStart);

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
  return {promise, resolve, reject};
}

function copy(value) {
  return value == null ? value : JSON.parse(JSON.stringify(value));
}

async function flush() {
  await new Promise(setImmediate);
}

async function bounded(promise, label = 'callback completion') {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} did not settle`)), 1500);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

function harness(options = {}) {
  const file = options.filePath ?? FILE;
  const state = {
    documentContext: {filePath: file, pageIndex: NATIVE_OPEN_PAGE, totalPages: 40},
    preferencesReady: true,
    pageIndex: READER_PAGE,
    totalPages: 40,
    display: {kind: 'spread', left: 'image-left', right: 'image-right', leftPageIndex: EDIT_PAGE, rightPageIndex: READER_PAGE},
    rendering: false,
    viewMode: 'spread',
    nativeSpreadAuthorityState: 'ready',
    nativeSpreadCompatible: true,
    settingsOpen: true,
    jumpOpen: true,
    jumpText: '25',
    ...options.state,
  };
  const refs = [];
  const effects = [];
  const timers = new Map();
  const backHandlers = [];
  const hostHides = [];
  const saves = [];
  const handoffs = [];
  const closes = [];
  const nativeChanges = [];
  const loads = [];
  const activations = [];
  const buttonListeners = [];
  const logs = [];
  const trace = options.trace || [];
  const savePlans = [...(options.savePlans || [])];
  const handoffPlans = [...(options.handoffPlans || [])];
  const closePlans = [...(options.closePlans || [])];
  const globals = options.globals || {};
  const store = options.store || new Map();
  let stateCursor = 0;
  let refCursor = 0;
  let effectCursor = 0;
  let timerId = 0;
  let callback;

  function executePlan(plan, fallback) {
    if (plan instanceof Error) return Promise.reject(plan);
    if (plan && typeof plan.then === 'function') return plan;
    return Promise.resolve(plan === undefined ? fallback : plan);
  }

  const native = {
    save(filePath, raw) {
      trace.push('save');
      const payload = JSON.parse(raw);
      const call = {filePath, payload, done: false};
      saves.push(call);
      return executePlan(savePlans.shift(), undefined).then(() => {
        call.done = true;
        store.set(filePath, copy(payload));
      });
    },
    handoffLastSavedPage() {
      trace.push('handoff');
      handoffs.push({persisted: copy(store.get(file))});
      return executePlan(handoffPlans.shift(), {filePath: file, pageIndex: EDIT_PAGE});
    },
    load(filePath) {
      const payload = copy(store.get(filePath));
      loads.push({filePath, payload});
      return Promise.resolve(payload == null ? null : JSON.stringify(payload));
    },
    configureNativeSpreadReadOnly(...args) { nativeChanges.push(['readOnly', args]); return Promise.resolve({}); },
    configureNativeSpreadEditable(...args) { nativeChanges.push(['editable', args]); return Promise.resolve({}); },
    reconcileNativeSpreadRecovery(...args) { nativeChanges.push(['reconcile', args]); return Promise.resolve({}); },
    restoreNativeAnnotationBackup(...args) { nativeChanges.push(['restore', args]); return Promise.resolve({}); },
    loadNativeSpreadMode(...args) {
      nativeChanges.push(['loadMode', args]);
      return Promise.resolve({
        configured: false, configuredEditable: false, activationPending: false,
        recoveryNeeded: false, enabled: false, editable: false, coverSeparate: false,
        showDivider: true, showHeader: true, compatible: true, backupAvailable: false,
        backupOriginalMarkPresent: false, reconciliationAvailable: false,
        spreadSizing: 'fit', backupStatus: 'missing', authorityStatus: 'ready', authorityReason: 'ready',
      });
    },
  };
  const context = vm.createContext({
    ...er,
    globalThis: globals,
    NativeModules: {ReaderPreferencesModule: native, SavedInkModule: options.savedInkModule,
      PdfRendererModule: {renderPage() { throw new Error('Unexpected PDF render'); }}},
    createSavedInkController: options.createSavedInkController,
    PluginFileAPI: options.pluginFileAPI,
    PluginManager: {
      getPluginDirPath: options.getPluginDirPath,
      closePluginView() {
        trace.push('close');
        closes.push({persisted: copy(store.get(file))});
        return executePlan(closePlans.shift(), undefined);
      },
      registerButtonListener(listener) { buttonListeners.push(listener); },
    },
    PluginCommAPI: {
      getCurrentFilePath: () => Promise.resolve({success: true, result: file}),
      getCurrentPageNum: () => Promise.resolve({success: true, result: NATIVE_OPEN_PAGE}),
    },
    PluginDocAPI: {getCurrentTotalPages: () => Promise.resolve({success: true, result: 40})},
    DeviceEventEmitter: {emit: (...args) => activations.push(args)},
    BackHandler: {
      addEventListener(name, handler) {
        assert.equal(name, 'hardwareBackPress');
        backHandlers.push(handler);
        return {remove() {}};
      },
    },
    Keyboard: {dismiss() {}},
    PanResponder: {create: config => ({panHandlers: config})},
    useWindowDimensions: () => ({width: 1400, height: 900}),
    useState(initial) {
      const name = stateNames[stateCursor++];
      assert.ok(name, 'Unexpected extra state hook');
      if (!Object.hasOwn(state, name)) state[name] = typeof initial === 'function' ? initial() : initial;
      return [state[name], value => { state[name] = typeof value === 'function' ? value(state[name]) : value; }];
    },
    useRef(initial) {
      const index = refCursor++;
      if (!refs[index]) refs[index] = {current: initial};
      return refs[index];
    },
    useEffect(effect, deps) {
      effects[effectCursor++] = {effect, deps};
    },
    setTimeout(fn) { const id = ++timerId; timers.set(id, fn); return id; },
    clearTimeout(id) { timers.delete(id); },
    console: Object.fromEntries(['log', 'warn', 'error'].map(level => [level, (...args) => logs.push([level, ...args])])),
  });
  const App = vm.runInContext(program, context, {filename: 'overlay/App.js lifecycle callbacks'});
  if (options.indexWrapper || options.indexListener) {
    vm.runInContext(wrapper, context, {filename: 'overlay/index.js actual close wrapper'});
  }
  if (options.indexListener) {
    vm.runInContext(buttonConstants + buttonListener, context, {filename: 'overlay/index.js actual activation listener'});
  }

  function render() {
    stateCursor = 0;
    refCursor = 0;
    effectCursor = 0;
    callback = App();
    assert.equal(stateCursor, stateNames.length, 'App state extraction missed a hook');
    return callback;
  }
  render();
  callback.filePathRef.current = file;
  callback.nativePageIndexAtOpenRef.current = NATIVE_OPEN_PAGE;
  render();
  const baseline = copy(callback.latestPreferencesRef.current);
  if (!store.has(file) && baseline) store.set(file, copy(baseline));
  const backEffect = effects.find(({effect}) => effect.toString().includes('BackHandler.addEventListener'));
  assert.ok(backEffect, 'BackHandler effect was not captured');
  backEffect.effect();

  return {
    get callback() { return callback; },
    context: globals,
    state,
    native,
    baseline,
    saves,
    handoffs,
    closes,
    hostHides,
    nativeChanges,
    loads,
    activations,
    store,
    logs,
    trace,
    get persisted() { return copy(store.get(file)); },
    render,
    back() {
      const consumed = backHandlers.some(handler => handler());
      if (!consumed) hostHides.push({reason: 'hardwareBack'});
      return consumed;
    },
    closeViaWrapper(...args) { return context.PluginManager.closePluginView(...args); },
    pressButton(event = {id: 100}) {
      assert.equal(buttonListeners.length, 1, 'Actual index button listener must be installed');
      return buttonListeners[0].onButtonPress(event);
    },
    unmount() { callback.unmountCleanup(); },
    runSavedInkEffect() {
      const effect = effects.find(({effect}) => effect.toString().includes('let cancelled = false;'));
      assert.ok(effect, 'Actual saved-ink lifecycle effect was not captured');
      return effect.effect();
    },
    runPreferenceEffect() {
      const effect = effects.find(({effect}) => effect.toString().includes("savePreferences('debounced')"));
      assert.ok(effect, 'Debounced preference effect was not captured');
      return effect.effect();
    },
    runTimers() {
      const scheduled = [...timers.values()];
      timers.clear();
      for (const fn of scheduled) fn();
    },
    get timerCount() { return timers.size; },
  };
}

function assertRestored(h) {
  assert.deepEqual(h.persisted, h.baseline, 'previous persisted reader payload must be restored exactly');
  assert.deepEqual(copy(h.callback.latestPreferencesRef.current), h.baseline);
  assert.equal(h.callback.editReturnRef.current, null);
  assert.equal(h.callback.editInFlightRef.current, false);
  // A component that was already unmounted must not receive state updates.
  if (h.callback.mountedRef.current) assert.equal(h.state.editBusy, false);
  assert.equal(h.handoffs.length, 0);
  assert.equal(h.closes.length, 0);
}

async function assertSuppressed(h) {
  const before = copy(h.state);
  const pageRef = h.callback.pageIndexRef.current;
  const savesBefore = h.saves.length;
  await h.callback.close();
  h.callback.nextLogicalPage();
  h.callback.previousLogicalPage();
  h.callback.handlePhysicalSwipe(80);
  h.callback.handlePhysicalTap(0);
  h.callback.submitJump();
  await h.callback.setDirectionValue('ltr');
  h.callback.setViewModeValue('single');
  await h.callback.setCoverSeparateValue(true);
  await h.callback.setNativeSpreadAppearanceValue(false, 'native_fill', false);
  await h.callback.setNativeSpreadReadOnly(false);
  await h.callback.setNativeSpreadEditableMode();
  await h.callback.reconcileNativeSpreadRecovery();
  await h.callback.restoreNativeBackup();
  h.callback.closeSettings();
  await h.callback.savePreferences('debounced');
  assert.equal(h.back(), true, 'Back must be consumed during Edit/recovery');
  assert.equal(h.closes.length, 0, 'normal Close must not compete with Edit');
  assert.equal(h.saves.length, savesBefore, 'ordinary saves must remain fenced');
  assert.equal(h.nativeChanges.length, 0, 'native settings must not compete with Edit');
  assert.equal(h.callback.pageIndexRef.current, pageRef, 'Jump must not mutate the live page ref');
  for (const key of ['pageIndex', 'direction', 'viewMode', 'coverSeparate', 'showSpreadDivider', 'showNativeSpreadHeader', 'spreadSizing', 'settingsOpen']) {
    assert.equal(h.state[key], before[key], `${key} must remain unchanged during Edit`);
  }
}

const tests = [];
function test(name, fn) { tests.push([name, fn]); }

// These integration cases run the actual App effect, actual production
// controller, actual Close/Edit callback, and actual index wrapper together.
// Deferred native discard models its explicit main-Looper lease-drain ACK;
// resolving the SDK alone must never release the handoff/host-close boundary.
const INK_FILE = '/storage/emulated/0/Document/RTL_RAPID_TOOLS_T004_20261001.pdf';
const INK_DIR = '/data/user/0/com.ratta.supernote.pluginhost/files/plugins/snrtl20260726001';
const INK_TOKEN = 'f3d09692-3a12-48cb-823b-62041968c761';
const INK_CONTROLLER = path.join(ROOT, 'overlay/savedInk.js');
const inkPrepared = () => ({
  token: INK_TOKEN, filePath: INK_FILE, pageIndex: 2, width: 1404, height: 1872,
  sourceVerified: true, pngPath: `${INK_DIR}/saved-ink-cache/${INK_TOKEN}/ink.png`,
});
const inkFinished = () => ({
  ...inkPrepared(), savedInkToken: INK_TOKEN, sourceUnchanged: true, markUnchanged: true,
  decoded: true, sha256: 'a'.repeat(64), byteLength: 1000, alphaMin: 0, alphaMax: 255,
});

function inkHarness(hooks = {}, options = {}) {
  delete require.cache[require.resolve(INK_CONTROLLER)];
  const {createSavedInkController} = require(INK_CONTROLLER);
  const controllers = [];
  const trace = [];
  const defaults = {
    pluginDir: () => INK_DIR,
    prepare: inkPrepared,
    generate: () => ({success: true, result: true}),
    finish: inkFinished,
    discard: token => ({token, discarded: true}),
  };
  const invoke = name => (...args) => {
    trace.push(name);
    return Promise.resolve().then(() => (hooks[name] || defaults[name])(...args)).then(result => {
      trace.push(`${name}:settled`);
      return result;
    });
  };
  const h = harness({
    indexWrapper: true,
    handoffPlans: [{filePath: INK_FILE, pageIndex: 2}],
    ...options,
    filePath: INK_FILE,
    trace,
    state: {
      documentContext: {filePath: INK_FILE, pageIndex: 2, totalPages: 8},
      pageIndex: 2, totalPages: 8,
      display: {kind: 'spread', leftPageIndex: 3, rightPageIndex: 2},
      ...options.state,
    },
    createSavedInkController(deps) {
      const controller = createSavedInkController(deps);
      controllers.push(controller);
      return controller;
    },
    getPluginDirPath: invoke('pluginDir'),
    pluginFileAPI: {generateMarkThumbnails: invoke('generate')},
    savedInkModule: {prepare: invoke('prepare'), finish: invoke('finish'), discard: invoke('discard')},
  });
  const cleanup = h.runSavedInkEffect();
  return Object.assign(h, {controllers, inkCleanup: cleanup});
}

for (const operation of ['close', 'edit']) {
  for (const stage of ['pluginDir', 'prepare', 'generate', 'finish']) {
    test(`${operation} quiesces actual ${stage} work and native lease drain before save/handoff/host close`, async () => {
      const pending = deferred();
      const drained = deferred();
      const h = inkHarness({[stage]: () => pending.promise, discard: () => drained.promise});
      await flush();
      assert.ok(h.trace.includes(stage), `The actual effect must enter ${stage}`);
      const transition = operation === 'close' ? h.callback.close() : h.callback.editPage(2);
      assert.equal(h.callback.savedInkContextRef.current, null, 'Publication authority is hidden synchronously');
      assert.equal(h.state.savedInk.status, 'unavailable');
      await flush();
      assert.equal(h.saves.length, 0);
      assert.equal(h.handoffs.length, 0);
      assert.equal(h.closes.length, 0);
      assert.ok(!h.trace.includes('discard'), 'Never remove output before its real native/SDK settlement');
      await h.callback.close();
      await h.callback.editPage(2);
      assert.equal(h.back(), true, 'Pending quiescence retains the transition fence');
      pending.resolve(stage === 'pluginDir' ? INK_DIR : stage === 'prepare' ? inkPrepared() :
        stage === 'finish' ? inkFinished() : {success: true, result: true});
      await flush();
      if (stage !== 'pluginDir') {
        assert.ok(h.trace.includes('discard'));
        assert.equal(h.saves.length, 0, 'SDK settlement alone is not a native lease-drain acknowledgment');
        assert.equal(h.handoffs.length, 0);
        assert.equal(h.closes.length, 0);
        drained.resolve({token: INK_TOKEN, discarded: true});
      }
      await bounded(transition);
      assert.equal(h.saves.length, 1);
      assert.equal(h.handoffs.length, 1, 'Edit and wrapper must not duplicate the native handoff');
      assert.equal(h.closes.length, 1);
      if (stage !== 'pluginDir') {
        assert.ok(h.trace.indexOf('discard:settled') < h.trace.indexOf('save'));
        assert.ok(h.trace.indexOf('discard:settled') < h.trace.indexOf('handoff'));
        assert.ok(h.trace.indexOf('discard:settled') < h.trace.indexOf('close'));
        assert.equal(h.controllers[0].getState().disposed, true);
      }
      h.inkCleanup();
      assert.equal(await h.context.RTL_READER_INK_CLEANUP, true);
    });
  }
}

test('settled ink hides immediately and Close still waits for retained view-lease drain', async () => {
  const drained = deferred();
  const h = inkHarness({discard: () => drained.promise});
  await flush();
  h.render();
  assert.equal(h.callback.savedInkTokenFor(2), INK_TOKEN);
  const closing = h.callback.close();
  assert.equal(h.callback.savedInkTokenFor(2), null, 'Even the cached ready-state accessor must hide its token');
  await flush();
  assert.equal(h.saves.length, 0);
  assert.equal(h.handoffs.length, 0);
  assert.equal(h.closes.length, 0);
  drained.resolve({token: INK_TOKEN, discarded: true});
  await bounded(closing);
  assert.equal(h.closes.length, 1);
  h.inkCleanup();
});

for (const operation of ['close', 'edit']) {
  test(`${operation} fails visibly closed on actual cleanup failure and never hands off`, async () => {
    const generation = deferred();
    const h = inkHarness({generate: () => generation.promise, discard: async () => { throw Error('drain rejected'); }});
    await flush();
    const transition = operation === 'close' ? h.callback.close() : h.callback.editPage(2);
    generation.resolve({success: true, result: true});
    await bounded(transition);
    assert.equal(h.handoffs.length, 0);
    assert.equal(h.closes.length, 0);
    assert.equal(h.callback.readerClosedRef.current, false);
    assert.equal(h.callback.savedInkTokenFor(2), null);
    assert.ok(h.state.editNotice.includes('Saved ink cleanup could not be verified'));
    assert.equal(h.context.RTL_READER_TRANSITION_IN_FLIGHT, null,
      'Finished rollback/failed Close releases its original transition normally');
    assert.equal(h.context.RTL_READER_INK_CLEANUP_BLOCKED, true);
    assert.equal(h.back(), true, 'Physical Back cannot dismiss the host after failed ink cleanup');
    assert.equal(h.hostHides.length, 0);
    assert.equal(h.handoffs.length, 0);
    assert.equal(h.closes.length, 0);
    assert.deepEqual(h.persisted, h.baseline, 'An unaccepted Edit must restore the exact previous preferences');
    assert.equal(h.saves.length, operation === 'edit' ? 1 : 0);
    await h.callback.close();
    await h.callback.editPage(2);
    assert.equal(h.handoffs.length, 0);
    assert.equal(h.closes.length, 0);
    assert.equal(h.trace.filter(name => name === 'generate').length, 1, 'Failed cleanup never starts a replacement SDK writer');
    assert.equal(h.back(), true, 'The failure latch survives further rejected Close/Edit attempts');
    assert.equal(h.hostHides.length, 0);
    h.inkCleanup();
    assert.equal(await h.context.RTL_READER_INK_CLEANUP, false);
  });
}

test('Back cleanup-failure latch clears only after current native cleanup is verified', async () => {
  const drained = deferred();
  const h = inkHarness({discard: () => drained.promise},
    {globals: {RTL_READER_INK_CLEANUP_BLOCKED: true, RTL_READER_INK_CLEANUP: Promise.resolve(true)}});
  await flush();
  const cleanup = h.callback.quiesceSavedInk();
  await flush();
  assert.equal(h.back(), true, 'A pending cleanup cannot clear an existing Back fence');
  assert.equal(h.hostHides.length, 0);
  drained.resolve({token: INK_TOKEN, discarded: true});
  await bounded(cleanup);
  assert.equal(h.context.RTL_READER_INK_CLEANUP_BLOCKED, false);
  assert.equal(h.back(), false, 'Normal Back resumes after an exact native cleanup acknowledgment');
  assert.equal(h.hostHides.length, 1);
  assert.equal(h.handoffs.length, 0);
  assert.equal(h.closes.length, 0);
  h.inkCleanup();
});

test('autonomous generation and discard rejection fence Back before any Close or Edit', async () => {
  const h = inkHarness({
    generate: async () => { throw Error('generation rejected'); },
    discard: async () => { throw Error('discard rejected'); },
  });
  await flush();
  assert.equal(h.state.savedInk.status, 'error');
  assert.equal(h.state.savedInk.reason, 'cleanup_failed');
  assert.equal(h.state.savedInk.handle.token, INK_TOKEN);
  assert.equal(h.controllers[0].getState().retained, true);
  assert.equal(h.controllers[0].getState().disposed, false);
  assert.equal(h.context.RTL_READER_TRANSITION_IN_FLIGHT, undefined);
  assert.equal(h.context.RTL_READER_INK_EXIT_PENDING, undefined);
  assert.equal(h.context.RTL_READER_INK_CLEANUP_BLOCKED, true);
  assert.equal(h.back(), true, 'Ordinary run-cleanup failure must consume Back without a transition fence');
  assert.equal(h.hostHides.length, 0);
  assert.equal(h.handoffs.length, 0);
  assert.equal(h.closes.length, 0);
  assert.equal(h.saves.length, 0);
  assert.ok(h.state.editNotice.includes('Saved ink cleanup could not be verified'));
  h.inkCleanup();
  assert.equal(await h.context.RTL_READER_INK_CLEANUP, false);
  assert.equal(h.back(), true);
  assert.equal(h.hostHides.length, 0);
});

test('Edit cleanup failure keeps rollback exclusive until prior preferences are restored', async () => {
  const generation = deferred();
  const restoration = deferred();
  const h = inkHarness({generate: () => generation.promise, discard: async () => { throw Error('cleanup failed'); }},
    {savePlans: [restoration.promise]});
  await flush();
  const editing = h.callback.editPage(2);
  generation.resolve({success: true, result: true});
  await flush();
  assert.equal(h.saves.length, 1);
  assert.equal(h.saves[0].done, false);
  assert.equal(h.callback.editInFlightRef.current, true);
  await assertSuppressed(h);
  restoration.resolve();
  await bounded(editing);
  assert.deepEqual(h.persisted, h.baseline);
  assert.equal(h.callback.editInFlightRef.current, false);
  assert.equal(h.handoffs.length, 0);
  assert.equal(h.closes.length, 0);
  h.inkCleanup();
});

test('actual index wrapper independently quiesces active SDK and native drain before handoff', async () => {
  const generation = deferred();
  const drained = deferred();
  const h = inkHarness({generate: () => generation.promise, discard: () => drained.promise});
  await flush();
  const closing = h.closeViaWrapper();
  assert.equal(h.callback.savedInkContextRef.current, null);
  assert.equal(h.state.savedInk.status, 'unavailable');
  const exitOwner = h.context.RTL_READER_INK_EXIT_PENDING;
  assert.ok(exitOwner, 'The unfenced wrapper establishes its Back guard synchronously');
  assert.equal(h.back(), true, 'Physical Back stays fenced while the SDK is pending');
  assert.equal(h.hostHides.length, 0);
  await flush();
  assert.equal(h.handoffs.length, 0);
  assert.equal(h.closes.length, 0);
  generation.resolve({success: true, result: true});
  await flush();
  assert.equal(h.context.RTL_READER_INK_EXIT_PENDING, exitOwner);
  assert.equal(h.back(), true, 'SDK settlement does not permit Back before the native drain ACK');
  assert.equal(h.hostHides.length, 0);
  assert.equal(h.handoffs.length, 0);
  assert.equal(h.closes.length, 0);
  drained.resolve({token: INK_TOKEN, discarded: true});
  await bounded(closing);
  assert.equal(h.handoffs.length, 1);
  assert.equal(h.closes.length, 1);
  assert.equal(h.context.RTL_READER_INK_EXIT_PENDING, null);
  assert.ok(h.trace.indexOf('discard:settled') < h.trace.indexOf('handoff'));
  h.inkCleanup();
});

for (const failure of ['false', 'rejected', 'malformed']) {
  test(`actual index wrapper rejects ${failure} prior cleanup without handoff/host close`, async () => {
    const cleanup = deferred();
    const h = harness({indexWrapper: true, globals: {RTL_READER_INK_CLEANUP: cleanup.promise}});
    const closing = h.closeViaWrapper();
    const rejected = assert.rejects(closing, /Saved ink cleanup could not be verified/);
    assert.ok(h.context.RTL_READER_INK_EXIT_PENDING, 'No-lifecycle fallback also fences pending cleanup');
    assert.equal(h.back(), true);
    assert.equal(h.hostHides.length, 0);
    if (failure === 'rejected') cleanup.reject(Error('prior cleanup rejected'));
    else cleanup.resolve(failure === 'false' ? false : {status: 'disposed'});
    await bounded(rejected);
    assert.equal(h.context.RTL_READER_INK_EXIT_PENDING, null);
    assert.equal(h.context.RTL_READER_INK_CLEANUP_BLOCKED, true);
    assert.equal(h.back(), true, 'Failed cleanup retains the exit fence after its pending token is released');
    assert.equal(h.hostHides.length, 0);
    assert.equal(h.handoffs.length, 0);
    assert.equal(h.closes.length, 0);
  });
}

test('no-lifecycle wrapper fallback consumes Back until exact prior cleanup settles cleanly', async () => {
  const cleanup = deferred();
  const h = harness({indexWrapper: true, globals: {RTL_READER_INK_CLEANUP: cleanup.promise}});
  const closing = h.closeViaWrapper();
  assert.ok(h.context.RTL_READER_INK_EXIT_PENDING);
  assert.equal(h.back(), true);
  assert.equal(h.hostHides.length, 0);
  assert.equal(h.handoffs.length, 0);
  assert.equal(h.closes.length, 0);
  cleanup.resolve(true);
  await bounded(closing);
  assert.equal(h.context.RTL_READER_INK_EXIT_PENDING, null);
  assert.equal(h.handoffs.length, 1);
  assert.equal(h.closes.length, 1);
});

test('actual index wrapper rechecks transition authority after awaiting ink cleanup', async () => {
  const cleanup = deferred();
  const h = harness({indexWrapper: true, globals: {RTL_READER_INK_CLEANUP: cleanup.promise}});
  const closing = h.closeViaWrapper();
  h.context.RTL_READER_TRANSITION_IN_FLIGHT = {allowClose: false};
  cleanup.resolve(true);
  await assert.rejects(closing, /changed while saved ink was settling/);
  assert.equal(h.handoffs.length, 0);
  assert.equal(h.closes.length, 0);
});

test('unfenced index close cannot target a replacement activation after awaiting old ink cleanup', async () => {
  const cleanup = deferred();
  const h = harness({indexWrapper: true, globals: {RTL_READER_INK_CLEANUP: cleanup.promise}});
  const closing = h.closeViaWrapper();
  const replacementExitOwner = {};
  h.context.RTL_READER_INK_EXIT_PENDING = replacementExitOwner;
  h.context.RTL_READER_INK_LIFECYCLE = {quiesce: async () => true};
  cleanup.resolve(true);
  await assert.rejects(closing, /changed while saved ink was settling/);
  assert.equal(h.handoffs.length, 0);
  assert.equal(h.closes.length, 0);
  assert.equal(h.context.RTL_READER_INK_EXIT_PENDING, replacementExitOwner,
    'An older wrapper cannot clear another activation\'s pending exit authority');
  assert.equal(h.back(), true);
  assert.equal(h.hostHides.length, 0);
});

test('repeated Edit is single-flight; normal Close, navigation, settings, and Back are suppressed', async () => {
  const saving = deferred();
  const h = harness({savePlans: [saving.promise]});
  h.runPreferenceEffect();
  assert.equal(h.timerCount, 1);
  const edit = h.callback.editPage(EDIT_PAGE);
  await flush();
  assert.equal(h.timerCount, 0, 'Edit cancels the scheduled preference write');
  assert.equal(h.saves.length, 1);
  assert.equal(h.callback.editInFlightRef.current, true);
  const pendingPayload = copy(h.callback.latestPreferencesRef.current);
  h.render();
  assert.deepEqual(copy(h.callback.latestPreferencesRef.current), pendingPayload,
    'the busy-state rerender must not rewrite the pending Edit payload');
  h.runPreferenceEffect();
  h.runTimers();
  await flush();
  assert.equal(h.saves.length, 1, 'rerender/debounce must not write while Edit is pending');
  await h.callback.editPage(READER_PAGE);
  assert.equal(h.saves.length, 1, 'second Edit must not enqueue a write');
  await assertSuppressed(h);
  saving.resolve();
  await bounded(edit);
  assert.equal(h.handoffs.length, 1);
  assert.equal(h.closes.length, 1);
  assert.equal(h.handoffs[0].persisted.lastPageIndex, EDIT_PAGE);
  assert.equal(h.handoffs[0].persisted.editReturn.editPage, EDIT_PAGE);
  assert.equal(h.closes[0].persisted.lastPageIndex, EDIT_PAGE);
  assert.equal(h.context.RTL_READER_EDIT_HANDOFF_DONE, true);
  await h.callback.editPage(READER_PAGE);
  assert.equal(h.handoffs.length, 1, 'successful Edit must never start a second handoff');
});

test('Edit drains every previously accepted preference write before saving or handoff', async () => {
  const first = deferred();
  const second = deferred();
  const h = harness({savePlans: [first.promise, second.promise]});
  const priorOne = h.callback.savePreferences('debounced', {...h.baseline, lastPageIndex: 4});
  const priorTwo = h.callback.savePreferences('debounced', {...h.baseline, lastPageIndex: 5});
  const edit = h.callback.editPage(EDIT_PAGE);
  await flush();
  assert.equal(h.saves.length, 1, 'prior writes themselves must be serialized');
  assert.equal(h.handoffs.length, 0);
  first.resolve();
  await bounded(priorOne);
  await flush();
  assert.equal(h.saves.length, 2);
  assert.equal(h.saves[1].payload.lastPageIndex, 5, 'previously accepted save remains ahead of Edit');
  assert.equal(h.handoffs.length, 0);
  second.resolve();
  await bounded(Promise.all([priorTwo, edit]));
  assert.deepEqual(h.saves.map(call => call.payload.lastPageIndex), [4, 5, EDIT_PAGE]);
  assert.equal(h.handoffs.length, 1);
  assert.equal(h.handoffs[0].persisted.lastPageIndex, EDIT_PAGE);
});

test('Edit fences opening settings/jump and otherwise-admissible native recovery actions', async () => {
  const saving = deferred();
  const h = harness({
    savePlans: [saving.promise],
    state: {
      settingsOpen: false,
      jumpOpen: false,
      nativeBackupAvailable: true,
      nativeSpreadReconciliationAvailable: true,
    },
  });
  const edit = h.callback.editPage(EDIT_PAGE);
  await flush();
  h.callback.openSettings();
  h.callback.openJump();
  assert.equal(h.state.settingsOpen, false);
  assert.equal(h.state.jumpOpen, false);
  await assertSuppressed(h);
  saving.resolve();
  await bounded(edit);
});

test('a rejected prior preference write does not strand the queue or prevent Edit', async () => {
  const first = deferred();
  const h = harness({savePlans: [first.promise]});
  const prior = h.callback.savePreferences('debounced').catch(() => {});
  const edit = h.callback.editPage(EDIT_PAGE);
  await flush();
  first.reject(new Error('prior save failed'));
  await bounded(Promise.all([prior, edit]));
  assert.equal(h.saves.length, 2);
  assert.equal(h.handoffs.length, 1);
  assert.equal(h.handoffs[0].persisted.lastPageIndex, EDIT_PAGE);
});

test('Edit save rejection restores prior in-memory and persisted reader state without handoff', async () => {
  const h = harness({savePlans: [new Error('save failed')]});
  await bounded(h.callback.editPage(EDIT_PAGE));
  assert.equal(h.saves.length, 2, 'failure must attempt the exact previous payload rollback');
  assertRestored(h);
  assert.equal(h.state.editNotice, er.EDIT_BLOCKED_MESSAGES.save_failed);
});

test('rollback remains exclusive until the previous payload has finished persisting', async () => {
  const restoring = deferred();
  const h = harness({savePlans: [new Error('save failed'), restoring.promise]});
  const edit = h.callback.editPage(EDIT_PAGE);
  await flush();
  assert.equal(h.saves.length, 2);
  assert.equal(h.saves[1].done, false);
  assert.equal(h.callback.editInFlightRef.current, true);
  await assertSuppressed(h);
  restoring.resolve();
  await bounded(edit);
  assertRestored(h);
});

test('rollback save rejection stays fenced and only an explicit restore retry can release it', async () => {
  const h = harness({savePlans: [new Error('save failed'), new Error('rollback failed')]});
  await bounded(h.callback.editPage(EDIT_PAGE));
  assert.equal(h.callback.editInFlightRef.current, true);
  assert.equal(h.state.editBusy, true);
  assert.equal(h.state.editRecoveryAvailable, true);
  assert.ok(typeof h.callback.retryEditRecovery === 'function', 'recovery must be a real App callback');
  await assertSuppressed(h);
  await h.callback.editPage(READER_PAGE);
  assert.equal(h.saves.length, 2, 'recovery cannot be bypassed by another Edit');
  await bounded(h.callback.retryEditRecovery());
  assert.equal(h.saves.length, 3);
  assertRestored(h);
  assert.equal(h.state.editRecoveryAvailable, false);
});

test('repeated restore retries are single-flight while the rollback write is pending', async () => {
  const restoring = deferred();
  const h = harness({savePlans: [new Error('save failed'), new Error('rollback failed'), restoring.promise]});
  await bounded(h.callback.editPage(EDIT_PAGE));
  const retry = h.callback.retryEditRecovery();
  await flush();
  await h.callback.retryEditRecovery();
  assert.equal(h.saves.length, 3, 'a second retry cannot enqueue another restoration');
  await assertSuppressed(h);
  restoring.resolve();
  await bounded(retry);
  assertRestored(h);
});

test('close failure preserves accepted Edit state and retries only close, never native handoff', async () => {
  const h = harness({closePlans: [new Error('plugin close failed')]});
  await bounded(h.callback.editPage(EDIT_PAGE));
  assert.equal(h.handoffs.length, 1);
  assert.equal(h.closes.length, 1);
  assert.equal(h.callback.editInFlightRef.current, true);
  assert.equal(h.state.editRecoveryAvailable, true);
  assert.equal(h.persisted.editReturn.editPage, EDIT_PAGE);
  await h.callback.editPage(READER_PAGE);
  await h.callback.close();
  assert.equal(h.handoffs.length, 1);
  assert.equal(h.closes.length, 1);
  await bounded(h.callback.retryEditRecovery());
  assert.equal(h.closes.length, 2);
  assert.equal(h.handoffs.length, 1);
  assert.equal(h.saves.length, 1, 'accepted Edit must not be resaved or rolled back on close retry');
  assert.equal(h.context.RTL_READER_EDIT_HANDOFF_DONE, true);
  assert.equal(h.state.editRecoveryAvailable, false);
});

test('unmount during Edit save waits, rolls back, and never starts native handoff or plugin close', async () => {
  const saving = deferred();
  const h = harness({savePlans: [saving.promise]});
  const edit = h.callback.editPage(EDIT_PAGE);
  await flush();
  h.unmount();
  await flush();
  assert.equal(h.saves.length, 1, 'unmount must not race the Edit write with an ordinary save');
  saving.resolve();
  await bounded(edit);
  assert.equal(h.saves.length, 2, 'unmounted Edit must restore the previous payload after the write settles');
  assertRestored(h);
});

test('unmount during a rejected Edit save still serializes rollback and never hands off', async () => {
  const saving = deferred();
  const h = harness({savePlans: [saving.promise]});
  const edit = h.callback.editPage(EDIT_PAGE);
  await flush();
  h.unmount();
  saving.reject(new Error('save failed after unmount'));
  await bounded(edit);
  assert.equal(h.saves.length, 2);
  assertRestored(h);
});

test('unmount while prior preference writes drain cannot start Edit handoff or close', async () => {
  const saving = deferred();
  const h = harness({savePlans: [saving.promise]});
  const prior = h.callback.savePreferences('debounced');
  const edit = h.callback.editPage(EDIT_PAGE);
  await flush();
  h.unmount();
  saving.resolve();
  await bounded(Promise.all([prior, edit]));
  assert.equal(h.handoffs.length, 0);
  assert.equal(h.closes.length, 0);
  assert.deepEqual(h.persisted, h.baseline);
});

test('unmount during successful native handoff preserves the accepted Edit record without issuing plugin close', async () => {
  const handingOff = deferred();
  const h = harness({handoffPlans: [handingOff.promise]});
  const edit = h.callback.editPage(EDIT_PAGE);
  await flush();
  assert.equal(h.handoffs.length, 1);
  h.unmount();
  assert.equal(h.saves.length, 1, 'unmount must not enqueue a stale ordinary payload');
  handingOff.resolve({filePath: FILE, pageIndex: EDIT_PAGE});
  await bounded(edit);
  assert.equal(h.handoffs.length, 1);
  assert.equal(h.closes.length, 0, 'an unmounted callback cannot close a different/new plugin view');
  assert.equal(h.persisted.lastPageIndex, EDIT_PAGE);
  assert.equal(h.persisted.editReturn.editPage, EDIT_PAGE);
});

test('unmount during failed native handoff queues the exact prior preference rollback', async () => {
  const handingOff = deferred();
  const h = harness({handoffPlans: [handingOff.promise]});
  const edit = h.callback.editPage(EDIT_PAGE);
  await flush();
  h.unmount();
  handingOff.reject(new Error('handoff failed after unmount'));
  await bounded(edit);
  assert.equal(h.saves.length, 2);
  assert.deepEqual(h.persisted, h.baseline);
  assert.equal(h.handoffs.length, 1);
  assert.equal(h.closes.length, 0);
});

for (const result of [
  {filePath: FILE, annotationRecovery: true, pageIndex: EDIT_PAGE},
  {filePath: FILE, pageIndex: READER_PAGE},
  {filePath: '/doc/other.pdf', pageIndex: EDIT_PAGE},
  undefined,
]) {
  test(`failed/mismatched handoff ${JSON.stringify(result)} restores the exact previous payload`, async () => {
    // null is supplied for the no-result case because undefined selects the
    // mock's default successful result.
    const h = harness({handoffPlans: [result === undefined ? null : result]});
    await bounded(h.callback.editPage(EDIT_PAGE));
    assert.equal(h.handoffs.length, 1);
    assert.equal(h.closes.length, 0);
    assert.equal(h.saves.length, 2);
    assert.deepEqual(h.persisted, h.baseline);
    assert.equal(h.callback.editInFlightRef.current, false);
    assert.equal(h.state.editNotice, er.EDIT_BLOCKED_MESSAGES.handoff_failed);
  });
}

for (const state of [
  {nativeSpreadConfigured: true, nativeSpreadEnabled: false, nativeSpreadConfiguredEditable: false},
  {nativeSpreadConfigured: true, nativeSpreadEnabled: false, nativeSpreadConfiguredEditable: true},
  {nativeSpreadConfigured: false, nativeSpreadEnabled: true},
]) {
  test(`configured/live Native Spread is blocked even when runtime differs: ${JSON.stringify(state)}`, async () => {
    const h = harness({state});
    await bounded(h.callback.editPage(EDIT_PAGE));
    assert.equal(h.saves.length, 0);
    assert.equal(h.handoffs.length, 0);
    assert.equal(h.closes.length, 0);
    assert.equal(h.state.editNotice, er.EDIT_BLOCKED_MESSAGES.native_spread_active);
  });
}

test('an already-started normal Close fences Edit and does not race its preference save', async () => {
  const saving = deferred();
  const h = harness({savePlans: [saving.promise]});
  const closing = h.callback.close();
  await flush();
  await h.callback.editPage(EDIT_PAGE);
  assert.equal(h.saves.length, 1);
  assert.equal(h.handoffs.length, 0);
  saving.resolve();
  await bounded(closing);
  assert.equal(h.closes.length, 1);
  assert.equal(h.closes[0].persisted.editReturn, undefined);
});

test('ordinary unmount preference save remains behind previously accepted writes', async () => {
  const saving = deferred();
  const h = harness({savePlans: [saving.promise]});
  const prior = h.callback.savePreferences('debounced', {...h.baseline, lastPageIndex: 4});
  await flush();
  h.unmount();
  await flush();
  assert.equal(h.saves.length, 1);
  saving.resolve();
  await bounded(prior);
  await flush();
  assert.equal(h.saves.length, 2);
  assert.deepEqual(h.persisted, h.baseline);
});

test('a new activation drains a native preference write accepted by the prior React activation', async () => {
  const globals = {};
  const saving = deferred();
  const previous = harness({globals, savePlans: [saving.promise]});
  const prior = previous.callback.savePreferences('debounced');
  await flush();
  const current = harness({globals});
  const edit = current.callback.editPage(EDIT_PAGE);
  await flush();
  assert.equal(current.saves.length, 0, 'a fresh component must still wait for the old native write');
  assert.equal(current.handoffs.length, 0);
  saving.resolve();
  await bounded(Promise.all([prior, edit]));
  assert.equal(current.saves.length, 1);
  assert.equal(current.handoffs.length, 1);
  assert.equal(current.handoffs[0].persisted.editReturn.editPage, EDIT_PAGE);
});

test('closed cached callbacks and their later unmount cannot write over a fresh activation', async () => {
  const globals = {};
  const previous = harness({globals});
  await bounded(previous.callback.editPage(EDIT_PAGE));
  const current = harness({globals, state: {pageIndex: 18}});
  await current.callback.savePreferences('debounced');
  await previous.callback.close();
  await previous.callback.editPage(READER_PAGE);
  previous.unmount();
  await flush();
  assert.equal(previous.saves.length, 1, 'closed cached App cannot issue an old unmount save');
  assert.equal(previous.handoffs.length, 1);
  assert.equal(previous.closes.length, 1);
  assert.equal(current.persisted.lastPageIndex, 18);
});

test('the real index close wrapper refuses premature close and skips the successful App Edit handoff', async () => {
  const saving = deferred();
  const h = harness({indexWrapper: true, savePlans: [saving.promise]});
  const edit = h.callback.editPage(EDIT_PAGE);
  await flush();
  await assert.rejects(h.closeViaWrapper(), /Reader hand-off or recovery is still in progress/);
  assert.equal(h.handoffs.length, 0);
  assert.equal(h.closes.length, 0);
  saving.resolve();
  await bounded(edit);
  assert.equal(h.handoffs.length, 1, 'the wrapper must not repeat App.js native handoff');
  assert.equal(h.closes.length, 1);
  assert.equal(h.handoffs[0].persisted.lastPageIndex, EDIT_PAGE);
  assert.equal(h.handoffs[0].persisted.editReturn.filePath, FILE);
  assert.equal(h.context.RTL_READER_EDIT_HANDOFF_DONE, true);
});

test('the real index wrapper preserves one normal Close handoff across a plugin-close retry', async () => {
  const h = harness({indexWrapper: true, closePlans: [new Error('plugin close failed')]});
  await bounded(h.callback.close());
  assert.equal(h.handoffs.length, 1);
  assert.equal(h.closes.length, 1);
  await h.callback.close();
  assert.equal(h.closes.length, 1, 'normal Close must remain fenced until explicit recovery retry');
  await bounded(h.callback.retryEditRecovery());
  assert.equal(h.handoffs.length, 1);
  assert.equal(h.closes.length, 2);
});

test('actual activation button cannot bypass a mounted pending Edit', async () => {
  const saving = deferred();
  const h = harness({indexListener: true, savePlans: [saving.promise]});
  const edit = h.callback.editPage(EDIT_PAGE);
  await flush();
  h.pressButton();
  h.pressButton();
  await flush();
  assert.equal(h.activations.length, 0);
  assert.equal(h.saves.length, 1);
  assert.equal(h.handoffs.length, 0);
  assert.equal(h.closes.length, 0);
  saving.resolve();
  await bounded(edit);
  assert.equal(h.handoffs.length, 1);
  assert.equal(h.closes.length, 1);
  assert.equal(h.activations.length, 0);
});

test('actual activation button cannot bypass a mounted rollback-recovery fence', async () => {
  const h = harness({indexListener: true, savePlans: [new Error('save failed'), new Error('rollback failed')]});
  await bounded(h.callback.editPage(EDIT_PAGE));
  h.pressButton();
  h.pressButton();
  await flush();
  assert.equal(h.activations.length, 0);
  assert.equal(h.saves.length, 2, 'orphan recovery is not admitted while the recovery UI is mounted');
  assert.equal(h.callback.editInFlightRef.current, true);
  assert.equal(h.state.editRecoveryAvailable, true);
  assert.equal(h.handoffs.length, 0);
  assert.equal(h.closes.length, 0);
});

test('actual activation button repairs an orphan rollback once before one double-press activation', async () => {
  const restoring = deferred();
  const h = harness({
    indexListener: true,
    savePlans: [new Error('save failed'), new Error('rollback failed'), restoring.promise],
  });
  await bounded(h.callback.editPage(EDIT_PAGE));
  h.unmount();
  h.pressButton();
  h.pressButton();
  await flush();
  assert.equal(h.saves.length, 3, 'double activation must run only one orphan repair write');
  assert.equal(h.activations.length, 0, 'activation must wait until repair is persisted');
  assert.ok(h.context.RTL_READER_TRANSITION_IN_FLIGHT);
  restoring.resolve();
  await flush();
  assert.equal(h.activations.length, 1);
  assert.deepEqual(h.activations[0], ['RTL_READER_ACTIVATE']);
  assert.equal(h.context.RTL_READER_TRANSITION_IN_FLIGHT, null);
  assertRestored(h);
});

test('failed orphan repair remains fenced; a later button press can retry without native handoff or close', async () => {
  const h = harness({
    indexListener: true,
    savePlans: [new Error('save failed'), new Error('rollback failed'), new Error('orphan repair failed')],
  });
  await bounded(h.callback.editPage(EDIT_PAGE));
  h.unmount();
  h.pressButton();
  h.pressButton();
  await flush();
  assert.equal(h.saves.length, 3);
  assert.equal(h.activations.length, 0);
  assert.ok(h.context.RTL_READER_TRANSITION_IN_FLIGHT);
  assert.equal(h.callback.editInFlightRef.current, true);
  h.pressButton();
  await flush();
  assert.equal(h.saves.length, 4);
  assert.equal(h.activations.length, 1);
  assertRestored(h);
});

test('double activation after an orphan Close failure releases once without another native Close or handoff', async () => {
  const h = harness({indexListener: true, closePlans: [new Error('plugin close failed')]});
  await bounded(h.callback.editPage(EDIT_PAGE));
  assert.equal(h.handoffs.length, 1);
  assert.equal(h.closes.length, 1);
  h.unmount();
  h.pressButton();
  h.pressButton();
  await flush();
  assert.equal(h.activations.length, 1, 'even an immediately resolved orphan repair must emit only one activation');
  assert.equal(h.handoffs.length, 1);
  assert.equal(h.closes.length, 1);
  assert.equal(h.saves.length, 1);
  assert.equal(h.context.RTL_READER_TRANSITION_IN_FLIGHT, null);
  assert.equal(h.persisted.editReturn.editPage, EDIT_PAGE);
});

const UNINITIALIZED_STATE = {
  documentContext: null,
  preferencesReady: false,
  pageIndex: null,
  totalPages: null,
  display: {kind: 'single', single: null},
  rendering: true,
  nativeSpreadAuthorityState: 'unknown',
};

test('actual initialize waits for prior save and newest unmount payload before reading; its debounce cannot overwrite newer state', async () => {
  const store = new Map();
  const globals = {};
  const first = deferred();
  const last = deferred();
  const previous = harness({globals, store, savePlans: [first.promise, last.promise]});
  const prior = previous.callback.savePreferences('debounced', {...previous.baseline, lastPageIndex: 4});
  await flush();
  previous.state.pageIndex = 18;
  previous.render();
  previous.unmount();
  const current = harness({globals, store, state: UNINITIALIZED_STATE});
  const opening = current.callback.initialize();
  await flush();
  assert.equal(current.loads.length, 0, 'initialize must not read ahead of old queued preference writes');
  first.resolve();
  await bounded(prior);
  await flush();
  assert.equal(previous.saves.length, 2);
  assert.equal(store.get(FILE).lastPageIndex, 4);
  assert.equal(current.loads.length, 0, 'initialize must wait for the newest queued unmount write too');
  last.resolve();
  await bounded(opening);
  assert.equal(current.loads.length, 1);
  assert.equal(current.loads[0].payload.lastPageIndex, 18);
  assert.equal(current.state.pageIndex, 18);
  assert.equal(current.state.preferencesReady, true);
  current.render();
  current.runPreferenceEffect();
  current.runTimers();
  await flush();
  assert.equal(store.get(FILE).lastPageIndex, 18, 'fresh activation debounce must preserve the newest page');
});

test('actual initialize unmounted during preference-chain drain never starts a stale native load', async () => {
  const store = new Map();
  const globals = {};
  const saving = deferred();
  const previous = harness({globals, store, savePlans: [saving.promise]});
  const prior = previous.callback.savePreferences('debounced');
  await flush();
  const current = harness({globals, store, state: UNINITIALIZED_STATE});
  const opening = current.callback.initialize();
  await flush();
  current.unmount();
  saving.resolve();
  await bounded(Promise.all([prior, opening]));
  assert.equal(current.loads.length, 0);
  assert.equal(current.state.preferencesReady, false);
  assert.equal(current.state.documentContext, null);
  assert.equal(current.saves.length, 0);
});

test('never-ready fatal Close skips preferences and stale-document handoff but still closes the plugin', async () => {
  const h = harness({indexWrapper: true, state: {...UNINITIALIZED_STATE, fatalError: 'Initialization failed'}});
  await bounded(h.callback.close());
  assert.equal(h.saves.length, 0);
  assert.equal(h.handoffs.length, 0);
  assert.equal(h.closes.length, 1);
});

test('never-ready fatal Close retry still cannot hand off a stale previous document', async () => {
  const h = harness({
    indexWrapper: true,
    closePlans: [new Error('plugin close failed')],
    state: {...UNINITIALIZED_STATE, fatalError: 'Initialization failed'},
  });
  await bounded(h.callback.close());
  assert.equal(h.state.editRecoveryAvailable, true);
  await bounded(h.callback.retryEditRecovery());
  assert.equal(h.saves.length, 0);
  assert.equal(h.handoffs.length, 0);
  assert.equal(h.closes.length, 2);
});

test('initialized Close with missing preference storage remains open without native handoff', async () => {
  const h = harness({indexWrapper: true});
  delete h.native.save;
  await bounded(h.callback.close());
  assert.equal(h.saves.length, 0);
  assert.equal(h.handoffs.length, 0);
  assert.equal(h.closes.length, 0);
  assert.ok(h.state.editNotice.includes('Could not save'));
});

(async () => {
  let failed = 0;
  for (const [name, fn] of tests) {
    try {
      await fn();
      console.log(`PASS ${name}`);
    } catch (error) {
      failed += 1;
      console.error(`FAIL ${name}\n${error.stack}`);
    }
  }
  console.log(`Edit lifecycle integration: ${tests.length - failed}/${tests.length} passed`);
  if (failed) process.exitCode = 1;
})().catch(error => { console.error(error.stack); process.exitCode = 1; });
