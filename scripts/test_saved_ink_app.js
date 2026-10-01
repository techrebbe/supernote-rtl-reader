'use strict';
// Execute the actual App effect/accessor, not a copied lifecycle model. Native
// and SDK promises are controlled; the real savedInk.js controller owns cleanup.
// No React renderer, device, filesystem mutation, timers, or external services.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const APP = path.join(__dirname, '..', 'overlay', 'App.js');
const CONTROLLER = path.join(__dirname, '..', 'overlay', 'savedInk.js');
const FILE = '/storage/emulated/0/Document/RTL_RAPID_TOOLS_T004_20261001.pdf';
const DIR = '/data/user/0/com.ratta.supernote.pluginhost/files/plugins/snrtl20260726001';
const TOKEN = 'f3d09692-3a12-48cb-823b-62041968c761';
const OTHER_TOKEN = 'e3d09692-3a12-48cb-823b-62041968c761';

function once(source, marker) {
  const first = source.indexOf(marker);
  assert.notEqual(first, -1, `Exact-source marker missing: ${marker}`);
  assert.equal(source.indexOf(marker, first + marker.length), -1, `Ambiguous marker: ${marker}`);
  return first;
}

function appSource() {
  const source = fs.readFileSync(APP, 'utf8').replace(/\r\n/g, '\n');
  const effectStart = once(source, '  useEffect(() => {\n    let cancelled = false;');
  const effectEndMarker = '  }, [savedInkVisible, documentContext?.filePath]);';
  const effectEnd = once(source, effectEndMarker);
  assert.ok(effectEnd > effectStart);
  const effect = source.slice(effectStart, effectEnd + effectEndMarker.length);
  const accessorStart = once(source, '  const savedInkTokenFor = page =>');
  assert.ok(accessorStart < effectStart);
  const accessor = source.slice(accessorStart, effectStart).trim();
  return {effect, accessor};
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}

async function flush(count = 80) {
  for (let step = 0; step < count; step += 1) await Promise.resolve();
}

function prepared(token) {
  return {
    token, filePath: FILE, pageIndex: 2, width: 1404, height: 1872,
    sourceVerified: true, pngPath: `${DIR}/saved-ink-cache/${token}/ink.png`,
  };
}

function finished(token) {
  return {
    ...prepared(token), savedInkToken: token, sourceUnchanged: true, markUnchanged: true,
    decoded: true, sha256: 'a'.repeat(64), byteLength: 1000, alphaMin: 0, alphaMax: 255,
  };
}

function harness(hooks = {}) {
  // Fresh module ownership per test; all mounts within the test share this real
  // module instance and the real global cleanup promise, including failed cleanup.
  delete require.cache[require.resolve(CONTROLLER)];
  const {createSavedInkController} = require(CONTROLLER);
  const code = appSource();
  const calls = [];
  const controllers = [];
  const mounts = [];
  const sharedGlobal = {};
  const contextRef = {current: {filePath: FILE, pageIndex: 2, totalPages: 8}};
  let filePath = FILE;
  let transitionLocked = false;
  let preparedCount = 0;

  function count(name) { return calls.filter(call => call.name === name).length; }
  async function invoke(name, defaults, args) {
    calls.push({name, args});
    return hooks[name] ? hooks[name](...args) : defaults(...args);
  }
  const native = {
    prepare: (...args) => invoke('prepare', () => prepared(++preparedCount === 1 ? TOKEN : OTHER_TOKEN), args),
    finish: (...args) => invoke('finish', token => finished(token), args),
    discard: (...args) => invoke('discard', token => ({token, discarded: true}), args),
  };

  function mount(options = {}) {
    const visible = options.visible !== false;
    const documentContext = {filePath: options.filePath ?? filePath};
    const updates = [];
    const logs = [];
    let cleanup;
    const scope = {
      globalThis: sharedGlobal,
      savedInkVisible: visible,
      documentContext,
      savedInkContextRef: contextRef,
      savedInkLifecycleRef: {current: null},
      mountedRef: {current: true},
      SavedInkModule: options.moduleAbsent ? undefined : native,
      PluginManager: {
        getPluginDirPath: (...args) => invoke('pluginDir', async () => DIR, args),
      },
      PluginCommAPI: {
        getCurrentFilePath: (...args) => invoke('currentFile', async () => ({success: true, result: filePath}), args),
      },
      PluginFileAPI: {
        generateMarkThumbnails: (...args) => invoke('generate', async () => ({success: true, result: true}), args),
      },
      createSavedInkController(deps) {
        const controller = createSavedInkController(deps);
        controllers.push(controller);
        return controller;
      },
      async requireResult(promise, label) {
        const response = await promise;
        if (response?.success !== true) throw Error(`${label} unavailable`);
        return response.result;
      },
      readerTransitionLocked: () => transitionLocked,
      setSavedInk: value => updates.push(value),
      console: {log: (...args) => logs.push(args), warn: (...args) => logs.push(args)},
      useEffect(effect, dependencies) {
        assert.deepEqual(dependencies, [visible, documentContext.filePath]);
        cleanup = effect();
      },
    };
    const names = Object.keys(scope);
    new Function(...names, code.effect)(...names.map(name => scope[name]));
    assert.equal(typeof cleanup, 'function', 'The real effect must retain its cleanup callback');
    const instance = {
      updates, logs,
      get state() { return updates.at(-1); },
      get ready() { return updates.filter(value => value.status === 'ready'); },
      tokenFor(page, overrides = {}) {
        return new Function('savedInkVisible', 'savedInk', 'documentContext', 'SAVED_INK_PAGE',
          'savedInkContextRef', 'readerTransitionLocked', `${code.accessor}\nreturn savedInkTokenFor;`)(
          overrides.visible ?? visible,
          overrides.state ?? instance.state ?? {},
          overrides.documentContext ?? documentContext,
          2,
          contextRef,
          () => transitionLocked,
        )(page);
      },
      cleanup() { cleanup(); return sharedGlobal.RTL_READER_INK_CLEANUP; },
      quiesce() { return sharedGlobal.RTL_READER_INK_LIFECYCLE.quiesce(); },
    };
    mounts.push(instance);
    return instance;
  }

  return {
    mount, calls, controllers, mounts, sharedGlobal, count,
    async enter(name, expected = 1) {
      for (let step = 0; step < 150 && count(name) < expected; step += 1) await Promise.resolve();
      assert.equal(count(name), expected, `Expected ${expected} ${name} calls`);
    },
    changeFile(value) { filePath = value; },
    changeVisibleContext(value) { contextRef.current = value; },
    lockTransition(value = true) { transitionLocked = value; },
  };
}

test('exact App effect generates original PAGE3 and publishes token only for matching displayed page/document', async () => {
  const h = harness();
  const app = h.mount();
  await flush();
  assert.equal(app.state.status, 'ready');
  assert.equal(app.ready.length, 1);
  assert.equal(app.state.filePath, FILE);
  assert.equal(app.tokenFor(2), TOKEN);
  for (const page of [0, 1, 3, 7, '2', null, NaN]) assert.equal(app.tokenFor(page), null);
  assert.equal(app.tokenFor(2, {visible: false}), null);
  assert.equal(app.tokenFor(2, {documentContext: {filePath: '/Document/other.pdf'}}), null);
  assert.equal(app.tokenFor(2, {state: {...app.state, status: 'loading'}}), null);
  assert.deepEqual(h.calls.find(call => call.name === 'prepare').args, [FILE, 2, 1404, 1872, DIR]);
  assert.deepEqual(h.calls.find(call => call.name === 'generate').args, [FILE, 2, prepared(TOKEN).pngPath, {width: 1404, height: 1872}]);
  assert.equal(h.count('discard'), 0);
  assert.equal(await app.cleanup(), true);
  assert.equal(h.count('discard'), 1);
});

test('invisible effect does not query plugin/native/SDK and leaves PDF state outside ink effect', async () => {
  const h = harness();
  const app = h.mount({visible: false});
  await flush();
  assert.deepEqual(app.state, {status: 'unavailable'});
  assert.equal(app.tokenFor(2), null);
  assert.equal(h.calls.length, 0);
  assert.equal(await app.cleanup(), true);
});

test('missing native module is a local ink error without plugin/native/SDK work', async () => {
  const h = harness();
  const app = h.mount({moduleAbsent: true});
  await flush();
  assert.deepEqual(app.state, {status: 'error', reason: 'module_unavailable'});
  assert.equal(app.tokenFor(2), null);
  assert.equal(h.calls.length, 0);
  assert.equal(await app.cleanup(), true);
});

test('plugin directory failure is caught locally and does not stop normal PDF reading', async () => {
  const h = harness({pluginDir: async () => { throw Error('plugin path denied'); }});
  const app = h.mount();
  await flush();
  assert.deepEqual(app.state, {status: 'error', reason: 'plugin path denied'});
  assert.equal(app.tokenFor(2), null);
  assert.equal(h.count('prepare'), 0);
  assert.equal(h.count('generate'), 0);
  assert.equal(await app.cleanup(), true);
});

test('invalid plugin path fails controller context before generating an image', async () => {
  const h = harness({pluginDir: async () => '/storage/emulated/0/not-private'});
  const app = h.mount();
  await flush();
  assert.equal(app.state.status, 'unavailable');
  assert.equal(app.state.reason, 'unsupported_context');
  assert.equal(h.count('prepare'), 0);
  assert.equal(h.count('generate'), 0);
  assert.equal(await app.cleanup(), true);
});

test('cancellation while plugin directory is pending suppresses errors and all subsequent native work', async () => {
  const directory = deferred();
  const h = harness({pluginDir: () => directory.promise});
  const app = h.mount();
  await h.enter('pluginDir');
  const disposal = app.cleanup();
  directory.reject(Error('late plugin error'));
  assert.equal(await disposal, true);
  assert.equal(app.updates.length, 1, 'No state publication after effect cleanup');
  assert.equal(h.count('prepare'), 0);
  assert.equal(h.count('generate'), 0);
});

test('cancelled prepare retains token until native settlement, then cleans without SDK work', async () => {
  const preparation = deferred();
  const h = harness({prepare: () => preparation.promise});
  const app = h.mount();
  await h.enter('prepare');
  const disposal = app.cleanup();
  await flush();
  assert.equal(h.count('discard'), 0);
  preparation.resolve(prepared(TOKEN));
  assert.equal(await disposal, true);
  assert.equal(h.count('generate'), 0);
  assert.equal(h.count('discard'), 1);
  assert.equal(app.updates.length, 1);
});

test('pending SDK output is never discarded early and remount waits for exact prior cleanup', async () => {
  const generation = deferred();
  let generations = 0;
  const h = harness({generate: () => ++generations === 1 ? generation.promise : {success: true, result: true}});
  const old = h.mount();
  await h.enter('generate');
  const disposal = old.cleanup();
  const next = h.mount();
  await flush();
  assert.equal(h.count('generate'), 1);
  assert.equal(h.count('prepare'), 1);
  assert.equal(h.count('discard'), 0, 'SDK still owns its PNG output');
  assert.equal(next.state.status, 'loading');
  generation.resolve({success: true, result: true});
  assert.equal(await disposal, true);
  await flush();
  assert.equal(old.ready.length, 0);
  assert.equal(next.ready.length, 1);
  assert.equal(next.tokenFor(2), OTHER_TOKEN);
  assert.equal(h.count('generate'), 2);
  assert.equal(h.count('discard'), 1);
  assert.ok(h.calls.findIndex(call => call.name === 'discard') < h.calls.findLastIndex(call => call.name === 'prepare'));
  assert.equal(await next.cleanup(), true);
});

test('cancelled finish cannot publish an otherwise valid attested bitmap', async () => {
  const finalization = deferred();
  const h = harness({finish: () => finalization.promise});
  const app = h.mount();
  await h.enter('finish');
  const disposal = app.cleanup();
  await flush();
  assert.equal(h.count('discard'), 0);
  finalization.resolve(finished(TOKEN));
  assert.equal(await disposal, true);
  assert.equal(app.ready.length, 0);
  assert.equal(h.count('discard'), 1);
});

test('ready preview cleanup is also serialized before a replacement activation', async () => {
  const discarded = deferred();
  let discards = 0;
  const h = harness({discard: token => ++discards === 1 ? discarded.promise : {token, discarded: true}});
  const old = h.mount();
  await flush();
  assert.equal(old.state.status, 'ready');
  const disposal = old.cleanup();
  const next = h.mount();
  await h.enter('discard');
  await flush();
  assert.equal(h.count('generate'), 1);
  assert.equal(next.state.status, 'loading');
  discarded.resolve({token: TOKEN, discarded: true});
  assert.equal(await disposal, true);
  await flush();
  assert.equal(next.state.status, 'ready');
  assert.equal(next.tokenFor(2), OTHER_TOKEN);
  assert.equal(await next.cleanup(), true);
});

test('false previous cleanup blocks every new plugin/native/SDK call', async () => {
  const h = harness();
  h.sharedGlobal.RTL_READER_INK_CLEANUP = Promise.resolve(false);
  const app = h.mount();
  await flush();
  assert.deepEqual(app.state, {status: 'error', reason: 'cleanup_failed'});
  assert.equal(h.calls.length, 0);
  assert.equal(app.tokenFor(2), null);
  assert.equal(await app.cleanup(), false, 'Blocked effect cannot clear previous cleanup failure');
});

test('rejected previous cleanup is caught, with no new SDK/native request', async () => {
  const h = harness();
  h.sharedGlobal.RTL_READER_INK_CLEANUP = Promise.reject(Error('prior cleanup rejected'));
  const app = h.mount();
  await flush();
  assert.deepEqual(app.state, {status: 'error', reason: 'prior cleanup rejected'});
  assert.equal(h.calls.length, 0);
  assert.equal(app.tokenFor(2), null);
  assert.equal(await app.cleanup(), false, 'Rejected cleanup remains failed after no-controller cleanup');
});

test('false cleanup authority remains latched across second and third remounts, including invisible mounts', async () => {
  const h = harness();
  h.sharedGlobal.RTL_READER_INK_CLEANUP = Promise.resolve(false);
  for (const visible of [true, false, true, true]) {
    const app = h.mount({visible});
    await flush();
    assert.equal(app.tokenFor(2), null);
    assert.equal(h.calls.length, 0, 'A failed cleanup chain must never query a new native/SDK request');
    if (visible) assert.deepEqual(app.state, {status: 'error', reason: 'cleanup_failed'});
    else assert.deepEqual(app.state, {status: 'unavailable'});
    assert.equal(await app.cleanup(), false);
  }
});

test('rejected cleanup authority remains latched across second and third remounts, including invisible mounts', async () => {
  const h = harness();
  h.sharedGlobal.RTL_READER_INK_CLEANUP = Promise.reject(Error('prior cleanup rejected'));
  const initial = h.mount();
  await flush();
  assert.deepEqual(initial.state, {status: 'error', reason: 'prior cleanup rejected'});
  assert.equal(await initial.cleanup(), false);
  for (const visible of [false, true, true]) {
    const app = h.mount({visible});
    await flush();
    assert.equal(app.tokenFor(2), null);
    assert.equal(h.calls.length, 0);
    assert.equal(await app.cleanup(), false);
  }
});

test('failed owned cleanup blocks remount even though old component is gone', async () => {
  let fail = true;
  const h = harness({discard: async token => {
    if (fail) throw Error('cannot remove owned output');
    return {token, discarded: true};
  }});
  const old = h.mount();
  await flush();
  assert.equal(old.state.status, 'ready');
  assert.equal(await old.cleanup(), false);
  const next = h.mount();
  await flush();
  assert.deepEqual(next.state, {status: 'error', reason: 'cleanup_failed'});
  assert.equal(h.count('generate'), 1);
  assert.equal(next.tokenFor(2), null);
  // Recover only in this isolated host harness so failed ownership is not
  // leaked across tests. Production recovery is intentionally not fabricated.
  fail = false;
  assert.equal((await h.controllers[0].release()).status, 'released');
  await next.cleanup();
});

test('current document replacement while SDK is pending suppresses wrong-document ink', async () => {
  const generation = deferred();
  const h = harness({generate: () => generation.promise});
  const app = h.mount();
  await h.enter('generate');
  h.changeFile('/storage/emulated/0/Document/replaced.pdf');
  generation.resolve({success: true, result: true});
  await flush();
  assert.equal(app.ready.length, 0);
  assert.equal(app.state.reason, 'context_changed');
  assert.equal(app.tokenFor(2), null);
  assert.equal(h.count('discard'), 1);
  assert.equal(await app.cleanup(), true);
});
test('visible page change during pending SDK does not attach PAGE3 ink to another page', async () => {
  const generation = deferred();
  const h = harness({generate: () => generation.promise});
  const app = h.mount();
  await h.enter('generate');
  h.changeVisibleContext({filePath: FILE, pageIndex: 3, totalPages: 8});
  generation.resolve({success: true, result: true});
  await flush();
  assert.equal(app.ready.length, 0);
  assert.equal(app.tokenFor(3), null);
  assert.equal(h.count('discard'), 1);
  assert.equal(await app.cleanup(), true);
});

test('away-and-back remount cannot revive pending old PAGE3 publication', async () => {
  const generation = deferred();
  let generations = 0;
  const h = harness({generate: () => ++generations === 1 ? generation.promise : {success: true, result: true}});
  const old = h.mount();
  await h.enter('generate');
  const oldDisposal = old.cleanup();
  h.changeVisibleContext(null);
  const away = h.mount({visible: false});
  const awayDisposal = away.cleanup();
  h.changeVisibleContext({filePath: FILE, pageIndex: 2, totalPages: 8});
  const returned = h.mount();
  generation.resolve({success: true, result: true});
  assert.equal(await oldDisposal, true);
  assert.equal(await awayDisposal, true);
  await flush();
  assert.equal(old.ready.length, 0);
  assert.equal(returned.state.status, 'ready');
  assert.equal(returned.tokenFor(2), OTHER_TOKEN);
  assert.equal(await returned.cleanup(), true);
});

test('Close/Edit transition fence prevents late publication without early SDK cleanup', async () => {
  for (const stage of ['prepare', 'generate', 'finish']) {
    const pending = deferred();
    const h = harness({[stage]: () => pending.promise});
    const app = h.mount();
    await h.enter(stage);
    h.lockTransition();
    assert.equal(h.count('discard'), 0);
    pending.resolve(stage === 'prepare' ? prepared(TOKEN) : stage === 'finish' ? finished(TOKEN) : {success: true, result: true});
    await flush();
    assert.equal(app.ready.length, 0, `${stage} result must not publish during Close/Edit`);
    assert.equal(app.updates.length, 1, 'Transition leaves no component-state publication');
    assert.equal(h.count('discard'), 1);
    assert.equal(await app.cleanup(), true);
  }
});

test('SDK rejection is contained to saved ink and normal effect cleanup completes', async () => {
  const h = harness({generate: async () => { throw Error('renderer unavailable'); }});
  const app = h.mount();
  await flush();
  assert.equal(app.state.status, 'error');
  assert.equal(app.state.reason, 'generate_failed');
  assert.equal(app.tokenFor(2), null);
  assert.equal(h.count('discard'), 1);
  assert.equal(await app.cleanup(), true);
});
