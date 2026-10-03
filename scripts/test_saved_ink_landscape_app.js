'use strict';
// Execute actual production eligibility, spread mapping, effect and accessor.
// The real savedInk controller owns cancellation, SDK settlement and cleanup.
// Only native/SDK responses, hook commits and Dimensions events are controlled.
// No copied lifecycle/eligibility model, device, filesystem mutation or timers.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const CONTROLLER = path.join(ROOT, 'overlay', 'savedInk.js');
const SOURCE = fs.readFileSync(path.join(ROOT, 'overlay', 'App.js'), 'utf8').replace(/\r\n/g, '\n');
const FILE = '/storage/emulated/0/Document/RTL_INK_GEOMETRY_T008_20261002.pdf';
const DIR = '/data/user/0/com.ratta.supernote.pluginhost/files/plugins/snrtl20260726001';
const TOKEN = 'f3d09692-3a12-48cb-823b-62041968c761';
const NEXT_TOKEN = 'e3d09692-3a12-48cb-823b-62041968c761';
const SHA = 'bd0fd00b4879cedb1b768a19deb2901a6d50dc7373decc8ef60e445613d83e64';
const PROFILE_ID = 't008-page1-stock-portrait-fit-v1';
const PAGE2_PROFILE_ID = 't008-page2-stock-portrait-fit-v1';

function once(marker) {
  const first = SOURCE.indexOf(marker);
  assert.notEqual(first, -1, `Actual App source marker missing: ${marker}`);
  assert.equal(SOURCE.indexOf(marker, first + marker.length), -1, `Ambiguous App marker: ${marker}`);
  return first;
}

const windowCode = SOURCE.slice(once('  const window = useWindowDimensions();'), once('  const [documentContext, setDocumentContext]'));
const modeCode = SOURCE.slice(once('  const effectiveMode ='), once('  const [nativeSpreadEnabled, setNativeSpreadEnabled]'));
const spreadCode = SOURCE.slice(once('function clampPage('), once('function viewModeLabel('));
const gateStart = once('  const savedInkProfile = selectSavedInkProfile(');
const effectStart = once('  useEffect(() => {\n    let cancelled = false;');
const effectEndMarker = '  }, [savedInkVisible, documentContext?.filePath, savedInkPresentationKey]);';
const effectEnd = once(effectEndMarker) + effectEndMarker.length;
const gateCode = SOURCE.slice(gateStart, effectStart);
const effectCode = SOURCE.slice(effectStart, effectEnd);
const pageSetterCode = SOURCE.slice(once('  const setPageIndex = value => {'), once('  const displayRef ='));
const invalidateCode = SOURCE.slice(once('  const invalidateSavedInkPresentation = () => {'), once('  const quiesceSavedInk ='));
const jumpCode = SOURCE.slice(once('  const submitJump = () => {'), once('  const footerLabel ='));
const goByCode = SOURCE.slice(once('  const goBy = delta => {'), once('  const pageStep ='));
const PATCH_SOURCE = fs.readFileSync(path.join(ROOT, 'scripts', 'patch_direct_view.py'), 'utf8').replace(/\r\n/g, '\n');
const generatedJumpCode = PATCH_SOURCE.match(/new_submit_jump = r'''([\s\S]*?)'''/)[1];

function execute(scope, code) {
  const names = Object.keys(scope);
  return new Function(...names, code)(...names.map(name => scope[name]));
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}

async function flush(count = 220) {
  for (let tick = 0; tick < count; tick += 1) await Promise.resolve();
}

const png = token => `${DIR}/saved-ink-cache/${token}/ink.png`;
const prepared = (token, pageIndex, profileId) => ({
  token, filePath: FILE, pageIndex, pageCount: 2, sourceSha256: SHA,
  profileId, geometryId: profileId, width: 1404, height: 1872,
  sourceVerified: true, pngPath: png(token),
});
const finished = evidence => ({
  ...evidence, sourceUnchanged: true, markUnchanged: true, savedInkToken: evidence.token,
  decoded: true, sha256: 'a'.repeat(64), byteLength: 1000, alphaMin: 0, alphaMax: 255,
});

function harness(hooks = {}, options = {}) {
  delete require.cache[require.resolve(CONTROLLER)];
  const {createSavedInkController, selectSavedInkProfile} = require(CONTROLLER);
  const calls = [];
  const controllers = [];
  const outcomes = [];
  const shared = {};
  const listeners = new Set();
  let window = options.window || {width: 1872, height: 1404};
  let liveFile = FILE;
  let locked = false;
  const issued = new Map();
  function preparePage(profileId, filePath, pageIndex, width, height, directory) {
    assert.equal(filePath, FILE);
    assert.deepEqual([width, height, directory], [1404, 1872, DIR]);
    assert.equal(profileId, [PROFILE_ID, PAGE2_PROFILE_ID][pageIndex], 'Independent per-source-page identity');
    const token = issued.size === 0 ? TOKEN : issued.size === 1 ? NEXT_TOKEN
      : `a3d09692-3a12-48cb-823b-${String(issued.size).padStart(12, '0')}`;
    const evidence = prepared(token, pageIndex, profileId);
    issued.set(token, evidence);
    return evidence;
  }

  function count(name) { return calls.filter(call => call.name === name).length; }
  function invoke(name, fallback, args) {
    const call = {name, args, settled: false};
    calls.push(call);
    return Promise.resolve().then(() => (hooks[name] || fallback)(...args)).then(value => {
      call.settled = true;
      return value;
    });
  }
  const native = {
    prepare: (...args) => invoke('prepare', preparePage, args),
    prepareSibling: (...args) => invoke('prepareSibling', (parent, ...pageArgs) => {
      assert.ok(issued.has(parent), 'Sibling requires a preceding exact parent');
      return preparePage(...pageArgs);
    }, args),
    validateBatch: (...args) => invoke('validateBatch', (firstToken, secondToken) =>
      ({firstToken, secondToken, batchUnchanged: true}), args),
    finish: (...args) => invoke('finish', token => finished(issued.get(token)), args),
    discard: (...args) => invoke('discard', token => ({token, discarded: true}), args),
  };

  function mount(view = {}, commit = true) {
    const refs = {
      savedInkContextRef: {current: null}, savedInkLifecycleRef: {current: null},
      savedInkPresentationEpochRef: {current: 0}, savedInkPresentationKeyRef: {current: null},
      mountedRef: {current: true},
      pageIndexRef: {current: view.pageIndex ?? 0}, totalPagesRef: {current: view.totalPages ?? 2},
      filePathRef: {current: view.filePath ?? FILE}, effectiveModeRef: {current: null},
      directionRef: {current: view.direction ?? 'rtl'}, coverSeparateRef: {current: view.coverSeparate ?? false},
      interactionTimingRef: {current: null}, lastNavigationDeltaRef: {current: 0},
    };
    const updates = [];
    const instance = {
      view: {filePath: FILE, totalPages: 2, pageIndex: 0, viewMode: 'auto', spreadSizing: 'fit',
        direction: 'rtl', coverSeparate: false, preferencesReady: true, editBusy: false, ...view},
      state: {status: 'unavailable'}, epoch: 0, refs, updates, effectDeps: null, cleanup: null,
      render(commitEffects = true) {
        const scope = {
          ...refs, selectSavedInkProfile, useWindowDimensions: () => window,
          ...instance.view, documentContext: {filePath: instance.view.filePath},
          savedInk: instance.state, savedInkPresentationEpoch: instance.epoch,
          readerTransitionLocked: () => locked,
          setSavedInk(value) { instance.state = value; updates.push(value); },
          setSavedInkPresentationEpoch(value) { instance.epoch = value; },
          setPageIndexRaw(value) { instance.view.pageIndex = value; },
          console: {log() {}, warn() {}}, Keyboard: {dismiss() {}}, setJumpOpen() {},
        };
        const locals = execute(scope, `${spreadCode}\n${windowCode}\n${modeCode}\n${gateCode}\n` +
          'return {savedInkVisible, savedInkProfile, savedInkPresentationKey, savedInkTokenFor, effectiveMode, getVisualSpread};');
        Object.assign(refs.pageIndexRef, {current: instance.view.pageIndex});
        Object.assign(refs.effectiveModeRef, {current: locals.effectiveMode});
        Object.assign(refs.coverSeparateRef, {current: instance.view.coverSeparate});
        Object.assign(refs.directionRef, {current: instance.view.direction});
        Object.assign(refs.totalPagesRef, {current: instance.view.totalPages});
        Object.assign(refs.filePathRef, {current: instance.view.filePath});
        instance.setPageIndex = execute(scope,
          `${spreadCode}\n${pageSetterCode}\n${invalidateCode}\nreturn setPageIndex;`);
        instance.transitionScope = scope;
        instance.locals = locals;
        const deps = [locals.savedInkVisible, instance.view.filePath, locals.savedInkPresentationKey];
        const changed = !instance.effectDeps || deps.some((value, index) => !Object.is(value, instance.effectDeps[index]));
        if (commitEffects && changed) {
          instance.cleanup?.(); // React cleans prior passive effect before replacement.
          const effectScope = {
            ...scope, ...locals, globalThis: shared, SavedInkModule: native,
            setSavedInk(value) { instance.state = value; updates.push(value); },
            setSavedInkPresentationEpoch(value) { instance.epoch = value; },
            Dimensions: {
              addEventListener(name, callback) {
                assert.equal(name, 'change');
                listeners.add(callback);
                return {remove() { listeners.delete(callback); }};
              },
            },
            PluginManager: {getPluginDirPath: (...args) => invoke('directory', () => DIR, args)},
            PluginCommAPI: {getCurrentFilePath: (...args) => invoke('file', () => ({success: true, result: liveFile}), args)},
            PluginFileAPI: {
              getPageSize: (...args) => invoke('size', () => ({success: true, result: {width: 1404, height: 1872}}), args),
              generateMarkThumbnails: (...args) => invoke('generate', () => ({success: true, result: true}), args),
            },
            async requireResult(promise, label) {
              const response = await promise;
              if (response?.success !== true) throw Error(`${label} unavailable`);
              return response.result;
            },
            createSavedInkController(deps) {
              const actual = createSavedInkController(deps);
              controllers.push(actual);
              const observe = method => context => actual[method](context).then(value => {
                  outcomes.push(value);
                  if (hooks.onControllerResult) hooks.onControllerResult(value, api, instance);
                  return value;
                });
              return {...actual, run: observe('run'), runBatch: observe('runBatch')};
            },
            console: {log() {}, warn() {}},
            useEffect(effect, observed) {
              assert.deepEqual(observed, deps, 'Actual effect uses the same eligibility/file/presentation key');
              instance.cleanup = effect();
            },
          };
          execute(effectScope, effectCode);
          instance.effectDeps = deps;
        }
        return locals;
      },
      tokenFor(page) { return instance.render(false).savedInkTokenFor(page); },
      update(patch, commitEffects = true) { Object.assign(instance.view, patch); return instance.render(commitEffects); },
      acceptPage(value, commitEffects = true, renderNow = true) {
        instance.setPageIndex(value);
        return renderNow ? instance.render(commitEffects) : null;
      },
      acceptJump(pageNumber, renderNow = false, generated = false) {
        execute({...instance.transitionScope, jumpText: String(pageNumber)},
          `${spreadCode}\n${pageSetterCode}\n${invalidateCode}\n${generated ? generatedJumpCode : jumpCode}\nsubmitJump();`);
        return renderNow ? instance.render() : null;
      },
      acceptGoBy(delta, renderNow = false) {
        execute({...instance.transitionScope, delta},
          `${spreadCode}\n${pageSetterCode}\n${invalidateCode}\n${goByCode}\ngoBy(delta);`);
        return renderNow ? instance.render() : null;
      },
      quiesce() { return refs.savedInkLifecycleRef.current.quiesce(); },
      unmount() { refs.mountedRef.current = false; instance.cleanup?.(); return shared.RTL_READER_INK_CLEANUP; },
      get ready() { return updates.filter(value => value.status === 'ready'); },
    };
    instance.render(commit);
    return instance;
  }
  const api = {
    mount, calls, controllers, outcomes, shared, count,
    rotate(value) { window = {...value}; for (const callback of [...listeners]) callback({window}); },
    lock(value = true) { locked = value; },
    changeFile(value) { liveFile = value; },
    async enter(name, expected = 1) {
      for (let tick = 0; tick < 500 && count(name) < expected; tick += 1) await Promise.resolve();
      assert.equal(count(name), expected, `Expected actual ${name} call ${expected}`);
    },
    async dispose(instance) { assert.equal(await instance.unmount(), true); },
  };
  return api;
}

test('actual T008 eligibility permits only portrait Single or landscape Single/Spread Fit', () => {
  for (const [window, view, expected] of [
    [{width: 1404, height: 1872}, {viewMode: 'single'}, true],
    [{width: 1404, height: 1872}, {viewMode: 'auto'}, true],
    [{width: 1404, height: 1872}, {viewMode: 'spread'}, false],
    [{width: 1872, height: 1404}, {viewMode: 'single'}, true],
    [{width: 1872, height: 1404}, {viewMode: 'auto'}, true],
    [{width: 1872, height: 1404}, {viewMode: 'spread'}, true],
    [{width: 1404, height: 1404}, {viewMode: 'single'}, false],
    [{width: 1872, height: 1404}, {viewMode: 'other'}, false],
    [{width: 1872, height: 1404}, {spreadSizing: 'native_fill'}, false],
    [{width: 1872, height: 1404}, {viewMode: 'single', pageIndex: 1}, true],
    [{width: 1872, height: 1404}, {filePath: '/Document/personal.pdf'}, false],
    [{width: 1872, height: 1404}, {filePath: `${FILE}.copy`}, false],
    [{width: 1872, height: 1404}, {totalPages: 8}, false],
    [{width: 1872, height: 1404}, {totalPages: '2'}, false],
    [{width: 1872, height: 1404}, {preferencesReady: false}, false],
  ]) {
    const h = harness({}, {window});
    const app = h.mount(view, false);
    assert.equal(app.locals.savedInkVisible, expected, JSON.stringify({window, view}));
    assert.deepEqual(app.refs.savedInkContextRef.current?.pageIndices ?? null,
      expected ? (app.locals.effectiveMode === 'single' ? [view.pageIndex ?? 0] : [0, 1]) : null);
    assert.equal(h.calls.length, 0, 'Eligibility inspection itself never extracts ink');
  }
});

test('actual legacy T004 PAGE3 eligibility keeps Single/Spread and Fit/native-fill behavior without a presentation witness', () => {
  const filePath = '/storage/emulated/0/Document/RTL_RAPID_TOOLS_T004_20261001.pdf';
  for (const window of [{width: 1404, height: 1872}, {width: 1872, height: 1404}]) {
    for (const viewMode of ['single', 'spread']) {
      for (const spreadSizing of ['fit', 'native_fill']) {
        const h = harness({}, {window});
        const app = h.mount({filePath, totalPages: 8, pageIndex: 2, viewMode, spreadSizing}, false);
        assert.equal(app.locals.savedInkVisible, true, JSON.stringify({window, viewMode, spreadSizing}));
        assert.equal(app.refs.savedInkContextRef.current.pageIndex, 2);
        assert.equal(app.locals.savedInkPresentationKey, null, 'T008 cancellation witness does not broaden legacy geometry authority');
        assert.equal(h.calls.length, 0);
      }
    }
  }
});

test('shared spreads keep both exact source-page identities across anchors, RTL/LTR sides and cover parity', async () => {
  const h = harness();
  const app = h.mount();
  await flush();
  assert.equal(app.tokenFor(0), TOKEN);
  assert.equal(app.tokenFor(1), NEXT_TOKEN);
  assert.deepEqual(app.locals.getVisualSpread(0, false, 2, 'rtl'), {left: 1, right: 0});
  app.acceptPage(1);
  await flush();
  assert.deepEqual(app.refs.savedInkContextRef.current.pageIndices, [0, 1], 'Same spread keeps both source pages');
  assert.equal(app.tokenFor(0), TOKEN);
  assert.equal(app.tokenFor(1), NEXT_TOKEN);
  assert.equal(h.count('prepare'), 1, 'Same shared spread retains the page-bound batch');
  assert.equal(h.count('prepareSibling'), 1);
  app.update({direction: 'ltr'});
  assert.deepEqual(app.locals.getVisualSpread(1, false, 2, 'ltr'), {left: 0, right: 1});
  assert.equal(app.tokenFor(0), TOKEN);
  assert.equal(app.tokenFor(1), NEXT_TOKEN);
  app.update({pageIndex: 0, coverSeparate: true, direction: 'rtl'});
  assert.deepEqual(app.locals.getVisualSpread(0, true, 2, 'rtl'), {left: null, right: 0});
  assert.equal(app.tokenFor(0), null, 'Cover parity changes the exact batch before passive cleanup');
  await flush();
  const coverToken = app.tokenFor(0);
  assert.ok(coverToken && ![TOKEN, NEXT_TOKEN].includes(coverToken));
  assert.equal(app.tokenFor(1), null);
  app.update({pageIndex: 1});
  assert.equal(app.locals.savedInkVisible, true, 'Separate-cover PAGE2 gets its own source-page batch');
  assert.equal(app.tokenFor(0), null);
  assert.equal(app.tokenFor(1), null);
  await flush();
  assert.ok(app.tokenFor(1) && app.tokenFor(1) !== coverToken);
  assert.equal(app.tokenFor(0), null);
  await h.dispose(app);
  assert.equal(h.count('discard'), 4, 'Both initial handles plus each separate-cover batch drain');
});

test('actual landscape effect keeps canonical output and exact real pre/post 1404x1872 witnesses', async () => {
  const h = harness();
  const app = h.mount();
  await flush();
  assert.equal(app.state.status, 'ready');
  assert.equal(app.tokenFor(0), TOKEN);
  assert.deepEqual(h.calls.filter(call => call.name === 'size').map(call => call.args),
    [[FILE, 0], [FILE, 0], [FILE, 1], [FILE, 1]]);
  assert.deepEqual(h.calls.find(call => call.name === 'prepare').args, [PROFILE_ID, FILE, 0, 1404, 1872, DIR]);
  assert.deepEqual(h.calls.find(call => call.name === 'generate').args, [FILE, 0, png(TOKEN), {width: 1404, height: 1872}]);
  assert.deepEqual(h.calls.find(call => call.name === 'prepareSibling').args,
    [TOKEN, PAGE2_PROFILE_ID, FILE, 1, 1404, 1872, DIR]);
  assert.deepEqual(h.calls.filter(call => call.name === 'generate')[1].args,
    [FILE, 1, png(NEXT_TOKEN), {width: 1404, height: 1872}]);
  assert.deepEqual(h.calls.find(call => call.name === 'validateBatch').args, [TOKEN, NEXT_TOKEN]);
  assert.equal(app.tokenFor(1), NEXT_TOKEN);
  assert.equal(app.state.presentationKey, app.locals.savedInkPresentationKey);
  await h.dispose(app);
});

test('actual Single PAGE1->PAGE2->PAGE1 replaces exact page authority before effects, never relabeling a token', async () => {
  const h = harness({}, {window: {width: 1404, height: 1872}});
  const app = h.mount({viewMode: 'single'});
  await flush();
  const first = app.tokenFor(0);
  const cached = app.render(false).savedInkTokenFor;
  app.acceptPage(1, false);
  assert.equal(cached(0), null, 'Old accessor loses authority during render, not just after cleanup');
  assert.equal(app.tokenFor(1), null, 'No PAGE1 token can be relabeled PAGE2');
  app.render();
  await flush();
  assert.equal(app.tokenFor(0), null);
  assert.equal(app.tokenFor(1), NEXT_TOKEN);
  app.acceptPage(0);
  assert.equal(app.tokenFor(0), null);
  await flush();
  assert.ok(app.tokenFor(0) && app.tokenFor(0) !== first);
  assert.equal(app.tokenFor(1), null);
  assert.deepEqual(h.calls.filter(call => call.name === 'generate').map(call => call.args[1]), [0, 1, 0]);
  await h.dispose(app);
  assert.equal(h.count('discard'), 3);
});

test('accepted PAGE1->PAGE2->PAGE1 before ANY render cannot revive the old SDK request', async () => {
  const generation = deferred();
  let generations = 0;
  const h = harness({generate: () => ++generations === 1 ? generation.promise : {success: true, result: true}});
  const app = h.mount({viewMode: 'single'});
  await h.enter('generate');
  const cached = app.render(false).savedInkTokenFor;
  app.acceptPage(1, false, false);
  app.acceptPage(0, false, false);
  assert.equal(app.epoch, 2, 'Both accepted changes advance a non-reusable fence, even with no intermediate render');
  assert.equal(cached(0), null);
  assert.equal(h.count('discard'), 0, 'Cancellation does not remove a still-writing SDK output');
  app.render();
  await flush();
  assert.equal(h.count('prepare'), 1);
  generation.resolve({success: true, result: true});
  await flush();
  assert.equal(h.outcomes[0].reason, 'cancelled');
  assert.equal(h.count('prepare'), 2);
  assert.equal(h.count('discard'), 1);
  assert.equal(app.tokenFor(0), NEXT_TOKEN);
  assert.equal(app.ready.length, 1, 'Only the fresh post-ABA generation is published');
  await h.dispose(app);
});

test('accepted anchor changes within the same spread retain both page handles, but locked navigation is inert', async () => {
  const h = harness();
  const app = h.mount();
  await flush();
  app.acceptPage(1);
  app.acceptPage(0);
  assert.equal(app.epoch, 0);
  assert.equal(h.count('prepare'), 1);
  assert.equal(h.count('prepareSibling'), 1);
  assert.equal(app.tokenFor(0), TOKEN);
  assert.equal(app.tokenFor(1), NEXT_TOKEN);
  h.lock();
  app.acceptPage(1);
  assert.equal(app.view.pageIndex, 0, 'Transition guard stays ahead of page state/ink invalidation');
  assert.equal(app.epoch, 0);
  await h.dispose(app);
});

test('actual Jump and Next/Previous routes cannot bypass the pre-render page-away/back epoch', async () => {
  for (const route of ['jump', 'generatedJump', 'goBy']) {
    const generation = deferred();
    let generations = 0;
    const h = harness({generate: () => ++generations === 1 ? generation.promise : {success: true, result: true}});
    const app = h.mount({viewMode: 'single'});
    await h.enter('generate');
    if (route !== 'goBy') { app.acceptJump(2, false, route === 'generatedJump'); app.acceptJump(1, false, route === 'generatedJump'); }
    else { app.acceptGoBy(1); app.acceptGoBy(-1); }
    assert.equal(app.view.pageIndex, 0);
    assert.equal(app.epoch, 2, `${route} invalidates both accepted transitions before rendering`);
    assert.equal(app.refs.savedInkContextRef.current, null);
    assert.equal(h.count('discard'), 0);
    app.render();
    generation.resolve({success: true, result: true});
    await flush();
    assert.equal(h.outcomes[0].reason, 'cancelled');
    assert.equal(h.count('prepare'), 2);
    assert.equal(app.ready.length, 1);
    assert.equal(app.tokenFor(0), NEXT_TOKEN);
    h.lock();
    if (route !== 'goBy') app.acceptJump(2, false, route === 'generatedJump');
    else app.acceptGoBy(1);
    assert.equal(app.view.pageIndex, 0);
    assert.equal(app.epoch, 2, 'Locked routes neither change the page nor invalidate its owner');
    await h.dispose(app);
  }
});

test('actual spread never publishes a first-page success if second-page generation or end validation fails', async () => {
  for (const stage of ['generate', 'validateBatch']) {
    let generations = 0;
    const h = harness(stage === 'generate' ? {generate: () => ++generations === 2
      ? {success: false, error: {code: 500}} : {success: true, result: true}}
      : {validateBatch: () => { throw Error('mark changed'); }});
    const app = h.mount();
    await flush();
    assert.equal(app.state.status, 'error');
    assert.equal(app.ready.length, 0);
    assert.equal(app.tokenFor(0), null);
    assert.equal(app.tokenFor(1), null);
    assert.equal(h.count('prepare'), 1);
    assert.equal(h.count('prepareSibling'), 1);
    assert.deepEqual(h.calls.filter(call => call.name === 'discard').map(call => call.args[0]).sort(),
      [TOKEN, NEXT_TOKEN].sort());
    await h.dispose(app);
  }
});

test('actual two-page Close/Edit during second SDK waits settlement and both native drains', async () => {
  const generation = deferred();
  const firstDrain = deferred();
  const secondDrain = deferred();
  let generations = 0;
  const h = harness({
    generate: () => ++generations === 2 ? generation.promise : {success: true, result: true},
    discard: token => token === NEXT_TOKEN ? secondDrain.promise : firstDrain.promise,
  });
  const app = h.mount();
  await h.enter('generate', 2);
  assert.equal(app.ready.length, 0, 'First retained page is not a complete spread');
  h.lock();
  const cleanup = app.quiesce();
  let done = false;
  cleanup.then(() => { done = true; });
  await flush();
  assert.equal(done, false);
  assert.equal(h.count('discard'), 0, 'SDK owns the second output until real settlement');
  generation.resolve({success: true, result: true});
  await h.enter('discard');
  assert.equal(h.calls.find(call => call.name === 'discard').args[0], NEXT_TOKEN);
  secondDrain.resolve({token: NEXT_TOKEN, discarded: true});
  await h.enter('discard', 2);
  assert.equal(done, false, 'First page still holds the whole transition until its drain');
  firstDrain.resolve({token: TOKEN, discarded: true});
  assert.equal(await cleanup, true);
  assert.equal(app.ready.length, 0);
  assert.equal(app.tokenFor(0), null);
  assert.equal(app.tokenFor(1), null);
  assert.equal(h.count('prepare'), 1);
  assert.equal(h.count('prepareSibling'), 1);
  await h.dispose(app);
});

test('production landscape still rejects a 1872x1404 native size before allocation and after extraction', async () => {
  for (const failAt of [1, 2]) {
    let reads = 0;
    const h = harness({size: () => ({success: true, result: ++reads === failAt
      ? {width: 1872, height: 1404} : {width: 1404, height: 1872}})});
    const app = h.mount();
    await flush();
    assert.equal(app.state.reason, 'canvas_mismatch');
    assert.equal(app.tokenFor(0), null);
    assert.equal(h.count('prepare'), failAt === 1 ? 0 : 1);
    assert.equal(h.count('finish'), 0);
    assert.equal(h.count('discard'), failAt === 1 ? 0 : 1);
    await h.dispose(app);
  }
});

test('rotation ABA during actual SDK waits for old writer and native drain before replacement', async () => {
  const generation = deferred();
  const drain = deferred();
  let generations = 0;
  let discards = 0;
  const h = harness({
    generate: () => ++generations === 1 ? generation.promise : {success: true, result: true},
    discard: token => ++discards === 1 ? drain.promise : {token, discarded: true},
  });
  const app = h.mount({viewMode: 'single'});
  await h.enter('generate');
  h.rotate({width: 1404, height: 1872});
  h.rotate({width: 1872, height: 1404}); // No intermediate render: epoch covers batched ABA.
  assert.equal(app.epoch, 2);
  assert.equal(app.tokenFor(0), null);
  app.render();
  await flush();
  assert.equal(h.count('prepare'), 1);
  assert.equal(h.count('discard'), 0, 'Unresolved SDK still owns its output');
  generation.resolve({success: true, result: true});
  await h.enter('discard');
  await flush();
  assert.equal(h.outcomes.length, 0, 'Cancelled controller result also waits for its native cleanup acknowledgment');
  assert.equal(app.ready.length, 0);
  assert.equal(h.count('prepare'), 1, 'Settled SDK alone does not release native lease ownership');
  drain.resolve({token: TOKEN, discarded: true});
  await flush();
  assert.equal(h.outcomes[0].reason, 'cancelled');
  assert.equal(h.count('prepare'), 2);
  assert.equal(h.count('generate'), 2);
  assert.equal(app.tokenFor(0), NEXT_TOKEN);
  assert.equal(app.ready.length, 1);
  await h.dispose(app);
});

test('completed ready token is hidden synchronously by rotation, including a cached accessor', async () => {
  const h = harness();
  const app = h.mount({viewMode: 'single'});
  await flush();
  const cached = app.render(false).savedInkTokenFor;
  assert.equal(cached(0), TOKEN);
  h.rotate({width: 1404, height: 1872});
  assert.equal(cached(0), null, 'Event invalidation does not wait for a React commit');
  assert.equal(app.tokenFor(0), null);
  app.render();
  await flush();
  assert.equal(app.tokenFor(0), NEXT_TOKEN);
  await h.dispose(app);
});

test('eligible Single-to-Spread change hides old token before passive cleanup and regenerates after drain', async () => {
  const drain = deferred();
  let discards = 0;
  const h = harness({discard: token => ++discards === 1 ? drain.promise : {token, discarded: true}});
  const app = h.mount({viewMode: 'single'});
  await flush();
  const cached = app.render(false).savedInkTokenFor;
  app.update({viewMode: 'spread'}, false);
  assert.equal(cached(0), null, 'Presentation ref fences the render-to-passive-effect interval');
  assert.equal(app.tokenFor(0), null);
  app.render();
  await h.enter('discard');
  assert.equal(h.count('prepare'), 1);
  drain.resolve({token: TOKEN, discarded: true});
  await flush();
  assert.equal(app.tokenFor(0), NEXT_TOKEN);
  await h.dispose(app);
});

test('actual resolved success rotated before App continuation is never published as old ready ink', async () => {
  const drain = deferred();
  let discards = 0;
  let results = 0;
  const h = harness({
    discard: token => ++discards === 1 ? drain.promise : {token, discarded: true},
    onControllerResult(value, environment) {
      if (++results === 1) {
        assert.equal(value.status, 'ready', 'Real controller completed checked bitmap publication');
        environment.rotate({width: 1404, height: 1872});
      }
    },
  });
  const app = h.mount({viewMode: 'single'});
  await h.enter('discard');
  assert.equal(app.ready.length, 0);
  assert.equal(app.tokenFor(0), null);
  app.render();
  await flush();
  assert.equal(h.count('prepare'), 1);
  drain.resolve({token: TOKEN, discarded: true});
  await flush();
  assert.equal(app.ready.length, 1);
  assert.equal(app.tokenFor(0), NEXT_TOKEN);
  await h.dispose(app);
});

test('rotation during either actual native-size query waits for settlement and cancels its extraction', async () => {
  for (const pendingAt of [1, 2]) {
    const size = deferred();
    let reads = 0;
    const h = harness({size: () => ++reads === pendingAt ? size.promise
      : {success: true, result: {width: 1404, height: 1872}}});
    const app = h.mount({viewMode: 'single'});
    await h.enter('size', pendingAt);
    h.rotate({width: 1404, height: 1872});
    assert.equal(h.count('discard'), 0);
    const cleanup = app.unmount(); // No replacement activation is needed for this bounded case.
    size.resolve({success: true, result: {width: 1404, height: 1872}});
    assert.equal(await cleanup, true);
    assert.equal(h.outcomes[0].reason, 'cancelled');
    assert.equal(h.count('prepare'), pendingAt === 1 ? 0 : 1);
    assert.equal(h.count('finish'), 0);
    assert.equal(h.count('discard'), pendingAt === 1 ? 0 : 1);
    assert.equal(app.ready.length, 0);
  }
});

test('rotation cleanup failure blocks replacement extraction and keeps the native owner for explicit recovery', async () => {
  let fail = true;
  const h = harness({discard: token => {
    if (fail) throw Error('native drain failed');
    return {token, discarded: true};
  }});
  const app = h.mount({viewMode: 'single'});
  await flush();
  h.rotate({width: 1404, height: 1872});
  app.render();
  await flush();
  assert.equal(app.state.reason, 'cleanup_failed');
  assert.equal(app.tokenFor(0), null);
  assert.equal(h.shared.RTL_READER_INK_CLEANUP_BLOCKED, true);
  assert.equal(h.count('prepare'), 1);
  assert.equal(h.count('generate'), 1);
  assert.equal(h.controllers[0].getState().retained, true);
  assert.equal(await app.unmount(), false);
  fail = false;
  assert.equal((await h.controllers[0].release()).status, 'released', 'Isolated host recovery only; no automatic production retry');
});

test('actual lifecycle quiescence fences T008 Close/Edit publication and waits for SDK plus native drain', async () => {
  const generation = deferred();
  const drain = deferred();
  const h = harness({generate: () => generation.promise, discard: () => drain.promise});
  const app = h.mount();
  await h.enter('generate');
  h.lock();
  const cleanup = app.quiesce();
  assert.equal(app.tokenFor(0), null);
  h.rotate({width: 1404, height: 1872});
  app.render();
  let done = false;
  cleanup.then(() => { done = true; });
  await flush();
  assert.equal(done, false);
  assert.equal(h.count('discard'), 0);
  assert.equal(h.count('prepare'), 1);
  generation.resolve({success: true, result: true});
  await h.enter('discard');
  assert.equal(done, false);
  assert.equal(app.ready.length, 0);
  drain.resolve({token: TOKEN, discarded: true});
  assert.equal(await cleanup, true);
  await flush();
  assert.equal(h.count('prepare'), 1, 'Locked Close/Edit never starts a rotation replacement');
  assert.equal(h.count('generate'), 1);
  await h.dispose(app);
});
