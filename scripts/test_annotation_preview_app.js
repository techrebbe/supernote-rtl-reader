'use strict';
// Execute the whole actual diagnostic App, including JSX and lifecycle hooks.
// The real annotationPreview controller owns SDK settlement and token cleanup;
// mocks provide React/RN rendering, observable events, and native/SDK responses.
// No device, network, filesystem mutation, timer, or copied state machine.
// Babel resolves normally, or set BABEL_MODULE_ROOT to an existing node_modules
// containing @babel/core, transform-react-jsx, and transform-modules-commonjs.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.resolve(__dirname, '..');
const APP = path.join(ROOT, 'probes', 'annotation-preview', 'App.js');
const CONTROLLER = require(path.join(ROOT, 'overlay', 'annotationPreview.js'));
const FILE = '/storage/emulated/0/Document/RTL_INK_GEOMETRY_T008_20261002.pdf';
const DIR = '/data/user/0/com.ratta.supernote.pluginhost/files/plugins/snrtlinkprobe20261001';
const SHA = 'bd0fd00b4879cedb1b768a19deb2901a6d50dc7373decc8ef60e445613d83e64';
const TOKEN = 'f3d09692-3a12-48cb-823b-62041968c761';
const PNG = `${DIR}/probe/${TOKEN}/ink.png`;
const GENERATE = 'Generate once';
const RETURN = 'Return to stock reader';

function babelModule(name) {
  const search = [process.env.BABEL_MODULE_ROOT, ROOT].filter(Boolean);
  try {
    return require.resolve(name, {paths: search});
  } catch (_) {
    throw new Error(`Cannot resolve ${name}; set BABEL_MODULE_ROOT to an existing Babel node_modules directory`);
  }
}

const transformed = require(babelModule('@babel/core')).transformSync(fs.readFileSync(APP, 'utf8'), {
  filename: APP, babelrc: false, configFile: false,
  plugins: [babelModule('@babel/plugin-transform-react-jsx'), babelModule('@babel/plugin-transform-modules-commonjs')],
}).code;

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}

async function flush(count = 180) {
  for (let step = 0; step < count; step += 1) await Promise.resolve();
}

function prepared() {
  return {
    token: TOKEN, filePath: FILE, pageIndex: 0, pageCount: 2, sourceSha256: SHA,
    width: 1404, height: 1872, sourceVerified: true, pngPath: PNG,
  };
}

function finished() {
  return {
    ...prepared(), sourceUnchanged: true, markUnchanged: true, decoded: true,
    sha256: 'a'.repeat(64), byteLength: 1000, alphaMin: 0, alphaMax: 255,
  };
}

function elements(tree, type) {
  if (Array.isArray(tree)) return tree.flatMap(child => elements(child, type));
  if (!tree || typeof tree !== 'object') return [];
  return [...(tree.type === type ? [tree] : []), ...elements(tree.children, type)];
}

function textOf(tree) {
  if (Array.isArray(tree)) return tree.map(textOf).join('');
  if (typeof tree === 'string' || typeof tree === 'number') return String(tree);
  return tree && typeof tree === 'object' ? textOf(tree.children) : '';
}

function harness(hooks = {}) {
  const calls = [];
  const controllers = [];
  const outcomes = [];
  const releases = [];
  const mounts = [];
  const logs = [];
  const events = new Map();
  const rotations = new Set();
  const backs = new Set();
  let window = {width: 1872, height: 1404};
  let currentMount = null;

  function count(name) { return calls.filter(call => call.name === name).length; }
  function invoke(name, fallback, args) {
    calls.push({name, args});
    return hooks[name] ? hooks[name](...args) : fallback(...args);
  }
  function listener(collection, callback) {
    collection.add(callback);
    return {remove() { collection.delete(callback); }};
  }

  const react = {
    createElement(type, props, ...children) { return {type, props: props || {}, children}; },
    useState(initial) {
      assert.ok(currentMount, 'useState runs inside actual App render');
      const instance = currentMount;
      const index = instance.cursor++;
      if (!instance.cells[index]) instance.cells[index] = {kind: 'state', value: typeof initial === 'function' ? initial() : initial};
      const cell = instance.cells[index];
      assert.equal(cell.kind, 'state');
      return [cell.value, value => {
        assert.equal(instance.mounted, true, 'removed App must not receive state updates');
        cell.value = typeof value === 'function' ? value(cell.value) : value;
      }];
    },
    useRef(initial) {
      const instance = currentMount;
      const index = instance.cursor++;
      if (!instance.cells[index]) instance.cells[index] = {kind: 'ref', value: {current: initial}};
      assert.equal(instance.cells[index].kind, 'ref');
      return instance.cells[index].value;
    },
    useEffect(effect, dependencies) {
      const instance = currentMount;
      const index = instance.cursor++;
      if (!instance.cells[index]) {
        instance.cells[index] = {kind: 'effect', dependencies};
        instance.pendingEffects.push({index, effect});
      } else {
        const cell = instance.cells[index];
        assert.equal(cell.kind, 'effect');
        assert.equal(dependencies.length, cell.dependencies.length);
        dependencies.forEach((value, offset) => assert.ok(Object.is(value, cell.dependencies[offset]), 'This App effect remains mount-scoped'));
      }
    },
  };

  const native = {
    prepare: (...args) => invoke('prepare', () => prepared(), args),
    finish: (...args) => invoke('finish', () => finished(), args),
    discard: (...args) => invoke('discard', token => ({token, discarded: true}), args),
  };
  const rn = {
    View: 'View', Text: 'Text', Image: 'Image', Pressable: 'Pressable',
    StyleSheet: {create: value => value}, NativeModules: {AnnotationPreviewModule: native},
    Dimensions: {
      get(name) { assert.equal(name, 'window'); return {...window}; },
      addEventListener(name, callback) { assert.equal(name, 'change'); return listener(rotations, callback); },
    },
    BackHandler: {
      addEventListener(name, callback) { assert.equal(name, 'hardwareBackPress'); return listener(backs, callback); },
    },
    DeviceEventEmitter: {
      addListener(name, callback) {
        if (!events.has(name)) events.set(name, new Set());
        return listener(events.get(name), callback);
      },
      emit(name) { for (const callback of [...(events.get(name) || [])]) callback(); },
    },
  };
  const sdk = {
    PluginCommAPI: {
      getCurrentFilePath: (...args) => invoke('file', () => ({success: true, result: FILE}), args),
      getCurrentPageNum: (...args) => invoke('page', () => ({success: true, result: 0}), args),
    },
    PluginDocAPI: {
      getCurrentTotalPages: (...args) => invoke('total', () => ({success: true, result: 2}), args),
    },
    PluginFileAPI: {
      getPageSize: (...args) => invoke('size', () => ({success: true, result: {width: 1872, height: 1404}}), args),
      generateMarkThumbnails: (...args) => invoke('generate', () => ({success: true, result: true}), args),
    },
    PluginManager: {
      getPluginDirPath: (...args) => invoke('directory', () => DIR, args),
      closePluginView: (...args) => invoke('close', () => undefined, args),
    },
  };
  const importedController = {
    ...CONTROLLER,
    createAnnotationPreviewProbe(deps, options) {
      const actual = CONTROLLER.createAnnotationPreviewProbe(deps, options);
      controllers.push(actual);
      return {
        ...actual,
        run(request) {
          return actual.run(request).then(value => {
            outcomes.push(value);
            // A real resolved result, before the actual App await continuation.
            // This instrumentation is not a replacement controller or result.
            if (hooks.onProbeResolved) hooks.onProbeResolved(value, api);
            return value;
          });
        },
        release(handle) {
          releases.push(handle);
          return actual.release(handle);
        },
      };
    },
  };
  const exports = {};
  const scope = vm.createContext({
    module: {exports}, exports,
    console: {log: (...args) => logs.push(args), warn: (...args) => logs.push(args)},
    require(name) {
      if (name === 'react') return {__esModule: true, default: react, ...react};
      if (name === 'react-native') return rn;
      if (name === 'sn-plugin-lib') return sdk;
      if (name === './annotationPreview') return importedController;
      throw new Error(`Unexpected actual-App import: ${name}`);
    },
  });
  new vm.Script(transformed, {filename: APP}).runInContext(scope);
  const App = scope.module.exports.default;
  assert.equal(typeof App, 'function');

  function mount() {
    const instance = {
      mounted: true, cells: [], pendingEffects: [], cursor: 0, renders: [],
      render() {
        assert.equal(instance.mounted, true);
        currentMount = instance;
        instance.cursor = 0;
        try {
          instance.tree = App();
          instance.renders.push(instance.tree);
        } finally {
          currentMount = null;
        }
        return instance.tree;
      },
      button(label) {
        instance.render();
        const found = elements(instance.tree, 'Pressable').filter(item => textOf(item) === label);
        assert.equal(found.length, 1, `Actual App button: ${label}`);
        return found[0];
      },
      press(label) {
        const button = instance.button(label);
        assert.equal(button.props.disabled, false, `Actual App enables ${label}`);
        return button.props.onPress();
      },
      unmount() {
        assert.equal(instance.mounted, true);
        instance.mounted = false;
        for (const cell of instance.cells) if (cell.kind === 'effect' && cell.cleanup) cell.cleanup();
      },
      get images() { return elements(instance.render(), 'Image'); },
      get notice() { return elements(instance.render(), 'Text').map(textOf).join('\n'); },
    };
    mounts.push(instance);
    instance.render(); // Preserve first render too: a passive effect cannot hide a leak.
    for (const pending of instance.pendingEffects.splice(0)) instance.cells[pending.index].cleanup = pending.effect();
    instance.render();
    return instance;
  }

  const api = {
    mount, mounts, calls, controllers, outcomes, releases, logs, scope, count,
    changeWindow(value) {
      window = {...value};
      for (const callback of [...rotations]) callback({window: {...window}});
    },
    back() { return [...backs].map(callback => callback()); },
    assertNeverImaged(instance) {
      instance.render();
      for (const tree of instance.renders) assert.equal(elements(tree, 'Image').length, 0, 'No initial or subsequent stale Image tree');
    },
    async enter(name, expected = 1) {
      for (let step = 0; step < 300 && count(name) < expected; step += 1) await Promise.resolve();
      assert.equal(count(name), expected, `${name} entered ${expected} times`);
    },
  };
  return api;
}

test('actual App preview unmount then portrait remount never renders stale Image and preserves exact cleanup handle', async () => {
  const h = harness();
  const first = h.mount();
  await first.press(GENERATE);
  assert.equal(first.images.length, 1);
  assert.equal(first.images[0].props.source.uri, `file://${PNG}`);
  const handle = h.outcomes[0].handle;
  first.unmount();
  h.changeWindow({width: 1404, height: 1872}); // No mounted Dimensions listener.
  const portrait = h.mount();
  h.assertNeverImaged(portrait);
  assert.equal(portrait.button(GENERATE).props.disabled, true);
  assert.equal(h.controllers.length, 1, 'Remount reuses the real session controller');
  assert.equal(h.count('discard'), 0, 'Unmount invalidates presentation, not native ownership');
  await portrait.press(RETURN);
  assert.equal(h.releases[0], handle, 'Cleanup keeps exact object identity, not a token reconstruction');
  assert.equal(h.count('discard'), 1);
  assert.equal(h.count('close'), 1);
  assert.equal(h.controllers[0].getState().retained, false);
  assert.equal(h.scope.RTL_INK_PROBE_BUSY, false);
});

test('actual Dimensions change suppresses retained Image immediately and still allows its exact cleanup', async () => {
  const h = harness();
  const app = h.mount();
  await app.press(GENERATE);
  assert.equal(app.images.length, 1);
  const handle = h.outcomes[0].handle;
  h.changeWindow({width: 1404, height: 1872});
  assert.equal(app.images.length, 0);
  h.changeWindow({width: 1872, height: 1404});
  assert.equal(app.images.length, 0, 'Landscape ABA does not restore a stale preview');
  assert.equal(h.count('discard'), 0);
  assert.deepEqual(h.back(), [true]);
  await app.press(RETURN);
  assert.equal(h.releases[0], handle);
  assert.equal(h.count('discard'), 1);
  assert.equal(h.count('close'), 1);
});

test('real resolved preview cannot publish Image after rotation before the App run continuation', async () => {
  let app;
  const h = harness({onProbeResolved(value, environment) {
    assert.equal(value.status, 'preview', 'Controller already returned a real checked preview');
    assert.equal(environment.controllers[0].getState().retained, true);
    environment.changeWindow({width: 1404, height: 1872});
    assert.equal(app.images.length, 0);
  }});
  app = h.mount();
  await app.press(GENERATE);
  h.assertNeverImaged(app);
  assert.equal(h.count('discard'), 0);
  await app.press(RETURN);
  assert.equal(h.releases[0], h.outcomes[0].handle);
  assert.equal(h.count('discard'), 1);
  assert.equal(h.count('close'), 1);
});

test('real resolved preview unmount/remount race preserves exact handle without any late stale Image', async () => {
  let first;
  let remount;
  const h = harness({onProbeResolved(value, environment) {
    assert.equal(value.status, 'preview');
    first.unmount();
    environment.changeWindow({width: 1404, height: 1872});
    remount = environment.mount();
    environment.assertNeverImaged(remount);
  }});
  first = h.mount();
  await first.press(GENERATE);
  h.assertNeverImaged(remount);
  assert.equal(h.count('discard'), 0);
  assert.equal(remount.button(GENERATE).props.disabled, true);
  await remount.press(RETURN);
  assert.equal(h.releases[0], h.outcomes[0].handle);
  assert.equal(h.count('discard'), 1);
  assert.equal(h.count('close'), 1);
});

test('pending actual SDK cancellation/remount never discards early and keeps Return and Generate fenced', async () => {
  const generation = deferred();
  const h = harness({generate: () => generation.promise});
  const first = h.mount();
  const run = first.press(GENERATE);
  await h.enter('generate');
  first.unmount();
  h.changeWindow({width: 1404, height: 1872});
  const remount = h.mount();
  await flush();
  assert.equal(h.count('discard'), 0, 'The unresolved real SDK call may still write its output');
  assert.equal(h.count('close'), 0);
  assert.equal(remount.button(GENERATE).props.disabled, true);
  assert.equal(remount.button(RETURN).props.disabled, true);
  await remount.button(RETURN).props.onPress(); // Handler also fences a cached callback.
  await remount.button(GENERATE).props.onPress();
  assert.equal(h.count('generate'), 1);
  assert.equal(h.count('discard'), 0);
  assert.deepEqual(h.back(), [true]);
  generation.resolve({success: true, result: true});
  await run;
  assert.equal(h.outcomes[0].reason, 'cancelled');
  assert.equal(h.count('finish'), 0);
  assert.equal(h.count('discard'), 1);
  h.assertNeverImaged(remount);
  await remount.press(RETURN);
  assert.equal(h.count('discard'), 1, 'Cancelled writer cleanup is not repeated by Return');
  assert.equal(h.count('close'), 1);
});

test('one actual diagnostic attempt survives failed result, unmount, and remount', async () => {
  const h = harness({generate: () => ({success: true, result: false})});
  const first = h.mount();
  await first.press(GENERATE);
  assert.equal(h.outcomes[0].reason, 'generation_failed');
  assert.equal(h.count('generate'), 1);
  assert.equal(h.count('discard'), 1);
  first.unmount();
  const remount = h.mount();
  assert.equal(remount.button(GENERATE).props.disabled, true);
  await remount.button(GENERATE).props.onPress();
  assert.equal(h.count('prepare'), 1);
  assert.equal(h.count('generate'), 1);
  h.assertNeverImaged(remount);
  await remount.press(RETURN);
  assert.equal(h.count('close'), 1);
});

test('actual Return waits for explicit matching native cleanup acknowledgement before stock close', async () => {
  const cleanup = deferred();
  const h = harness({discard: () => cleanup.promise});
  const app = h.mount();
  await app.press(GENERATE);
  const close = app.press(RETURN);
  await h.enter('discard');
  await flush();
  assert.equal(h.count('close'), 0);
  assert.equal(app.button(RETURN).props.disabled, true);
  assert.deepEqual(h.back(), [true]);
  await app.button(RETURN).props.onPress();
  assert.equal(h.count('discard'), 1);
  assert.equal(h.count('close'), 0);
  cleanup.resolve({token: TOKEN, discarded: true});
  await close;
  assert.equal(h.count('close'), 1);
  assert.equal(h.controllers[0].getState().retained, false);
  assert.equal(app.images.length, 0);
});

test('resolved cleanup_failed handle survives presentation race/remount and explicit retry releases exact owner', async () => {
  let first;
  let remount;
  let fail = true;
  const h = harness({
    generate: () => ({success: true, result: false}),
    discard: token => {
      if (fail) throw new Error('native cleanup failed');
      return {token, discarded: true};
    },
    onProbeResolved(value, environment) {
      assert.equal(value.reason, 'cleanup_failed');
      assert.equal(environment.controllers[0].getState().retained, true);
      first.unmount();
      environment.changeWindow({width: 1404, height: 1872});
      remount = environment.mount();
    },
  });
  first = h.mount();
  await first.press(GENERATE);
  h.assertNeverImaged(remount);
  assert.equal(remount.button(GENERATE).props.disabled, true);
  assert.equal(h.count('discard'), 1);
  assert.equal(h.count('close'), 0);
  await remount.press(RETURN);
  assert.equal(h.count('discard'), 2);
  assert.equal(h.count('close'), 0, 'Cleanup failure cannot report successful Return');
  assert.equal(h.releases[0], h.outcomes[0].handle);
  assert.equal(h.controllers[0].getState().retained, true);
  fail = false;
  await remount.press(RETURN);
  assert.equal(h.releases[1], h.outcomes[0].handle);
  assert.equal(h.count('discard'), 3);
  assert.equal(h.count('close'), 1);
  assert.equal(h.controllers[0].getState().retained, false);
});
