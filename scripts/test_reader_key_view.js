'use strict';
// Execute the ACTUAL mounted wrapper hook/callback body, not a copied model.
// These hook/native queue doubles do not prove Android focus or RN delivery.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {createReaderKeySession} = require('../overlay/readerKeySession');
const source = fs.readFileSync(path.join(__dirname, '../overlay/ReaderKeyView.js'), 'utf8');
const start = source.indexOf('export default function ReaderKeyView(');
const end = source.indexOf('\n  return (', start);
assert.ok(start > 0 && end > start);
const body = source.slice(start, end).replace('export default function', 'function') +
  '\nreturn {ownerRef, viewRef, routeSpec, handleLayout, onReaderKey};\n}\nreturn ReaderKeyView;';
const NS = 'd1a05000-0000-4000-8000-000000000001';
const INSTANCE = 'd1a05000-0000-4000-8000-000000000002';
const flush = () => new Promise(setImmediate);

function harness(namespace = Promise.resolve(NS)) {
  const state = [], refs = [], effects = [], layoutEffects = [], commands = [], statuses = [], turns = [], layouts = [], diagnostics = [];
  let stateIndex = 0, refIndex = 0, effectIndex = 0, layoutIndex = 0, dirty = false;
  let calls = 0, result;
  const context = {documentId: '/disposable.pdf', presentationId: 'single:1:ready:1',
    direction: 'rtl', enabled: true, blocked: false, profile: 'navigation'};
  const controllerRef = {current: null};
  function schedule(list, index, fn, deps) {
    const old = list[index];
    if (old && deps.every((v, i) => v === old.deps[i])) return;
    old?.cleanup?.(); list[index] = {fn, deps, pending: true};
  }
  const scope = {
    console: {log: value => diagnostics.push(value)},
    createReaderKeySession,
    NativeModules: {ReaderKeyModule: {createRequestNamespace() { calls++; return namespace; }}},
    findNodeHandle: v => v === 'native-view' ? 42 : null,
    UIManager: {getViewManagerConfig: () => ({Commands: {requestReaderKeyFocus: 100}}),
      dispatchViewManagerCommand: (...args) => commands.push(args)},
    useRef(initial) { const i = refIndex++; if (!refs[i]) refs[i] = {current: initial}; return refs[i]; },
    useState(initial) { const i = stateIndex++; if (state[i] === undefined) state[i] = initial;
      return [state[i], v => { state[i] = typeof v === 'function' ? v(state[i]) : v; dirty = true; }]; },
    useEffect: (fn, deps) => schedule(effects, effectIndex++, fn, deps),
    useLayoutEffect: (fn, deps) => schedule(layoutEffects, layoutIndex++, fn, deps),
  };
  const names = Object.keys(scope);
  const Component = new Function(...names, body)(...names.map(name => scope[name]));
  function render() {
    dirty = false; stateIndex = refIndex = effectIndex = layoutIndex = 0;
    result = Component({controllerRef, context: JSON.stringify(context), currentContext: () => context,
      turn: action => turns.push(action), onStatus: s => statuses.push(s), onLayout: e => layouts.push(e)});
    result.viewRef.current = 'native-view';
    for (const list of [layoutEffects, effects]) for (const effect of list) {
      if (!effect.pending) continue;
      effect.pending = false; effect.cleanup = effect.fn();
    }
    return result;
  }
  function settle() { let count = 0; while (dirty) { assert.ok(++count < 8, 'No reconfiguration render loop'); render(); } }
  render();
  return {context, controllerRef, commands, statuses, turns, layouts, diagnostics, scope, render, settle,
    get result() { return result; }, get calls() { return calls; },
    layout(width = 1872, height = 1404) { result.handleLayout({nativeEvent: {layout: {width, height}}}); settle(); },
    event(patch = {}) { result.onReaderKey({nativeEvent: {schemaVersion: 1, kind: 'state',
      requestId: result.routeSpec.requestId, documentId: context.documentId, sequence: 1,
      activationId: `${INSTANCE}:1`, generation: 1, eligible: false, disposed: false, ...patch}}); },
    unmount() { for (const e of effects) e.cleanup?.(); },
  };
}

test('fresh asynchronous namespace, measured layout and exact native-bound focus precede any routing', async () => {
  const h = harness(); assert.equal(h.result.routeSpec, null); assert.equal(h.calls, 1);
  await flush(); h.settle();
  assert.equal(h.result.routeSpec.enabled, false, 'No measured viewport');
  h.layout(); assert.equal(h.result.routeSpec.enabled, true);
  h.event(); assert.deepEqual(h.commands, [[42, 100, [h.result.routeSpec.requestId]]]);
  assert.equal(h.layouts.length, 1);
  h.render(); h.settle(); assert.equal(h.calls, 1, 'Ordinary rerender never reuses/reacquires a namespace');
  h.unmount(); assert.equal(h.controllerRef.current, null);
});

test('delayed namespace after parent disposal/unmount cannot publish, focus or turn', async () => {
  let resolve; const h = harness(new Promise(r => { resolve = r; }));
  h.controllerRef.current.dispose(); h.unmount(); resolve(NS); await flush(); h.settle();
  assert.equal(h.result.routeSpec, null); assert.equal(h.result.ownerRef.current, null);
  assert.deepEqual(h.commands, []); assert.deepEqual(h.turns, []);
});

test('layout ABA fences synchronously; delayed old key/state never acquires new viewport authority', async () => {
  const h = harness(); await flush(); h.settle(); h.layout();
  const original = h.result.routeSpec.requestId;
  h.event({eligible: true});
  h.layout(1404, 1872); h.layout();
  assert.notEqual(h.result.routeSpec.requestId, original);
  h.event({requestId: original, kind: 'key', eligible: true, action: 0, keyCode: 93,
    deviceId: 2, downTime: 100, repeatCount: 0});
  assert.deepEqual(h.turns, []);
  assert.equal(h.result.ownerRef.current.getState().failed, false);
  h.unmount();
});

test('namespace/bridge failure is observable and does not capture keys', async () => {
  const h = harness(Promise.reject(new Error('not registered')));
  await flush(); h.settle();
  assert.equal(h.result.routeSpec, null); assert.match(h.statuses.at(-1), /Unavailable/);
  assert.deepEqual(h.commands, []); h.unmount();
});

test('actual wrapper reports native key/JS decision without restamping or logging document data', async () => {
  const h = harness(); await flush(); h.settle(); h.layout(); h.event({eligible: true});
  const key = {kind: 'key', eligible: true, action: 0, keyCode: 93, deviceId: -1,
    downTime: 100, repeatCount: 0, sequence: 2};
  h.event(key); assert.deepEqual(h.turns, ['next']);
  assert.match(h.diagnostics[0], /sequence=2 generation=1 key=93 action=0 result=turned handled=true/);
  assert.ok(!h.diagnostics[0].includes(h.context.documentId));
  h.controllerRef.current.fence(); h.event({...key, sequence: 3});
  assert.match(h.diagnostics.at(-1), /result=ui_fenced handled=false/);
  assert.deepEqual(h.turns, ['next']); h.unmount();
});

test('diagnostic failure and saturation cannot block, retry or unbound key delivery', async () => {
  const h = harness(); await flush(); h.settle(); h.layout(); h.event({eligible: true});
  h.scope.console.log = () => { throw new Error('logger unavailable'); };
  h.event({kind: 'key', eligible: true, action: 0, keyCode: 93, deviceId: -1,
    downTime: 100, repeatCount: 0, sequence: 2});
  assert.deepEqual(h.turns, ['next']);
  h.scope.console.log = value => h.diagnostics.push(value);
  for (let sequence = 3; sequence < 250; sequence++) h.event({kind: 'key', eligible: true,
    action: 0, keyCode: 93, deviceId: -1, downTime: 100 + sequence, repeatCount: 0, sequence});
  assert.equal(h.diagnostics.length, 127);
  assert.equal(h.turns.length, 248);
  assert.ok(h.turns.every(action => action === 'next'));
  assert.equal(h.result.ownerRef.current.getState().failed, false); h.unmount();
});

test('strict packet rejection remains fail-closed even when observation fails', async () => {
  for (const patch of [{schemaVersion: '1'}, {extra: '/private-content'},
    {keyCode: 'private-content'}, {sequence: NaN}]) {
    const h = harness(); await flush(); h.settle(); h.layout(); h.event({eligible: true});
    h.scope.console.log = () => { throw new Error('logger unavailable'); };
    h.event({kind: 'key', eligible: true, action: 0, keyCode: 93, deviceId: -1,
      downTime: 100, repeatCount: 0, sequence: 2, ...patch});
    assert.deepEqual(h.turns, []);
    assert.equal(h.result.ownerRef.current.getState().failed, true); h.unmount();
  }
});

test('stale packet observations retain original stamps and cannot imply delivery authority', async () => {
  const h = harness(); await flush(); h.settle(); h.layout(); h.event({eligible: true});
  h.event({kind: 'key', requestId: 'stale-request', eligible: true, action: 0,
    keyCode: 93, deviceId: -1, downTime: 100, repeatCount: 0, sequence: 2, generation: 17});
  assert.match(h.diagnostics.at(-1), /generation=17.*result=stale_request/);
  assert.deepEqual(h.turns, []);
  assert.equal(h.result.ownerRef.current.getState().failed, false); h.unmount();
});
