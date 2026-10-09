'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {createPageTurnerTransport} = require('../overlay/pageTurnerTransport');
const {DEFAULT_BINDINGS} = require('../overlay/pageTurnerKeys');
const NAMESPACE = 'd1a05000-0000-4000-8000-000000000001';
const INSTANCE = 'd1a05000-0000-4000-8000-000000000002';

function harness() {
  const turns = [];
  const hooks = {read: null};
  const context = {documentId: '/disposable.pdf', presentationId: 'single:2:ready:1',
    direction: 'rtl', enabled: true, blocked: false};
  const transport = createPageTurnerTransport({namespace: NAMESPACE,
    currentContext: () => { hooks.read?.(); return context; }, turn: action => turns.push(action)});
  let spec = transport.configure(context);
  let sequence = 0, generation = 1, downTime = 100;
  const envelope = (kind, patch = {}) => ({schemaVersion: 1, kind, requestId: spec.requestId,
    sequence: ++sequence, activationId: `${INSTANCE}:${generation}`, documentId: context.documentId,
    generation, eligible: true, disposed: false,
    ...(kind === 'key' ? {action: 0, keyCode: 93, deviceId: 2, downTime: ++downTime, repeatCount: 0} : {}), ...patch});
  const state = patch => transport.handle(envelope('state', patch));
  return {context, transport, turns, hooks, envelope, state,
    key(patch) { return transport.handle(envelope('key', patch)); },
    configure(bindings = DEFAULT_BINDINGS, force = false) { spec = transport.configure(context, bindings, force); generation++; return spec; },
    get spec() { return spec; }, nextGeneration() { generation++; }};
}

test('one native state/key stream retains exact request stamps and logical mappings', () => {
  for (const direction of ['rtl', 'ltr']) {
    const h = harness(); h.context.direction = direction; h.configure();
    assert.equal(h.state().reason, 'native_ready');
    assert.equal(h.transport.focusRequest(), h.spec.requestId);
    h.key({keyCode: 21}); h.key({keyCode: 22}); h.key({keyCode: 93}); h.key({keyCode: 92});
    assert.deepEqual(h.turns, [direction === 'rtl' ? 'next' : 'previous',
      direction === 'rtl' ? 'previous' : 'next', 'next', 'previous']);
  }
});

test('reentrant context callbacks cannot bypass fence/disposal or replace authority mid-check', () => {
  for (const operation of ['fence', 'dispose', 'configure', 'state']) {
    for (const check of ['key', 'focus']) {
      const h = harness(); h.state();
      // Allocate the outer key before the newer lifecycle event for the
      // recursive-state case, without assuming native delivery order reversed.
      const key = h.envelope('key');
      h.hooks.read = () => {
        h.hooks.read = null;
        if (operation === 'configure') h.configure(DEFAULT_BINDINGS, true);
        else if (operation === 'state') { h.nextGeneration(); h.state({eligible: false}); }
        else h.transport[operation]();
      };
      if (check === 'key') assert.equal(h.transport.handle(key).handled, false);
      else assert.equal(h.transport.focusRequest(), null);
      assert.deepEqual(h.turns, [], `${operation} inside ${check} callback revokes before any navigation`);
    }
  }
});

test('duplicate complete prop objects do not reset identity; changed config is fenced atomically', () => {
  const h = harness(); const first = h.spec;
  assert.equal(h.transport.configure({...h.context}), first);
  h.state(); const oldKey = h.envelope('key');
  for (const patch of [{direction: 'ltr'}, {presentationId: 'spread:2:ready:2'},
    {enabled: false}, {enabled: true}, {blocked: true}, {blocked: false}, {documentId: '/other.pdf'}]) {
    Object.assign(h.context, patch); const next = h.configure();
    assert.notEqual(next.requestId, first.requestId);
    assert.equal(h.transport.handle(oldKey).reason, 'stale_request');
    assert.equal(h.transport.getState().activationId, undefined);
  }
  assert.deepEqual(h.turns, []);
});

test('new request first state can anchor after ignored old-request packets; keys cannot', () => {
  const h = harness(); h.state(); const oldState = h.envelope('state');
  h.context.presentationId = 'spread:2:ready:2'; h.configure();
  assert.equal(h.transport.handle(oldState).reason, 'stale_request');
  assert.equal(h.state().reason, 'native_ready'); h.key(); assert.deepEqual(h.turns, ['next']);
  const noState = harness(); assert.equal(noState.key().reason, 'missing_configuration_state');
  assert.equal(noState.state().reason, 'transport_unavailable');
});

test('synchronous modal/Edit/Close/render fences reject queued DOWN without later replay', () => {
  for (const patch of [{blocked: true}, {enabled: false}, {direction: 'ltr'},
    {presentationId: 'single:3:pending:2'}, {documentId: '/changed.pdf'}]) {
    const h = harness(); h.state(); const key = h.envelope('key');
    const previous = {...h.context}; Object.assign(h.context, patch);
    assert.equal(h.transport.handle(key).handled, false);
    assert.equal(h.transport.focusRequest(), null);
    Object.assign(h.context, previous);
    assert.equal(h.transport.handle(key).handled, false); assert.deepEqual(h.turns, []);
  }
});

test('explicit fence cannot be rearmed by delayed state even after identical UI ABA', () => {
  const h = harness(); h.state(); h.nextGeneration(); const delayed = h.envelope('state');
  h.transport.fence();
  assert.equal(h.transport.handle(delayed).reason, 'transport_unavailable');
  assert.equal(h.transport.focusRequest(), null);
  const old = h.spec.requestId; h.configure(); assert.notEqual(h.spec.requestId, old);
  assert.equal(h.transport.handle(delayed).reason, 'stale_request');
  h.state(); h.key(); assert.deepEqual(h.turns, ['next']);
});

test('ordered stream rejects gaps, replay, native-instance changes and generation rollback', () => {
  for (const patch of [{sequence: 1}, {sequence: 3}, {generation: 2, activationId: `${INSTANCE}:2`},
    {activationId: `${NAMESPACE}:1`}, {activationId: `${INSTANCE}:01`}]) {
    const h = harness(); h.state(); assert.equal(h.key(patch).handled, false);
    assert.equal(h.transport.getState().faulted, true); assert.deepEqual(h.turns, []);
    assert.equal(h.state().reason, 'transport_unavailable');
  }
  const h = harness(); h.state(); assert.equal(h.state().reason, 'generation_replay');
});

test('native lifecycle loss/ABA updates generation and rejects stale contact stamps', () => {
  const h = harness(); h.state(); const key = h.envelope('key');
  h.nextGeneration(); assert.equal(h.state({eligible: false}).reason, 'stream_gap');
  // Above deliberately omitted sequence2 (the queued key), so fail closed.
  const ordered = harness(); ordered.state(); ordered.key();
  ordered.nextGeneration(); ordered.state({eligible: false});
  assert.equal(ordered.transport.getState().eligible, false);
  ordered.nextGeneration(); ordered.state();
  assert.equal(ordered.transport.handle(key).handled, false);
  assert.equal(ordered.turns.length, 1);
});

test('held repeat, exact UP and newer press remain bounded across the native transport', () => {
  const h = harness(); h.state(); h.key({downTime: 101});
  h.key({downTime: 101, repeatCount: 2147483647});
  h.key({action: 1, downTime: 101}); h.key({downTime: 102});
  assert.deepEqual(h.turns, ['next', 'next']);
});

test('strict native envelope types and identities fail closed, never throw', () => {
  const patches = [{schemaVersion: '1'}, {eligible: 1}, {disposed: true}, {extra: 2},
    {activationId: null}, {documentId: '/wrong.pdf'}, {sequence: NaN}, {sequence: Infinity},
    {generation: Number.MAX_SAFE_INTEGER + 1}, {kind: 'unknown'}, {downTime: -1},
    {repeatCount: 2147483648}, {deviceId: 2147483648}, {action: 2}, {keyCode: 93.1}];
  for (const patch of patches) {
    const h = harness(); h.state();
    assert.doesNotThrow(() => assert.equal(h.key(patch).handled, false));
    assert.equal(h.transport.getState().faulted, true); assert.deepEqual(h.turns, []);
  }
  const disabled = harness(); disabled.context.enabled = false; disabled.configure();
  assert.equal(disabled.state().reason, 'malformed_envelope');
});

test('opt-in bindings, defensive copies, namespace/counter and terminal disposal', () => {
  const h = harness(); const bindings = {24: 'next', 25: 'previous'};
  h.configure(bindings); bindings[24] = 'previous'; h.state(); h.key({keyCode: 24});
  assert.deepEqual(h.turns, ['next']);
  assert.deepEqual(h.spec.keyCodes, [24, 25]); assert.equal(Object.isFrozen(h.spec), true);
  assert.equal(Object.isFrozen(h.spec.keyCodes), true);
  assert.throws(() => h.configure({23: 'next'})); // DPAD_CENTER remains unmapped/reserved.
  assert.equal(h.transport.getState().faulted, false, 'Failed context validation does not mutate the old route');
  h.transport.dispose(); assert.equal(h.key().reason, 'transport_unavailable');
  assert.equal(h.transport.focusRequest(), null); assert.throws(() => h.configure());
  assert.throws(() => createPageTurnerTransport({namespace: 'not-native', currentContext() {}, turn() {}}));
});
