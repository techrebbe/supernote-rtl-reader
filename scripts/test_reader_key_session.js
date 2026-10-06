'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {createReaderKeySession} = require('../overlay/readerKeySession');
const NS = 'd1a05000-0000-4000-8000-000000000001';
const INSTANCE = 'd1a05000-0000-4000-8000-000000000002';
function harness(patch = {}, onTurn = null) {
  const context = {documentId: '/disposable.pdf', presentationId: 'single:1:ready:1', direction: 'rtl',
    enabled: true, blocked: false, profile: 'navigation', ...patch};
  const specs = [], statuses = [], focus = [], turns = [];
  const session = createReaderKeySession({namespace: NS, currentContext: () => context,
    turn: action => { turns.push(action); onTurn?.(session, context); },
    publishSpec: spec => specs.push(spec), focus: id => focus.push(id), status: s => statuses.push(s)});
  let sequence = 0, generation = 0, downTime = 100;
  function envelope(kind, extra = {}) {
    if (kind === 'state') generation++;
    return {schemaVersion: 1, kind, requestId: specs.at(-1).requestId, sequence: ++sequence,
      documentId: context.documentId, activationId: `${INSTANCE}:${generation}`, generation,
      eligible: true, disposed: false,
      ...(kind === 'key' ? {action: 0, keyCode: 93, deviceId: 2, downTime: ++downTime, repeatCount: 0} : {}), ...extra};
  }
  session.synchronize();
  return {session, context, specs, statuses, focus, turns, envelope,
    state(extra) { return session.handle(envelope('state', extra)); },
    key(extra) { return session.handle(envelope('key', extra)); }};
}

test('explicit profiles never claim volume by default; disabled/UI-blocked cannot focus or turn', () => {
  for (const patch of [{enabled: false}, {blocked: true}]) {
    const h = harness(patch); h.state({eligible: false}); h.session.requestFocus();
    assert.equal(h.specs[0].enabled, false); assert.deepEqual(h.focus, []); assert.deepEqual(h.turns, []);
  }
  const nav = harness(); assert.deepEqual(nav.specs[0].keyCodes, [21, 22, 92, 93]);
  for (const profile of ['volume', 'volume_reversed']) {
    const h = harness({profile}); h.state(); h.key({keyCode: 24});
    assert.deepEqual(h.specs[0].keyCodes, [24, 25]);
    assert.deepEqual(h.turns, [profile === 'volume' ? 'next' : 'previous']);
  }
});

test('focus command binds exact current request and never restamps a delayed state', () => {
  const h = harness(); h.state({eligible: false}); assert.deepEqual(h.focus, [h.specs[0].requestId]);
  const stale = h.envelope('state', {eligible: false}); h.context.presentationId = 'spread:3:ready:2';
  h.session.fence(); h.session.synchronize();
  h.session.handle(stale); assert.equal(h.focus.length, 1);
  h.state({eligible: false}); assert.equal(h.focus.at(-1), h.specs.at(-1).requestId);
});

test('queued packets during a UI fence cannot fail or revive the owner; accepted turn fences are normal', () => {
  const h = harness({}, (owner, ctx) => { owner.fence(); ctx.presentationId = 'single:2:pending:2'; ctx.blocked = true; });
  h.state(); const turn = h.key(); assert.equal(turn.handled, true);
  assert.equal(h.session.getState().failed, false);
  h.state(); h.key(); assert.deepEqual(h.turns, ['next']);
  h.session.synchronize(); assert.equal(h.specs.at(-1).enabled, false);
  h.context.blocked = false; h.context.presentationId = 'single:2:ready:2'; h.session.synchronize();
  h.state(); h.key(); assert.deepEqual(h.turns, ['next', 'next']);
  assert.equal(h.session.getState().failed, false);
});

test('stream faults are visible, publish native OFF and remain latched across ordinary rerenders', () => {
  const h = harness(); h.state(); h.key({sequence: 50});
  assert.equal(h.session.getState().failed, true); assert.equal(h.specs.at(-1).enabled, false);
  assert.match(h.statuses.at(-1), /Unavailable: stream_gap/);
  const count = h.specs.length; h.session.synchronize(); h.session.fence(); h.session.synchronize();
  assert.equal(h.specs.length, count); h.key(); assert.deepEqual(h.turns, []);
});

test('current UI is reread on focus/key and disposed owner never publishes or turns', () => {
  const h = harness(); h.state(); const packet = h.envelope('key');
  h.context.blocked = true; h.session.handle(packet); h.session.requestFocus();
  assert.deepEqual(h.turns, []); assert.deepEqual(h.focus, []);
  h.session.dispose(); const count = h.specs.length, statuses = h.statuses.length;
  h.context.blocked = false; h.session.synchronize(); h.session.handle(packet); h.session.requestFocus();
  assert.equal(h.specs.length, count); assert.equal(h.statuses.length, statuses); assert.deepEqual(h.turns, []);
});
