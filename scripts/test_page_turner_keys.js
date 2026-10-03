'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {DEFAULT_BINDINGS, MAX_RECORDS, createPageTurnerKeys} = require('../overlay/pageTurnerKeys');

function harness(bindings) {
  const context = {activationId: 'mount-1', documentId: '/original.pdf', enabled: true,
    focused: true, blocked: false, direction: 'rtl'};
  const turns = [];
  const controller = createPageTurnerKeys({currentContext: () => context, turn: action => turns.push(action),
    ...(bindings === undefined ? {} : {bindings})});
  let tick = 1;
  return {context, turns, controller, press: (keyCode, patch = {}) => controller.handle({activationId: context.activationId,
    documentId: context.documentId,
    keyCode, deviceId: 3, downTime: tick++, repeatCount: 0, action: 0, ...patch})};
}

test('logical page keys are direction-independent; physical arrows follow reading direction', () => {
  for (const direction of ['rtl', 'ltr']) {
    const h = harness(); h.context.direction = direction;
    for (const key of [92, 93, 21, 22]) assert.equal(h.press(key).handled, true);
    assert.deepEqual(h.turns, direction === 'rtl'
      ? ['previous', 'next', 'next', 'previous'] : ['previous', 'next', 'previous', 'next']);
  }
});

test('volume, space and enter retain ordinary behavior unless explicitly mapped', () => {
  const h = harness();
  for (const key of [24, 25, 62, 66, 4, 26]) assert.equal(h.press(key).handled, false);
  assert.equal(h.turns.length, 0);
  assert.equal(h.controller.getState().records, 0);
  const configured = harness({24: 'previous', 25: 'next', 62: 'next', 66: 'next'});
  for (const key of [24, 25, 62, 66]) configured.press(key);
  assert.deepEqual(configured.turns, ['previous', 'next', 'next', 'next']);
});

test('binding authority is copied and rejects malformed or reserved keys', () => {
  assert.ok(Object.isFrozen(DEFAULT_BINDINGS));
  const mapping = {93: 'next'}; const h = harness(mapping); mapping[93] = 'previous';
  h.press(93); assert.deepEqual(h.turns, ['next']);
  for (const bindings of [null, [], {4: 'next'}, {26: 'next'}, {'093': 'next'}, {93: 'swipe'}, {'x': 'next'}]) {
    assert.throws(() => harness(bindings), TypeError);
  }
});

test('every malformed event is non-mutating and no unowned repeat or UP turns a page', () => {
  const h = harness();
  for (const patch of [{action: 2}, {action: '0'}, {downTime: NaN}, {downTime: -1}, {downTime: 1.5},
    {repeatCount: -1}, {repeatCount: 256}, {deviceId: -2}, {deviceId: 0.5},
    {keyCode: '93'}, {action: 1}, {activationId: 'old-mount'}, {documentId: 'other.pdf'}, {documentId: null}]) {
    assert.equal(h.press(93, patch).handled, false, JSON.stringify(patch));
  }
  assert.equal(h.turns.length, 0); assert.equal(h.controller.getState().records, 0);
});

test('one physical press turns once; held repeats and stale DOWN never queue more turns', () => {
  const h = harness(); h.press(93, {downTime: 10});
  for (const repeatCount of [0, 1, 2, 255]) assert.equal(h.press(93, {downTime: 10, repeatCount}).handled, true);
  assert.equal(h.press(93, {downTime: 9}).handled, true);
  assert.deepEqual(h.turns, ['next']);
  assert.equal(h.press(93, {action: 1, downTime: 9}).handled, false);
  assert.equal(h.controller.getState().held, 1);
  assert.equal(h.press(93, {action: 1, downTime: 10}).handled, true);
  h.press(93, {downTime: 10}); assert.deepEqual(h.turns, ['next']);
  h.press(93, {downTime: 11}); assert.deepEqual(h.turns, ['next', 'next']);
});

test('newer exact-key press recovers a missing UP without a timer or deferred action', () => {
  const h = harness(); h.press(93, {downTime: 10}); h.press(93, {downTime: 11});
  assert.equal(h.controller.getState().held, 1); assert.deepEqual(h.turns, ['next', 'next']);
  assert.equal(h.press(93, {action: 1, downTime: 10}).handled, false);
  assert.equal(h.controller.getState().held, 1);
});

test('inactive, settings/transition-locked and unknown-direction contexts do not retain future turns', () => {
  for (const patch of [{enabled: false}, {enabled: undefined}, {focused: false}, {blocked: true},
    {blocked: undefined}, {direction: 'guess'}, {activationId: ''}, {documentId: ''}]) {
    const h = harness(); Object.assign(h.context, patch); h.press(93);
    assert.deepEqual(h.turns, []);
    assert.equal(h.controller.getState().held, 0);
  }
});

test('owned UP completes while navigation is blocked; focus cancellation cannot resurrect a press', () => {
  const h = harness(); h.press(93, {downTime: 10}); h.context.blocked = true;
  assert.equal(h.press(93, {action: 1, downTime: 10}).handled, true);
  h.context.blocked = false; h.press(93, {downTime: 11}); h.controller.cancelContacts();
  assert.equal(h.controller.getState().held, 0);
  h.press(93, {downTime: 11}); assert.deepEqual(h.turns, ['next', 'next']);
  h.press(93, {downTime: 12}); assert.deepEqual(h.turns, ['next', 'next', 'next']);
});

test('old activation packets cannot target another document/mount and no handler survives disposal', () => {
  const h = harness(); h.press(93, {downTime: 10}); h.context.activationId = 'mount-2'; h.context.documentId = '/other.pdf';
  assert.equal(h.press(93, {activationId: 'mount-1', downTime: 11}).handled, false);
  assert.equal(h.controller.getState().records, 0);
  h.press(93, {downTime: 11}); assert.deepEqual(h.turns, ['next', 'next']);
  h.controller.dispose(); assert.equal(h.press(93).handled, false);
  assert.equal(h.controller.getState().records, 0);
});

test('each rejected contact remains rejected after a routing fence clears', () => {
  for (const patch of [{enabled: false}, {focused: false}, {blocked: true}, {direction: 'guess'}]) {
    const h = harness(); Object.assign(h.context, patch);
    assert.equal(h.press(93, {downTime: 10}).handled, false);
    Object.assign(h.context, {enabled: true, focused: true, blocked: false, direction: 'rtl'});
    assert.equal(h.press(93, {downTime: 10}).handled, false);
    assert.equal(h.press(93, {downTime: 9}).handled, false);
    assert.equal(h.press(93, {action: 1, downTime: 10}).handled, false);
    assert.deepEqual(h.turns, []);
    h.press(93, {downTime: 11}); assert.deepEqual(h.turns, ['next']);
  }
});

test('unowned repeat classifies the missing DOWN and cannot later replay it', () => {
  const h = harness(); assert.equal(h.press(93, {downTime: 10, repeatCount: 1}).handled, false);
  assert.equal(h.press(93, {downTime: 10, repeatCount: 0}).handled, false);
  assert.deepEqual(h.turns, []); assert.equal(h.controller.getState().held, 0);
  h.press(93, {downTime: 11}); assert.deepEqual(h.turns, ['next']);
});

test('missing context preserves classified-contact history instead of reviving it', () => {
  const h = harness(); h.press(93, {downTime: 10});
  h.context.documentId = ''; assert.equal(h.press(93, {downTime: 10}).handled, false);
  h.context.documentId = '/original.pdf'; h.press(93, {downTime: 10});
  assert.deepEqual(h.turns, ['next']);
});

test('a document-only change rejects the actual old packet even with an unchanged activation', () => {
  const h = harness();
  const event = {activationId: 'mount-1', documentId: '/original.pdf', keyCode: 93,
    deviceId: 3, downTime: 10, repeatCount: 0, action: 0};
  h.controller.handle(event); h.context.documentId = '/other.pdf';
  assert.equal(h.controller.handle(event).handled, false);
  assert.deepEqual(h.turns, ['next']); assert.equal(h.controller.getState().records, 0);
});

test('device/key history is bounded; no new contact allocates past its fixed capacity', () => {
  const h = harness();
  for (let deviceId = 0; deviceId < MAX_RECORDS; deviceId++) h.press(93, {deviceId});
  const result = h.press(93, {deviceId: MAX_RECORDS});
  assert.equal(result.reason, 'capacity'); assert.equal(result.handled, false);
  assert.equal(h.press(93, {deviceId: MAX_RECORDS, action: 1, downTime: MAX_RECORDS + 1}).handled, false);
  assert.equal(h.turns.length, MAX_RECORDS); assert.equal(h.controller.getState().records, MAX_RECORDS);
  h.controller.cancelContacts();
  h.press(93, {deviceId: MAX_RECORDS});
  assert.equal(h.turns.length, MAX_RECORDS + 1);
  assert.equal(h.controller.getState().records, MAX_RECORDS);
});

test('finished contacts retire across reconnects without accepting evicted replay', () => {
  const h = harness();
  for (let deviceId = 0; deviceId < MAX_RECORDS * 3; deviceId++) {
    const downTime = 10 + deviceId;
    assert.equal(h.press(93, {deviceId, downTime}).handled, true);
    assert.equal(h.press(93, {deviceId, downTime, action: 1}).handled, true);
    assert.ok(h.controller.getState().records <= MAX_RECORDS);
  }
  assert.equal(h.turns.length, MAX_RECORDS * 3); assert.equal(h.controller.getState().held, 0);
  assert.equal(h.press(93, {deviceId: 0, downTime: 10}).handled, false);
  assert.equal(h.turns.length, MAX_RECORDS * 3);
  h.press(93, {deviceId: 0, downTime: 1000}); assert.equal(h.turns.length, MAX_RECORDS * 3 + 1);
});

test('evicted rejected and capacity-rejected contacts cannot replay after recovery', () => {
  const h = harness(); h.context.blocked = true;
  for (let deviceId = 0; deviceId <= MAX_RECORDS; deviceId++) h.press(93, {deviceId, downTime: deviceId + 10});
  h.context.blocked = false;
  h.press(93, {deviceId: 0, downTime: 10}); assert.deepEqual(h.turns, []);
  const allHeld = harness();
  for (let deviceId = 0; deviceId < MAX_RECORDS; deviceId++) allHeld.press(93, {deviceId, downTime: deviceId + 10});
  assert.equal(allHeld.press(93, {deviceId: MAX_RECORDS, downTime: 100}).handled, false);
  assert.equal(allHeld.press(93, {deviceId: MAX_RECORDS, downTime: 100, action: 1}).handled, false);
  allHeld.controller.cancelContacts();
  assert.equal(allHeld.press(93, {deviceId: MAX_RECORDS, downTime: 100}).handled, false);
  assert.equal(allHeld.turns.length, MAX_RECORDS);
  allHeld.press(93, {deviceId: MAX_RECORDS, downTime: 101});
  assert.equal(allHeld.turns.length, MAX_RECORDS + 1);
});

test('callback failure is consumed once and cannot be replayed as an automatic retry', () => {
  let calls = 0;
  const controller = createPageTurnerKeys({currentContext: () => ({activationId: 'mount', documentId: 'pdf',
    enabled: true, focused: true, blocked: false, direction: 'rtl'}), turn() { calls++; throw Error('navigation rejected'); }});
  const event = {activationId: 'mount', documentId: 'pdf', keyCode: 93, deviceId: 1, downTime: 10, repeatCount: 0, action: 0};
  assert.equal(controller.handle(event).reason, 'turn_failed');
  controller.handle(event); assert.equal(calls, 1);
});
