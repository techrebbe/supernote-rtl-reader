'use strict';
// Execute the actual existing App navigation functions with the isolated key
// controller. Native focus/key delivery is intentionally NOT simulated/proven.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {createPageTurnerKeys} = require('../overlay/pageTurnerKeys');
const source = fs.readFileSync(path.join(__dirname, '..', 'overlay', 'App.js'), 'utf8').replace(/\r\n/g, '\n');

function section(start, end) {
  const from = source.indexOf(start);
  const to = source.indexOf(end, from);
  assert.ok(from >= 0 && to > from, `Missing actual App source: ${start}`);
  assert.equal(source.indexOf(start, from + start.length), -1, `Ambiguous source: ${start}`);
  return source.slice(from, to);
}
const geometry = section('function clampPage(', 'function viewModeLabel(');
const locked = section('  const readerTransitionLocked =', '  const beginReaderTransition =');
const setter = section('  const setPageIndex = value => {', '  const displayRef =');
const logicalRoute = section('  const goBy = delta => {', '  const handlePhysicalSwipe =');

function harness({mode = 'single', direction = 'rtl', page = 2, total = 8, cover = false} = {}) {
  let invalidations = 0;
  const context = {activationId: 'one-reader', documentId: '/disposable.pdf',
    enabled: true, focused: true, direction};
  const scope = {
    pageIndexRef: {current: page}, totalPagesRef: {current: total},
    effectiveModeRef: {current: mode}, coverSeparateRef: {current: cover},
    directionRef: {current: direction}, readerClosedRef: {current: false},
    editInFlightRef: {current: false}, closeInFlightRef: {current: false},
    globalThis: {RTL_READER_TRANSITION_IN_FLIGHT: null},
    invalidateSavedInkPresentation() { invalidations++; }, fenceReaderKeys() {}, setPageIndexRaw() {}, console: {log() {}},
  };
  const names = Object.keys(scope);
  const route = new Function(...names, geometry + locked + setter + logicalRoute +
    '\nreturn {nextLogicalPage, previousLogicalPage, readerTransitionLocked};')(...names.map(name => scope[name]));
  const controller = createPageTurnerKeys({currentContext: () => ({...context,
    blocked: route.readerTransitionLocked() || context.modal === true}),
    turn: action => action === 'next' ? route.nextLogicalPage() : route.previousLogicalPage()});
  let time = 0;
  const packet = (keyCode, downTime, action = 0) => ({activationId: context.activationId,
    documentId: context.documentId, keyCode, downTime, deviceId: 2, repeatCount: 0, action});
  return {context, scope, controller, packet,
    press(keyCode) { const downTime = ++time; controller.handle(packet(keyCode, downTime));
      controller.handle(packet(keyCode, downTime, 1)); },
    get page() { return scope.pageIndexRef.current; }, get invalidations() { return invalidations; }};
}

test('actual App route uses Single/Spread logical steps and physical RTL/LTR direction', () => {
  for (const mode of ['single', 'spread']) for (const direction of ['rtl', 'ltr']) {
    const h = harness({mode, direction});
    const step = mode === 'single' ? 1 : 2;
    h.press(93); assert.equal(h.page, 2 + step);
    h.press(92); assert.equal(h.page, 2);
    h.press(direction === 'rtl' ? 21 : 22); assert.equal(h.page, 2 + step);
    h.press(direction === 'rtl' ? 22 : 21); assert.equal(h.page, 2);
    assert.equal(h.invalidations, 4, 'Accepted visible-page changes use the existing ink fence');
  }
});

test('actual App clamps first/last page without new saved-ink invalidation', () => {
  for (const mode of ['single', 'spread']) for (const cover of [false, true]) {
    const first = harness({mode, cover, page: 0}); first.press(92);
    assert.equal(first.page, 0); assert.equal(first.invalidations, 0);
    const last = harness({mode, cover, page: 7}); last.press(93);
    assert.equal(last.page, 7); assert.equal(last.invalidations, 0);
  }
});

test('actual Edit/Close/closed/global transition fences reject keys without a later replay', () => {
  for (const name of ['editInFlightRef', 'closeInFlightRef', 'readerClosedRef', 'global']) {
    const h = harness();
    if (name === 'global') h.scope.globalThis.RTL_READER_TRANSITION_IN_FLIGHT = {};
    else h.scope[name].current = true;
    const event = h.packet(93, 10);
    assert.equal(h.controller.handle(event).handled, false); assert.equal(h.page, 2);
    if (name === 'global') h.scope.globalThis.RTL_READER_TRANSITION_IN_FLIGHT = null;
    else h.scope[name].current = false;
    assert.equal(h.controller.handle(event).handled, false); assert.equal(h.page, 2);
    h.controller.handle(h.packet(93, 11)); assert.equal(h.page, 3);
    assert.equal(h.invalidations, 1);
  }
});

test('modal/focus gates and disposal never call the actual page owner', () => {
  for (const patch of [{modal: true}, {focused: false}, {enabled: false}]) {
    const h = harness(); Object.assign(h.context, patch); h.press(93);
    assert.equal(h.page, 2); assert.equal(h.invalidations, 0);
  }
  const h = harness(); h.controller.dispose(); h.press(93);
  assert.equal(h.page, 2); assert.equal(h.invalidations, 0);
});
