'use strict';
// In-memory mutations of the actual controller; no device or file writes.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../overlay/pageTurnerKeys.js'), 'utf8');

function verify(text) {
  const sandbox = {module: {exports: {}}};
  vm.runInNewContext(text, sandbox, {timeout: 1000});
  for (const direction of ['rtl', 'ltr']) {
    const turns = [];
    const context = {activationId: 'test', documentId: '/disposable.pdf',
      enabled: true, focused: true, blocked: false, direction};
    const keys = sandbox.module.exports.createPageTurnerKeys({currentContext: () => context,
      turn: action => turns.push(action)});
    for (const keyCode of [19, 20]) {
      const event = {activationId: context.activationId, documentId: context.documentId,
        keyCode, deviceId: 3, downTime: keyCode, repeatCount: 0, action: 0};
      assert.equal(keys.handle(event).handled, true);
      keys.handle({...event, repeatCount: 256});
      assert.equal(keys.handle({...event, action: 1}).handled, true);
    }
    assert.deepEqual(turns, ['previous', 'next']);
  }
}

test('actual vertical mapping passes and four omission/reversal mutations are rejected', () => {
  verify(source);
  for (const [before, after] of [
    ["19: 'previous', ", ''], ["20: 'next', ", ''],
    ["19: 'previous'", "19: 'next'"], ["20: 'next'", "20: 'previous'"],
  ]) {
    assert.equal(source.split(before).length, 2, 'Mutation anchor must be unique');
    assert.throws(() => verify(source.replace(before, after)), assert.AssertionError);
  }
});
