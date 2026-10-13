'use strict';
const assert = require('node:assert/strict');
const {test} = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const {handoffSavedPage} = require('../overlay/sdkPageHandoff');
const target = {filePath: '/Document/test.pdf', pageIndex: 1, requestId: 'one-shot'};
const ok = result => ({success: true, result});
function harness(options = {}) {
  const calls = [];
  let page = 0, current = true;
  const paths = [...(options.paths ?? [])];
  const counts = [...(options.counts ?? [])];
  const validations = [...(options.validations ?? [])];
  const args = {
    isCurrent: () => current,
    expected: options.expected ?? {...target, totalPages: 2},
    preferences: {
      async handoffLastSavedPage() {
        calls.push('prepare');
        if (options.prepare) return options.prepare(() => {current = false;});
        return options.target === undefined ? target : options.target;
      },
      async validatePreparedPageHandoff(id) {
        calls.push(['validate', id]);
        const value = validations.length ? validations.shift() : true;
        if (value instanceof Error) throw value;
        return value;
      },
    },
    comm: {
      async getCurrentFilePath() {calls.push('file'); return paths.length ? paths.shift() : ok(target.filePath);},
      async getCurrentPageNum() {calls.push('page'); return options.afterPage ?? ok(page);},
      async jumpToPage(index) {
        calls.push(['jump', index]); page = index;
        if (options.unmountOnJump) current = false;
        return options.jump ?? ok(true);
      },
    },
    doc: {async getCurrentTotalPages() {calls.push('count'); return counts.length ? counts.shift() : ok(2);}},
  };
  return {args, calls, run: () => handoffSavedPage(args)};
}
test('actual shared route jumps once and verifies exact document, source, count and page', async () => {
  const h = harness();
  assert.equal((await h.run()).navigation, 'sdk-verified');
  assert.deepEqual(h.calls, ['prepare', 'file', 'count', ['validate', 'one-shot'], 'file',
    ['jump', 1], 'file', 'page', 'count', ['validate', 'one-shot'], 'file']);
});
for (const bad of [null, {}, {...target, pageIndex: -1}, {...target, pageIndex: '1'},
  {...target, requestId: null}, {...target, annotationRecovery: true},
  {...target, filePath: '/Document/other.pdf'}, {...target, pageIndex: 0}]) {
  test(`invalid/recovery/mismatched prepared target never navigates: ${JSON.stringify(bad)}`, async () => {
    const h = harness({target: bad}); await assert.rejects(h.run());
    assert.deepEqual(h.calls, ['prepare']);
  });
}
for (const count of [0, 1, 3, '2', null]) {
  test(`invalid/changed page count ${count} never navigates`, async () => {
    const h = harness({counts: [ok(count)]}); await assert.rejects(h.run());
    assert.ok(!h.calls.some(call => Array.isArray(call) && call[0] === 'jump'));
  });
}
for (const position of [0, 1, 2, 3]) {
  test(`document change at SDK check ${position} rejects without wrong-document success`, async () => {
    const paths = Array.from({length: position}, () => ok(target.filePath));
    paths.push(ok('/Document/other.pdf'));
    const h = harness({paths}); await assert.rejects(h.run(), /document changed/);
    assert.equal(h.calls.filter(call => Array.isArray(call) && call[0] === 'jump').length,
      position >= 2 ? 1 : 0);
  });
}
for (const jump of [ok(false), ok('true'), {success: false, error: {message: 'native refused'}}]) {
  test(`SDK setter rejection ${JSON.stringify(jump)} is not success`, async () => {
    await assert.rejects(harness({jump}).run());
  });
}
test('wrong post-jump page and changed post-jump count fail even after true setter success', async () => {
  await assert.rejects(harness({afterPage: ok(0)}).run(), /did not confirm/);
  await assert.rejects(harness({counts: [ok(2), ok(3)]}).run(), /did not confirm/);
});
test('replaced source/stale prefs fail at either native verification', async () => {
  const before = harness({validations: [new Error('source changed')]});
  await assert.rejects(before.run());
  assert.ok(!before.calls.some(call => Array.isArray(call) && call[0] === 'jump'));
  await assert.rejects(harness({validations: [true, false]}).run(), /source PDF changed/);
});
test('unmount before dispatch cancels; after dispatch only read-only verification completes', async () => {
  const before = harness({prepare: retire => {retire(); return target;}});
  await assert.rejects(before.run(), /owner changed/);
  assert.deepEqual(before.calls, ['prepare']);
  const after = harness({unmountOnJump: true});
  assert.equal((await after.run()).navigation, 'sdk-verified');
  assert.equal(after.calls.filter(call => Array.isArray(call) && call[0] === 'jump').length, 1);
});
test('packaged Edit/Close share the route; live native preparation cannot touch private CONFIG/restart', () => {
  const root = path.resolve(__dirname, '..');
  const native = fs.readFileSync(path.join(root, 'native/ReaderPreferencesModule.kt.template'), 'utf8');
  const live = native.slice(native.indexOf('fun handoffLastSavedPage('), native.indexOf('private fun findMatchingConfig('));
  assert.ok(!/findMatchingConfig\(|readConfigMap\(|writeBytesSynced\(|scheduleDocumentRestart\(|Os\.kill\(/.test(live));
  for (const marker of ['validatePreparedPageHandoff', 'preparedPageHandoff === prepared',
    'samePersistedFileVersion', 'O_NOFOLLOW', 'inspectNativeMarkRecoveryFence(pdfFile).blocking']) {
    assert.ok(live.includes(marker), marker);
  }
  const build = fs.readFileSync(path.join(root, 'build.sh'), 'utf8');
  assert.ok(build.includes('cp "$ROOT/overlay/sdkPageHandoff.js" "$PROJECT/sdkPageHandoff.js"'));
  for (const file of ['App.js', 'index.js']) {
    const text = fs.readFileSync(path.join(root, 'overlay', file), 'utf8');
    assert.ok(text.includes("from './sdkPageHandoff'"));
    assert.ok(!text.includes('await ReaderPreferencesModule.handoffLastSavedPage()'));
  }
});
