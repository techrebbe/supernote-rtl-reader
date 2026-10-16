'use strict';
const assert = require('node:assert/strict');
const {test} = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {handoffSavedPage} = require('../overlay/sdkPageHandoff');
const target = {filePath: '/Document/test.pdf', pageIndex: 1, requestId: 'one-shot'};
const ok = result => ({success: true, result});
function harness(options = {}) {
  const calls = [];
  let page = 0, current = true;
  const paths = [...(options.paths ?? [])];
  const counts = [...(options.counts ?? [])];
  const pages = [...(options.pages ?? [])];
  const validations = [...(options.validations ?? [])];
  const args = {
    isCurrent: () => current,
    expected: options.expected ?? {...target, totalPages: 2},
    waitForConfirmation: async ms => {
      calls.push(['wait', ms]);
      if (options.onWait) await options.onWait(() => {current = false;});
    },
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
      async getCurrentPageNum() {calls.push('page'); return pages.length ? pages.shift() : options.afterPage ?? ok(page);},
      async jumpToPage(index) {
        calls.push(['jump', index]); page = index;
        if (options.unmountOnJump) current = false;
        return options.jump ?? ok(true);
      },
    },
    doc: {async getCurrentTotalPages() {calls.push('count'); return counts.length ? counts.shift() : ok(2);}},
  };
  return {args, calls, run: () => (options.route ?? handoffSavedPage)(args)};
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

test('one acknowledged SDK jump can settle after its first read without another mutation', async () => {
  const h = harness({pages: [ok(0), ok(0), ok(1)]});
  assert.equal((await h.run()).navigation, 'sdk-verified');
  assert.equal(h.calls.filter(call => Array.isArray(call) && call[0] === 'jump').length, 1);
  assert.equal(h.calls.filter(call => call === 'page').length, 3);
  assert.deepEqual(h.calls.filter(call => Array.isArray(call) && call[0] === 'wait'),
    [['wait', 100], ['wait', 100]]);
});

test('unconfirmed SDK position is bounded and includes numeric evidence, never a second jump', async () => {
  const h = harness({afterPage: ok(0)});
  await assert.rejects(h.run(), /did not confirm.*expected=1 observed=0 count=2 attempts=8/);
  assert.equal(h.calls.filter(call => call === 'page').length, 8);
  assert.equal(h.calls.filter(call => Array.isArray(call) && call[0] === 'wait').length, 7);
  assert.equal(h.calls.filter(call => Array.isArray(call) && call[0] === 'jump').length, 1);
});

test('deferred confirmation revalidates document, count and prepared source at each observation', async () => {
  const valid = harness({pages: [ok(0), ok(1)]});
  await valid.run();
  assert.deepEqual(valid.calls.slice(-5), ['file', 'page', 'count', ['validate', 'one-shot'], 'file']);
  const changedFile = harness({pages: [ok(0), ok(1)], paths: [
    ok(target.filePath), ok(target.filePath), ok(target.filePath), ok(target.filePath), ok('/Document/other.pdf'),
  ]});
  await assert.rejects(changedFile.run(), /document changed/);
  assert.equal(changedFile.calls.filter(call => call === 'page').length, 1);
  const changedCount = harness({pages: [ok(0), ok(1)], counts: [ok(2), ok(2), ok(3)]});
  await assert.rejects(changedCount.run(), /page count changed/);
  const replaced = harness({pages: [ok(0), ok(1)], validations: [true, true, false]});
  await assert.rejects(replaced.run(), /source PDF changed/);
});

for (const page of [-1, 2, '1', null, NaN]) {
  test(`invalid post-jump position ${page} fails immediately instead of waiting`, async () => {
    const h = harness({afterPage: ok(page)});
    await assert.rejects(h.run(), /invalid page/);
    assert.ok(!h.calls.some(call => Array.isArray(call) && call[0] === 'wait'));
  });
}

test('SDK read failure during delayed confirmation is terminal', async () => {
  const h = harness({pages: [ok(0), {success: false, error: {message: 'page unavailable'}}]});
  await assert.rejects(h.run(), /page unavailable/);
  assert.equal(h.calls.filter(call => call === 'page').length, 2);
});

test('unmount after dispatch permits only bounded read-only confirmation', async () => {
  const h = harness({pages: [ok(0), ok(1)], onWait: retire => retire()});
  assert.equal((await h.run()).navigation, 'sdk-verified');
  assert.equal(h.calls.filter(call => Array.isArray(call) && call[0] === 'jump').length, 1);
  assert.ok(!h.calls.some(call => call === 'close' || call === 'restart' || call === 'save'));
});

test('the last permitted observation can confirm; no later observation is allowed', async () => {
  const h = harness({pages: [...Array.from({length: 7}, () => ok(0)), ok(1)]});
  assert.equal((await h.run()).navigation, 'sdk-verified');
  assert.equal(h.calls.filter(call => call === 'page').length, 8);
  assert.equal(h.calls.filter(call => Array.isArray(call) && call[0] === 'wait').length, 7);
});

test('actual default timer permits an asynchronous SDK visibility callback, not an immediate setter witness', async () => {
  let visible = 0;
  const waits = [];
  const source = fs.readFileSync(path.join(__dirname, '../overlay/sdkPageHandoff.js'), 'utf8');
  const context = vm.createContext({module: {exports: {}}, setTimeout(callback, ms) {
    waits.push(ms);
    queueMicrotask(() => {visible = 1; callback();});
  }});
  vm.runInContext(source, context);
  const h = harness({route: context.module.exports.handoffSavedPage});
  delete h.args.waitForConfirmation;
  h.args.comm.getCurrentPageNum = async () => {h.calls.push('page'); return ok(visible);};
  assert.equal((await h.run()).navigation, 'sdk-verified');
  assert.deepEqual(waits, [100]);
  assert.equal(h.calls.filter(call => call === 'page').length, 2);
  assert.equal(h.calls.filter(call => Array.isArray(call) && call[0] === 'jump').length, 1);
});

test('invalid count diagnostics cannot emit arbitrary SDK payload content', async () => {
  const h = harness({counts: [ok(2), ok('/private/document-name')]});
  await assert.rejects(h.run(), error => {
    assert.match(error.message, /page count changed expected=2 observed=invalid/);
    assert.ok(!error.message.includes('/private/'));
    return true;
  });
  assert.ok(!h.calls.some(call => Array.isArray(call) && call[0] === 'wait'));
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
