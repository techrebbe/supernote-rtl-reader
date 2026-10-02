'use strict';
// Deterministic tests of the actual pure T008 landscape annotation probe.
// No device, filesystem, timers, SDK runtime, or copied orchestration.
// Run: node scripts/test_annotation_preview_landscape.js
const test = require('node:test');
const assert = require('node:assert/strict');
const {
  FIXTURE_NAME, PAGE_INDEX, TOTAL_PAGES, WIDTH, HEIGHT,
  T008_PROFILE_ID, T008_PROFILE,
  createAnnotationPreviewProbe,
} = require('../overlay/annotationPreview');

const PROFILE_ID = 't008-page1-landscape-probe-v1';
const FILE = '/storage/emulated/0/Document/RTL_INK_GEOMETRY_T008_20261002.pdf';
const SOURCE_SHA = 'bd0fd00b4879cedb1b768a19deb2901a6d50dc7373decc8ef60e445613d83e64';
const TOKEN = 'f3d09692-3a12-48cb-823b-62041968c761';
const PNG = `/data/user/0/com.ratta.supernote.pluginhost/files/probe/${TOKEN}/ink.png`;
const OPTIONS = {enabled: true, profileId: PROFILE_ID};
const context = () => ({filePath: FILE, pageIndex: 0, totalPages: 2, orientation: 'landscape'});
const nativeSize = (width = 1404, height = 1872) => ({success: true, result: {width, height}});
const prepared = () => ({
  token: TOKEN, filePath: FILE, pageIndex: 0, pngPath: PNG,
  width: 1404, height: 1872, sourceVerified: true,
  sourceSha256: SOURCE_SHA, pageCount: 2,
});
const finished = () => ({
  ...prepared(), sourceUnchanged: true, markUnchanged: true, decoded: true,
  sha256: 'a'.repeat(64), byteLength: 1000, alphaMin: 0, alphaMax: 255,
});

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}

function harness(overrides = {}, options = OPTIONS) {
  const calls = [];
  let current = context();
  const defaults = {
    currentContext: async () => ({...current}),
    getPageSize: async () => nativeSize(),
    prepare: async () => prepared(),
    generateThumbnail: async () => ({success: true, result: true}),
    finish: async () => finished(),
    discard: async ({token}) => ({token, discarded: true}),
  };
  const deps = {};
  for (const name of Object.keys(defaults)) {
    deps[name] = async (...args) => {
      calls.push({name, args});
      return (overrides[name] || defaults[name])(...args);
    };
  }
  return {
    probe: createAnnotationPreviewProbe(deps, options), calls,
    change(patch) { current = {...current, ...patch}; },
    count(name) { return calls.filter(call => call.name === name).length; },
  };
}

async function enter(h, name, count = 1) {
  // Drain only promises, without a wall-clock timeout or background writer.
  for (let step = 0; step < 100 && h.count(name) < count; step += 1) await Promise.resolve();
  assert.equal(h.count(name), count, `${name} reached expected call ${count}`);
}

function noImage(result) {
  assert.equal(result.imageUri, undefined);
  assert.equal(result.geometryVerified, undefined);
}

test('T008 selection remains disabled by default and needs explicit manual consent', async () => {
  const disabled = harness({}, {profileId: PROFILE_ID});
  assert.deepEqual(await disabled.probe.run({manual: true}), {status: 'blocked', reason: 'disabled'});
  assert.equal(disabled.calls.length, 0);
  const h = harness();
  for (const manual of [undefined, false, 1, 'true']) {
    assert.deepEqual(await h.probe.run({manual}), {status: 'blocked', reason: 'manual_required'});
  }
  assert.equal(h.calls.length, 0);
});

test('T008 profile identity is immutable, explicit, and requires native page-size dependency', () => {
  assert.equal(T008_PROFILE_ID, PROFILE_ID);
  assert.deepEqual(T008_PROFILE, {filePath: FILE, pageIndex: 0, totalPages: 2, sourceSha256: SOURCE_SHA});
  assert.equal(Object.isFrozen(T008_PROFILE), true);
  assert.throws(() => { T008_PROFILE.pageIndex = 1; }, TypeError);
  const deps = {
    currentContext: async () => context(), prepare: async () => prepared(),
    generateThumbnail: async () => ({success: true, result: true}),
    finish: async () => finished(), discard: async ({token}) => ({token, discarded: true}),
  };
  assert.throws(() => createAnnotationPreviewProbe(deps, OPTIONS), /Missing probe dependency: getPageSize/);
  for (const profileId of ['t008-page1-stock-portrait-fit-v1', '', null, true]) {
    assert.throws(() => createAnnotationPreviewProbe(deps, {enabled: true, profileId}), /Unsupported diagnostic profile/);
  }
});

test('both stable nominal native pairs are observations; output stays canonical 1404x1872', async () => {
  for (const pair of [[1404, 1872], [1872, 1404]]) {
    const h = harness({getPageSize: async () => nativeSize(...pair)});
    const result = await h.probe.run({manual: true});
    assert.equal(result.status, 'preview', JSON.stringify(pair));
    assert.equal(result.imageUri, `file://${PNG}`);
    assert.equal(result.geometryVerified, false, 'native size is not alignment authority');
    assert.equal(result.annotationCompleteness, 'unknown');
    assert.deepEqual(h.calls.filter(call => call.name === 'getPageSize').map(call => call.args), [[FILE, 0], [FILE, 0]]);
    assert.deepEqual(h.calls.find(call => call.name === 'prepare').args, [{filePath: FILE, pageIndex: 0, width: 1404, height: 1872}]);
    assert.deepEqual(h.calls.find(call => call.name === 'generateThumbnail').args, [FILE, 0, PNG, {width: 1404, height: 1872}]);
    assert.deepEqual(h.calls.find(call => call.name === 'finish').args, [{token: TOKEN, missingMark: false}]);
    assert.deepEqual(result.evidence.nativePageSizeBefore, {width: pair[0], height: pair[1]});
    assert.deepEqual(result.evidence.nativePageSizeAfter, {width: pair[0], height: pair[1]});
    assert.equal(h.count('discard'), 0, 'successful output remains token-owned until dismissal');
    assert.deepEqual(await h.probe.run({manual: true}), {status: 'blocked', reason: 'preview_retained'});
    assert.deepEqual(await h.probe.release(result.handle), {status: 'released'});
    assert.equal(h.count('discard'), 1);
  }
});

test('native size evidence is copied and frozen, not supplied by finish or mutable dependencies', async () => {
  const before = nativeSize(1872, 1404);
  const after = nativeSize(1872, 1404);
  let reads = 0;
  const h = harness({
    getPageSize: async () => ++reads === 1 ? before : after,
    finish: async () => ({...finished(), nativePageSizeBefore: {width: 1, height: 2}, nativePageSizeAfter: {width: 3, height: 4}}),
  });
  const result = await h.probe.run({manual: true});
  assert.equal(result.status, 'preview');
  const savedBefore = result.evidence.nativePageSizeBefore;
  const savedAfter = result.evidence.nativePageSizeAfter;
  assert.notEqual(savedBefore, before.result);
  assert.notEqual(savedAfter, after.result);
  assert.equal(Object.isFrozen(savedBefore), true);
  assert.equal(Object.isFrozen(savedAfter), true);
  before.result.width = 1;
  after.result.height = 2;
  assert.deepEqual(savedBefore, {width: 1872, height: 1404});
  assert.deepEqual(savedAfter, {width: 1872, height: 1404});
  assert.throws(() => { savedBefore.width = 1; }, TypeError);
  assert.throws(() => { savedAfter.height = 2; }, TypeError);
  assert.equal(result.geometryVerified, false);
  await h.probe.release(result.handle);
});

test('T008 requires exact disposable fixture, first page, two pages, and explicit landscape', async () => {
  for (const patch of [
    {orientation: 'portrait'}, {orientation: undefined}, {orientation: null},
    {orientation: 'LANDSCAPE'}, {orientation: true}, {orientation: 1},
    {filePath: '/Document/RTL_INK_GEOMETRY_T008_20261002.pdf'},
    {filePath: `${FILE}.mark`}, {filePath: FILE.replace('/Document/', '/Document/../Document/')},
    {filePath: FILE.replace('/Document/', '/Document//')}, {filePath: FILE.replace('/Document/', '/Document/\u0000')},
    {pageIndex: 1}, {pageIndex: '0'}, {pageIndex: false}, {pageIndex: Infinity},
    {totalPages: 8}, {totalPages: '2'}, {totalPages: true}, {totalPages: NaN},
  ]) {
    const h = harness();
    h.change(patch);
    const result = await h.probe.run({manual: true});
    assert.equal(result.reason, 'fixture_context_required', JSON.stringify(patch));
    noImage(result);
    assert.equal(h.count('getPageSize'), 0);
    assert.equal(h.count('prepare'), 0);
    assert.equal(h.count('discard'), 0);
  }
});

const INVALID_SIZES = [
  null, undefined, {}, [], true,
  {success: false, result: {width: 1404, height: 1872}},
  {success: 'true', result: {width: 1404, height: 1872}},
  {success: true, result: null}, {success: true, result: []},
  {success: true, result: true}, {success: true, result: {}},
  nativeSize('1404', 1872), nativeSize(1404, '1872'),
  nativeSize(true, 1872), nativeSize(1404, false),
  nativeSize(NaN, 1872), nativeSize(1404, NaN),
  nativeSize(Infinity, 1872), nativeSize(1404, -Infinity),
  nativeSize(0, 1872), nativeSize(1403, 1872), nativeSize(1404, 1871),
  nativeSize(1404.5, 1872), nativeSize(1404, 1872.5),
  nativeSize(1404, 1404), nativeSize(1872, 1872), nativeSize(800, 600),
];

test('malformed, nonfinite, boolean, failed and non-nominal pre-size results fail closed before preparation', async () => {
  for (const size of INVALID_SIZES) {
    const h = harness({getPageSize: async () => size});
    const result = await h.probe.run({manual: true});
    assert.equal(result.status, 'error');
    assert.equal(result.reason, 'canvas_invalid', JSON.stringify(size));
    noImage(result);
    assert.equal(h.count('getPageSize'), 1);
    assert.equal(h.count('prepare'), 0);
    assert.equal(h.count('generateThumbnail'), 0);
    assert.equal(h.count('discard'), 0);
  }
});

test('bad post-size results suppress output, skip finish, and clean only the issued token', async () => {
  for (const size of INVALID_SIZES) {
    let reads = 0;
    const h = harness({getPageSize: async () => ++reads === 1 ? nativeSize() : size});
    const result = await h.probe.run({manual: true});
    assert.equal(result.reason, 'canvas_invalid', JSON.stringify(size));
    noImage(result);
    assert.equal(h.count('generateThumbnail'), 1);
    assert.equal(h.count('finish'), 0);
    assert.equal(h.count('discard'), 1);
    assert.deepEqual(h.calls.find(call => call.name === 'discard').args, [{token: TOKEN}]);
  }
});

test('native page-size rejections remain errors, with cleanup only after token issuance', async () => {
  for (const failAt of [1, 2]) {
    let reads = 0;
    const h = harness({getPageSize: async () => {
      if (++reads === failAt) throw new Error('native size failed');
      return nativeSize();
    }});
    const result = await h.probe.run({manual: true});
    assert.equal(result.status, 'error');
    assert.equal(result.reason, 'canvas_failed');
    noImage(result);
    assert.equal(h.count('prepare'), failAt === 1 ? 0 : 1);
    assert.equal(h.count('discard'), failAt === 1 ? 0 : 1);
  }
});

test('switching between the two nominal native pairs is a canvas change, not new output authority', async () => {
  for (const pairs of [[[1404, 1872], [1872, 1404]], [[1872, 1404], [1404, 1872]]]) {
    let reads = 0;
    const h = harness({getPageSize: async () => nativeSize(...pairs[reads++])});
    const result = await h.probe.run({manual: true});
    assert.equal(result.status, 'error');
    assert.equal(result.reason, 'canvas_changed');
    noImage(result);
    assert.equal(h.count('generateThumbnail'), 1);
    assert.equal(h.count('finish'), 0);
    assert.equal(h.count('discard'), 1);
  }
});

test('orientation and fixture changes at every awaited stage suppress the landscape preview', async () => {
  for (const [name, occurrence, patch] of [
    ['getPageSize', 1, {orientation: 'portrait'}],
    ['prepare', 1, {orientation: 'portrait'}],
    ['generateThumbnail', 1, {orientation: 'portrait'}],
    ['getPageSize', 2, {orientation: 'portrait'}],
    ['finish', 1, {orientation: 'portrait'}],
    ['generateThumbnail', 1, {filePath: '/storage/emulated/0/Document/other.pdf'}],
    ['finish', 1, {pageIndex: 1}], ['finish', 1, {totalPages: 3}],
  ]) {
    let h;
    let count = 0;
    h = harness({[name]: async () => {
      if (++count === occurrence) h.change(patch);
      if (name === 'getPageSize') return nativeSize();
      if (name === 'prepare') return prepared();
      if (name === 'finish') return finished();
      return {success: true, result: true};
    }});
    const result = await h.probe.run({manual: true});
    assert.equal(result.status, 'stale');
    assert.equal(result.reason, 'context_changed', `${name}:${occurrence}`);
    noImage(result);
    assert.equal(h.count('discard'), name === 'getPageSize' && occurrence === 1 ? 0 : 1);
    if (name === 'prepare') assert.equal(h.count('generateThumbnail'), 0);
    if (name === 'getPageSize' && occurrence === 2) assert.equal(h.count('finish'), 0);
  }
});

test('T008 prepare and finish require exact source SHA and numeric page-count attestation', async () => {
  for (const name of ['prepare', 'finish']) {
    for (const patch of [
      {sourceSha256: 'a'.repeat(64)}, {sourceSha256: SOURCE_SHA.toUpperCase()},
      {sourceSha256: undefined}, {sourceSha256: null}, {sourceSha256: true},
      {pageCount: 8}, {pageCount: '2'}, {pageCount: undefined},
      {pageCount: true}, {pageCount: NaN}, {pageCount: Infinity},
    ]) {
      const h = harness({[name]: async () => ({...(name === 'prepare' ? prepared() : finished()), ...patch})});
      const result = await h.probe.run({manual: true});
      assert.equal(result.reason, `${name}_invalid`, `${name}:${JSON.stringify(patch)}`);
      noImage(result);
      assert.equal(h.count('discard'), 1);
      if (name === 'prepare') assert.equal(h.count('generateThumbnail'), 0);
    }
  }
});

test('landscape native size never permits swapped or malformed prepared and decoded output dimensions', async () => {
  for (const name of ['prepare', 'finish']) {
    for (const patch of [{width: 1872, height: 1404}, {width: '1404'}, {height: true}, {width: NaN}]) {
      const h = harness({
        getPageSize: async () => nativeSize(1872, 1404),
        [name]: async () => ({...(name === 'prepare' ? prepared() : finished()), ...patch}),
      });
      const result = await h.probe.run({manual: true});
      assert.equal(result.reason, `${name}_invalid`);
      noImage(result);
      assert.equal(h.count('discard'), 1);
      if (name === 'prepare') assert.equal(h.count('generateThumbnail'), 0);
    }
  }
});

test('missing mark still needs source attestation and stable landscape observations before blank evidence', async () => {
  const h = harness({
    generateThumbnail: async () => ({success: false, error: {code: 1302}}),
    finish: async () => ({...finished(), missingMark: true}),
  });
  const result = await h.probe.run({manual: true});
  assert.equal(result.status, 'blank');
  assert.equal(result.reason, 'missing_mark_page');
  assert.equal(result.geometryVerified, false);
  assert.deepEqual(result.evidence.nativePageSizeBefore, {width: 1404, height: 1872});
  assert.deepEqual(result.evidence.nativePageSizeAfter, {width: 1404, height: 1872});
  assert.equal(Object.isFrozen(result.evidence.nativePageSizeBefore), true);
  assert.equal(Object.isFrozen(result.evidence.nativePageSizeAfter), true);
  assert.equal(result.imageUri, undefined);
  assert.equal(result.handle, undefined);
  assert.equal(h.count('discard'), 1);
  for (const patch of [{sourceSha256: 'a'.repeat(64)}, {pageCount: 8}]) {
    const bad = harness({
      generateThumbnail: async () => ({success: false, error: {code: 1302}}),
      finish: async () => ({...finished(), missingMark: true, ...patch}),
    });
    assert.equal((await bad.probe.run({manual: true})).reason, 'finish_invalid');
    assert.equal(bad.count('discard'), 1);
  }
});

test('cancel while pre-size is pending holds single-flight and prevents native token issuance', async () => {
  const size = deferred();
  const h = harness({getPageSize: () => size.promise});
  const request = h.probe.run({manual: true});
  await enter(h, 'getPageSize');
  h.probe.cancel();
  assert.deepEqual(await h.probe.run({manual: true}), {status: 'blocked', reason: 'busy'});
  assert.deepEqual(await h.probe.release({token: TOKEN}), {status: 'blocked', reason: 'busy'});
  assert.equal(h.count('prepare'), 0);
  assert.equal(h.count('discard'), 0);
  assert.equal(h.probe.getState().busy, true);
  size.resolve(nativeSize());
  assert.deepEqual(await request, {status: 'stale', reason: 'cancelled'});
  assert.equal(h.count('prepare'), 0);
  assert.equal(h.count('discard'), 0);
  assert.equal(h.probe.getState().busy, false);
});

test('cancel while post-size is pending retains its token until actual size settlement', async () => {
  const size = deferred();
  let reads = 0;
  const h = harness({getPageSize: () => ++reads === 1 ? nativeSize() : size.promise});
  const request = h.probe.run({manual: true});
  await enter(h, 'getPageSize', 2);
  h.probe.cancel();
  assert.equal(h.count('generateThumbnail'), 1);
  assert.equal(h.count('discard'), 0);
  assert.deepEqual(await h.probe.run({manual: true}), {status: 'blocked', reason: 'busy'});
  size.resolve(nativeSize());
  assert.deepEqual(await request, {status: 'stale', reason: 'cancelled'});
  assert.equal(h.count('finish'), 0);
  assert.equal(h.count('discard'), 1);
});

test('rotation ABA cancellation waits for actual SDK settlement, never cleaning a pending writer', async () => {
  const generation = deferred();
  const h = harness({generateThumbnail: () => generation.promise});
  const request = h.probe.run({manual: true});
  await enter(h, 'generateThumbnail');
  h.change({orientation: 'portrait'});
  h.probe.cancel();
  h.change({orientation: 'landscape'});
  assert.deepEqual(await h.probe.run({manual: true}), {status: 'blocked', reason: 'busy'});
  assert.deepEqual(await h.probe.release({token: TOKEN}), {status: 'blocked', reason: 'busy'});
  assert.equal(h.count('discard'), 0);
  assert.equal(h.count('getPageSize'), 1);
  assert.equal(h.probe.getState().busy, true);
  generation.resolve({success: true, result: true});
  assert.deepEqual(await request, {status: 'stale', reason: 'cancelled'});
  assert.equal(h.count('getPageSize'), 1, 'cancelled SDK output must not start a post-size query');
  assert.equal(h.count('finish'), 0);
  assert.equal(h.count('discard'), 1);
  assert.equal(h.probe.getState().busy, false);
});

test('a pending rejected SDK writer is also cleaned only after its actual rejection', async () => {
  const generation = deferred();
  const h = harness({generateThumbnail: () => generation.promise});
  const request = h.probe.run({manual: true});
  await enter(h, 'generateThumbnail');
  h.probe.cancel();
  assert.equal(h.count('discard'), 0);
  generation.reject(new Error('SDK writer failed'));
  const result = await request;
  assert.equal(result.status, 'error');
  assert.equal(result.reason, 'generate_failed');
  noImage(result);
  assert.equal(h.count('finish'), 0);
  assert.equal(h.count('discard'), 1);
});

test('cancel during finish waits for attestation settlement and suppresses checked evidence', async () => {
  const finishing = deferred();
  const h = harness({finish: () => finishing.promise});
  const request = h.probe.run({manual: true});
  await enter(h, 'finish');
  h.probe.cancel();
  assert.equal(h.count('discard'), 0);
  finishing.resolve(finished());
  assert.deepEqual(await request, {status: 'stale', reason: 'cancelled'});
  assert.equal(h.count('discard'), 1);
});

test('cleanup failure retains a single explicit retry capability and blocks overlapping SDK work', async () => {
  let fail = true;
  const h = harness({
    getPageSize: async () => nativeSize(1872, 1404),
    generateThumbnail: async () => ({success: true, result: false}),
    discard: async ({token}) => {
      if (fail) throw new Error('cleanup failed');
      return {token, discarded: true};
    },
  });
  const result = await h.probe.run({manual: true});
  assert.equal(result.reason, 'cleanup_failed');
  assert.equal(result.causeReason, 'generation_failed');
  assert.equal(h.count('discard'), 1);
  assert.equal(h.probe.getState().retained, true);
  assert.deepEqual(await h.probe.run({manual: true}), {status: 'blocked', reason: 'preview_retained'});
  assert.equal((await h.probe.release({...result.handle})).reason, 'unknown_handle');
  fail = false;
  assert.deepEqual(await h.probe.release(result.handle), {status: 'released'});
  assert.equal(h.count('discard'), 2);
  assert.equal(h.probe.getState().retained, false);
});

test('successful preview release is identity-bound and holds single-flight through native cleanup', async () => {
  const cleanup = deferred();
  const h = harness({discard: () => cleanup.promise});
  const result = await h.probe.run({manual: true});
  assert.equal((await h.probe.release({token: TOKEN})).reason, 'unknown_handle');
  assert.equal(h.count('discard'), 0);
  const releasing = h.probe.release(result.handle);
  assert.deepEqual(await h.probe.run({manual: true}), {status: 'blocked', reason: 'busy'});
  assert.deepEqual(await h.probe.release(result.handle), {status: 'blocked', reason: 'busy'});
  assert.equal(h.count('discard'), 1);
  cleanup.resolve({token: TOKEN, discarded: true});
  assert.deepEqual(await releasing, {status: 'released'});
  assert.equal((await h.probe.release(result.handle)).reason, 'unknown_handle');
  assert.equal(h.count('discard'), 1);
});

test('T004 exported defaults and native contract stay independent of the selected landscape profile', async () => {
  assert.equal(FIXTURE_NAME, 'RTL_RAPID_TOOLS_T004_20261001.pdf');
  assert.equal(PAGE_INDEX, 2);
  assert.equal(TOTAL_PAGES, 8);
  assert.equal(WIDTH, 1404);
  assert.equal(HEIGHT, 1872);
  const file = `/storage/emulated/0/Document/${FIXTURE_NAME}`;
  const oldPrepared = {token: TOKEN, filePath: file, pageIndex: 2, pngPath: PNG, width: 1404, height: 1872, sourceVerified: true};
  let sizeCalls = 0;
  const deps = {
    currentContext: async () => ({filePath: file, pageIndex: 2, totalPages: 8}),
    getPageSize: async () => { sizeCalls += 1; throw new Error('T004 must not observe a canvas'); },
    prepare: async args => {
      assert.deepEqual(args, {filePath: file, pageIndex: 2, width: 1404, height: 1872});
      return oldPrepared;
    },
    generateThumbnail: async () => ({success: true, result: true}),
    finish: async () => ({...oldPrepared, sourceUnchanged: true, markUnchanged: true, decoded: true, sha256: 'a'.repeat(64), byteLength: 1000, alphaMin: 0, alphaMax: 255}),
    discard: async ({token}) => ({token, discarded: true}),
  };
  const probe = createAnnotationPreviewProbe(deps, {enabled: true});
  const result = await probe.run({manual: true});
  assert.equal(result.status, 'preview');
  assert.equal(result.evidence.nativePageSizeBefore, undefined);
  assert.equal(result.evidence.nativePageSizeAfter, undefined);
  assert.equal(sizeCalls, 0);
  await probe.release(result.handle);
  delete deps.getPageSize;
  assert.doesNotThrow(() => createAnnotationPreviewProbe(deps, {enabled: true}), 'T004 keeps its existing dependency set');
});
