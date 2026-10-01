'use strict';
// Deterministic tests of the actual pure annotation probe. No device/files/API.
// Run: node scripts/test_annotation_preview.js
const test = require('node:test');
const assert = require('node:assert/strict');
const {
  FIXTURE_NAME, PAGE_INDEX, TOTAL_PAGES, WIDTH, HEIGHT, MAX_PNG_BYTES,
  createAnnotationPreviewProbe,
} = require('../overlay/annotationPreview');

const TOKEN = 'f3d09692-3a12-48cb-823b-62041968c761';
const FILE = `/storage/emulated/0/Document/${FIXTURE_NAME}`;
const PNG = `/data/user/0/com.ratta.supernote.pluginhost/files/probe/${TOKEN}/ink.png`;
const context = () => ({filePath: FILE, pageIndex: PAGE_INDEX, totalPages: TOTAL_PAGES});
const prepared = () => ({token: TOKEN, filePath: FILE, pageIndex: PAGE_INDEX, pngPath: PNG, width: WIDTH, height: HEIGHT, sourceVerified: true});
const checked = () => ({
  ...prepared(), sourceUnchanged: true, markUnchanged: true, decoded: true,
  sha256: 'a'.repeat(64), byteLength: 1000, alphaMin: 0, alphaMax: 255,
});

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}

function harness(overrides = {}, options = {enabled: true}) {
  const calls = [];
  let current = context();
  const defaults = {
    currentContext: async () => ({...current}),
    prepare: async () => prepared(),
    generateThumbnail: async () => ({success: true, result: true}),
    finish: async () => checked(),
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
    change(value) { current = {...current, ...value}; },
    count(name) { return calls.filter(call => call.name === name).length; },
  };
}

async function enterGenerate(h) {
  // No wall-clock waiting: just drain the deterministic promise pipeline.
  for (let step = 0; step < 20 && h.count('generateThumbnail') === 0; step += 1) await Promise.resolve();
  assert.equal(h.count('generateThumbnail'), 1);
}

test('default is disabled and every request needs explicit manual consent', async () => {
  const h = harness({}, {});
  assert.deepEqual(await h.probe.run({manual: true}), {status: 'blocked', reason: 'disabled'});
  assert.equal(h.calls.length, 0);
  const enabled = harness();
  for (const manual of [undefined, false, 1, 'true']) {
    assert.deepEqual(await enabled.probe.run({manual}), {status: 'blocked', reason: 'manual_required'});
  }
  assert.equal(enabled.calls.length, 0);
});

test('uses exact original PDF / zero-based page / fixed dimensions and checked evidence', async () => {
  const h = harness();
  const result = await h.probe.run({manual: true});
  assert.equal(result.status, 'preview');
  assert.equal(result.imageUri, `file://${PNG}`);
  assert.equal(result.geometryVerified, false);
  assert.equal(result.annotationCompleteness, 'unknown');
  assert.deepEqual(h.calls.find(call => call.name === 'prepare').args, [{filePath: FILE, pageIndex: 2, width: 1404, height: 1872}]);
  assert.deepEqual(h.calls.find(call => call.name === 'generateThumbnail').args, [FILE, 2, PNG, {width: 1404, height: 1872}]);
  assert.deepEqual(h.calls.find(call => call.name === 'finish').args, [{token: TOKEN, missingMark: false}]);
  assert.equal(h.count('currentContext'), 4);
  assert.equal(h.count('discard'), 0, 'successful PNG is held until explicit dismissal');
  assert.deepEqual(await h.probe.run({manual: true}), {status: 'blocked', reason: 'preview_retained'});
  assert.deepEqual(await h.probe.release(result.handle), {status: 'released'});
  assert.deepEqual(h.calls.at(-1).args, [{token: TOKEN}]);
  assert.equal(h.probe.getState().retained, false);
});

test('requires every dependency but imports no device or filesystem runtime', () => {
  assert.throws(() => createAnnotationPreviewProbe({}), /Missing probe dependency/);
});

test('rejects all nonfixture, wrong page/count and malformed initial identities before native work', async () => {
  for (const patch of [
    {filePath: '/Document/personal.pdf'}, {filePath: `${FILE}.mark`},
    {filePath: `relative/${FIXTURE_NAME}`}, {filePath: `/Document/../${FIXTURE_NAME}`},
    {filePath: `/Document//${FIXTURE_NAME}`}, {filePath: `/Document/\u0000${FIXTURE_NAME}`},
    {pageIndex: 1}, {pageIndex: '2'}, {pageIndex: -1}, {pageIndex: 2.5},
    {totalPages: 7}, {totalPages: '8'}, {totalPages: Infinity},
  ]) {
    const h = harness(); h.change(patch);
    assert.equal((await h.probe.run({manual: true})).reason, 'fixture_context_required');
    assert.equal(h.count('prepare'), 0, JSON.stringify(patch));
  }
});

test('strict native prepare contract rejects bad bounds/identity/path and cleans only its issued token', async () => {
  for (const patch of [
    {filePath: '/Document/other.pdf'}, {pageIndex: 3}, {pageIndex: '2'},
    {width: 1403}, {height: 1871}, {width: '1404'}, {height: Infinity},
    {sourceVerified: false}, {sourceVerified: 'true'},
    {pngPath: `/sdcard/${TOKEN}/ink.png`}, {pngPath: `${PNG}.png`},
    {pngPath: PNG.replace('/probe/', '/probe/../')}, {pngPath: PNG.replace('/probe/', '/probe//')},
    {pngPath: PNG.replace(TOKEN, 'e3d09692-3a12-48cb-823b-62041968c761')},
  ]) {
    const h = harness({prepare: async () => ({...prepared(), ...patch})});
    assert.equal((await h.probe.run({manual: true})).reason, 'prepare_invalid');
    assert.equal(h.count('generateThumbnail'), 0);
    assert.deepEqual(h.calls.find(call => call.name === 'discard').args, [{token: TOKEN}]);
  }
});

test('invalid tokens never reach a cleanup API or raw output path', async () => {
  for (const token of [null, '', 'some-token', `${TOKEN} `, TOKEN.toUpperCase(), '../ink.png']) {
    const h = harness({prepare: async () => ({...prepared(), token})});
    assert.equal((await h.probe.run({manual: true})).reason, 'prepare_invalid');
    assert.equal(h.count('discard'), 0);
    assert.equal(h.count('generateThumbnail'), 0);
  }
});

test('requires success AND result true; non1302 errors are never interpreted as blank', async () => {
  for (const api of [
    null, {}, {success: true, result: false}, {success: true, result: 1},
    {success: 'true', result: true}, {success: false, result: true},
    {success: false, error: {code: 1201}}, {success: false, error: {code: '1302'}},
    {success: true, result: false, error: {code: 1302}},
  ]) {
    const h = harness({generateThumbnail: async () => api});
    const result = await h.probe.run({manual: true});
    assert.equal(result.reason, 'generation_failed');
    assert.equal(h.count('finish'), 0);
    assert.equal(h.count('discard'), 1);
  }
});

test('1302 becomes explicitly blank ONLY after native unchanged-source attestation', async () => {
  const h = harness({
    generateThumbnail: async () => ({success: false, error: {code: 1302}}),
    finish: async () => ({token: TOKEN, filePath: FILE, pageIndex: PAGE_INDEX, sourceUnchanged: true, markUnchanged: true, missingMark: true}),
  });
  const result = await h.probe.run({manual: true});
  assert.equal(result.status, 'blank');
  assert.equal(result.reason, 'missing_mark_page');
  assert.equal(result.imageUri, undefined);
  assert.equal(result.handle, undefined);
  assert.equal(h.count('discard'), 1);
  assert.deepEqual(h.calls.find(call => call.name === 'finish').args, [{token: TOKEN, missingMark: true}]);
  for (const patch of [{sourceUnchanged: false}, {markUnchanged: false}, {missingMark: false}, {missingMark: 'true'}]) {
    const bad = harness({generateThumbnail: async () => ({success: false, error: {code: 1302}}), finish: async () => ({...checked(), missingMark: true, ...patch})});
    assert.equal((await bad.probe.run({manual: true})).reason, 'finish_invalid');
    assert.equal(bad.count('discard'), 1);
  }
});

test('strict finish checks source/mark identity and bounded decoded PNG evidence', async () => {
  for (const patch of [
    {token: 'e3d09692-3a12-48cb-823b-62041968c761'}, {filePath: '/Document/other.pdf'}, {pageIndex: 3},
    {sourceUnchanged: false}, {sourceUnchanged: 'true'}, {markUnchanged: false},
    {missingMark: true}, {pngPath: `${PNG}.other`}, {width: 1403}, {height: '1872'}, {decoded: false},
    {sha256: 'a'.repeat(63)}, {sha256: 'A'.repeat(64)}, {sha256: null},
    {byteLength: 0}, {byteLength: 1.5}, {byteLength: MAX_PNG_BYTES + 1}, {byteLength: '1000'},
    {alphaMin: -1}, {alphaMax: 256}, {alphaMin: 200, alphaMax: 100},
    {alphaMin: 0.5}, {alphaMax: '255'},
  ]) {
    const h = harness({finish: async () => ({...checked(), ...patch})});
    const result = await h.probe.run({manual: true});
    assert.equal(result.reason, 'finish_invalid', JSON.stringify(patch));
    assert.equal(result.imageUri, undefined);
    assert.equal(h.count('discard'), 1);
  }
  const boundary = harness({finish: async () => ({...checked(), byteLength: MAX_PNG_BYTES, alphaMin: 255, alphaMax: 255})});
  assert.equal((await boundary.probe.run({manual: true})).status, 'preview', 'opaque output is evidence, not assumed transparent');
});

test('context changes after prepare reject before thumbnail API', async () => {
  let h;
  h = harness({prepare: async () => { h.change({pageIndex: 3}); return prepared(); }});
  const result = await h.probe.run({manual: true});
  assert.equal(result.status, 'stale');
  assert.equal(result.reason, 'context_changed');
  assert.equal(h.count('generateThumbnail'), 0);
  assert.equal(h.count('discard'), 1);
});

test('context changes after thumbnail reject before finish', async () => {
  let h;
  h = harness({generateThumbnail: async () => { h.change({filePath: '/Document/other.pdf'}); return {success: true, result: true}; }});
  const result = await h.probe.run({manual: true});
  assert.equal(result.reason, 'context_changed');
  assert.equal(h.count('finish'), 0);
  assert.equal(h.count('discard'), 1);
});

test('context changes during finish suppress otherwise checked image', async () => {
  let h;
  h = harness({finish: async () => { h.change({pageIndex: 3}); return checked(); }});
  const result = await h.probe.run({manual: true});
  assert.equal(result.reason, 'context_changed');
  assert.equal(result.imageUri, undefined);
  assert.equal(h.count('discard'), 1);
});

test('cancellation and single-flight retain pending API output until it actually completes', async () => {
  const generation = deferred();
  const h = harness({generateThumbnail: () => generation.promise});
  const request = h.probe.run({manual: true});
  await enterGenerate(h);
  h.probe.cancel();
  assert.deepEqual(await h.probe.run({manual: true}), {status: 'blocked', reason: 'busy'});
  assert.deepEqual(await h.probe.release({token: TOKEN}), {status: 'blocked', reason: 'busy'});
  assert.equal(h.count('discard'), 0, 'never remove a PNG while the unresolved API may write it');
  assert.equal(h.probe.getState().busy, true);
  generation.resolve({success: true, result: true});
  assert.deepEqual(await request, {status: 'stale', reason: 'cancelled'});
  assert.equal(h.count('finish'), 0);
  assert.equal(h.count('discard'), 1);
  assert.equal(h.probe.getState().busy, false);
});

test('cancel during prepare cleans issued token but cannot generate', async () => {
  const preparation = deferred();
  const h = harness({prepare: () => preparation.promise});
  const request = h.probe.run({manual: true});
  for (let step = 0; step < 10 && h.count('prepare') === 0; step += 1) await Promise.resolve();
  h.probe.cancel();
  assert.equal(h.count('discard'), 0);
  preparation.resolve(prepared());
  assert.equal((await request).reason, 'cancelled');
  assert.equal(h.count('generateThumbnail'), 0);
  assert.equal(h.count('discard'), 1);
});

test('away-and-back context transitions invalidate via cancellation epoch', async () => {
  const generation = deferred();
  const h = harness({generateThumbnail: () => generation.promise});
  const request = h.probe.run({manual: true});
  await enterGenerate(h);
  h.change({pageIndex: 3}); h.probe.cancel(); h.change({pageIndex: 2});
  generation.resolve({success: true, result: true});
  assert.equal((await request).reason, 'cancelled');
  assert.equal(h.count('finish'), 0);
});

test('dependency failures remain errors; native token cleanup follows actual completion', async () => {
  for (const name of ['prepare', 'generateThumbnail', 'finish']) {
    const h = harness({[name]: async () => { throw new Error('native failed'); }});
    const result = await h.probe.run({manual: true});
    assert.equal(result.status, 'error');
    assert.equal(result.reason, `${name === 'generateThumbnail' ? 'generate' : name}_failed`);
    assert.equal(h.count('discard'), name === 'prepare' ? 0 : 1);
  }
  let h;
  h = harness({currentContext: async () => { if (h.count('currentContext') > 1) throw new Error('context failed'); return context(); }});
  assert.equal((await h.probe.run({manual: true})).status, 'error');
  assert.equal(h.count('discard'), 1);
});

test('failed cleanup blocks further probe and provides only a tracked explicit retry handle', async () => {
  let fail = true;
  const h = harness({
    generateThumbnail: async () => ({success: true, result: false}),
    discard: async ({token}) => { if (fail) throw new Error('cleanup failed'); return {token, discarded: true}; },
  });
  const result = await h.probe.run({manual: true});
  assert.equal(result.reason, 'cleanup_failed');
  assert.equal(result.causeReason, 'generation_failed');
  assert.deepEqual(await h.probe.run({manual: true}), {status: 'blocked', reason: 'preview_retained'});
  assert.equal((await h.probe.release({...result.handle})).reason, 'unknown_handle');
  fail = false;
  assert.deepEqual(await h.probe.release(result.handle), {status: 'released'});
});

test('native cleanup must explicitly attest matching token and completed discard', async () => {
  for (const response of [null, {}, {token: TOKEN, discarded: false}, {token: TOKEN, discarded: 'true'}, {token: 'other', discarded: true}]) {
    const h = harness({discard: async () => response});
    const preview = await h.probe.run({manual: true});
    assert.equal((await h.probe.release(preview.handle)).reason, 'cleanup_failed');
    assert.equal(h.probe.getState().retained, true);
  }
});

test('successful native preview cannot be released by a forged or already-released handle', async () => {
  const h = harness();
  const preview = await h.probe.run({manual: true});
  assert.equal((await h.probe.release({token: TOKEN})).reason, 'unknown_handle');
  assert.equal(h.count('discard'), 0);
  assert.equal((await h.probe.release(preview.handle)).status, 'released');
  assert.equal((await h.probe.release(preview.handle)).reason, 'unknown_handle');
  assert.equal(h.count('discard'), 1);
});

test('blank cleanup failure is reported once without an automatic duplicate discard', async () => {
  const h = harness({
    generateThumbnail: async () => ({success: false, error: {code: 1302}}),
    finish: async () => ({...checked(), missingMark: true}),
    discard: async () => { throw new Error('cleanup failed'); },
  });
  const result = await h.probe.run({manual: true});
  assert.equal(result.reason, 'cleanup_failed');
  assert.equal(result.status, 'error');
  assert.equal(result.imageUri, undefined);
  assert.equal(h.count('discard'), 1);
  assert.equal(h.probe.getState().retained, true);
});

test('blank result is suppressed if context changes during cleanup', async () => {
  let h;
  h = harness({
    generateThumbnail: async () => ({success: false, error: {code: 1302}}),
    finish: async () => ({...checked(), missingMark: true}),
    discard: async ({token}) => { h.change({pageIndex: 3}); return {token, discarded: true}; },
  });
  const result = await h.probe.run({manual: true});
  assert.equal(result.status, 'stale');
  assert.equal(result.reason, 'context_changed');
  assert.equal(h.count('discard'), 1);
  assert.equal(h.probe.getState().retained, false);
});

test('release also holds single-flight until native discard settles', async () => {
  const cleanup = deferred();
  const h = harness({discard: () => cleanup.promise});
  const preview = await h.probe.run({manual: true});
  const release = h.probe.release(preview.handle);
  assert.deepEqual(await h.probe.run({manual: true}), {status: 'blocked', reason: 'busy'});
  assert.deepEqual(await h.probe.release(preview.handle), {status: 'blocked', reason: 'busy'});
  assert.equal(h.count('discard'), 1);
  cleanup.resolve({token: TOKEN, discarded: true});
  assert.deepEqual(await release, {status: 'released'});
});

test('cancellation during finish suppresses checked evidence and cleans exactly once', async () => {
  const finishing = deferred();
  const h = harness({finish: () => finishing.promise});
  const request = h.probe.run({manual: true});
  for (let step = 0; step < 30 && h.count('finish') === 0; step += 1) await Promise.resolve();
  assert.equal(h.count('finish'), 1);
  h.probe.cancel();
  assert.equal(h.count('discard'), 0);
  finishing.resolve(checked());
  assert.equal((await request).reason, 'cancelled');
  assert.equal(h.count('discard'), 1);
});
