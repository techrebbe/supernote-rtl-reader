'use strict';
// Execute production request control; no PDF, pen, device or timeout modelling.
const test = require('node:test');
const assert = require('node:assert/strict');
const {PROFILES, selectSavedInkProfile, createSavedInkController} = require('../overlay/savedInk');
const PROFILE = PROFILES[1];
const DIR = '/data/user/0/com.ratta.supernote.pluginhost/files/plugins/snrtl20260726001';
const TOKEN = 'f3d09692-3a12-48cb-823b-62041968c761';
const context = () => ({filePath: PROFILE.filePath, pageIndex: 0, totalPages: 2, pluginDir: DIR});
const evidence = () => ({
  token: TOKEN, profileId: PROFILE.id, geometryId: PROFILE.id, sourceSha256: PROFILE.sourceSha256,
  filePath: PROFILE.filePath, pageIndex: 0, pageCount: 2, width: 1404, height: 1872,
  pngPath: `${DIR}/saved-ink-cache/${TOKEN}/ink.png`, sourceVerified: true,
});
function deferred() {
  let resolve;
  const promise = new Promise(yes => { resolve = yes; });
  return {promise, resolve};
}
function harness(overrides = {}) {
  let current = context();
  const calls = [];
  const defaults = {
    currentContext: async () => ({...current}),
    getPageSize: async () => ({success: true, result: {width: 1404, height: 1872}}),
    prepare: async () => evidence(),
    generateThumbnail: async () => ({success: true, result: true}),
    finish: async () => ({...evidence(), sourceUnchanged: true, markUnchanged: true,
      savedInkToken: TOKEN, decoded: true, sha256: 'a'.repeat(64), byteLength: 100,
      alphaMin: 0, alphaMax: 255}),
    discard: async () => ({token: TOKEN, discarded: true}),
  };
  const deps = {};
  for (const name of Object.keys(defaults)) {
    if (overrides[name] === null) continue;
    deps[name] = async (...args) => {
      calls.push({name, args});
      return (overrides[name] ?? defaults[name])(...args);
    };
  }
  return {controller: createSavedInkController(deps), calls,
    change(patch) { current = {...current, ...patch}; },
    count(name) { return calls.filter(call => call.name === name).length; }};
}
async function entered(h, name, count = 1) {
  for (let tick = 0; tick < 100 && h.count(name) < count; ++tick) await Promise.resolve();
  assert.equal(h.count(name), count);
}
test('UI profiles are exact-path/count immutable eligibility, not basename inference', () => {
  assert.equal(selectSavedInkProfile(PROFILE.filePath, 2), PROFILE);
  assert.equal(Object.isFrozen(PROFILE), true);
  for (const [file, count] of [[PROFILE.filePath, '2'], [PROFILE.filePath, 8],
    [PROFILE.filePath.replace('/Document/', '/Documents/'), 2],
    [PROFILE.filePath.replace('/Document/', '/Document/../Document/'), 2]]) {
    assert.equal(selectSavedInkProfile(file, count), null);
  }
});
test('T008 uses original PAGE1 and full native canvas, with real API size checks around extraction', async () => {
  const h = harness();
  const result = await h.controller.run(context());
  assert.equal(result.status, 'ready');
  assert.equal(result.evidence.geometryId, PROFILE.id);
  assert.deepEqual(h.calls.filter(c => c.name === 'getPageSize').map(c => c.args),
    [[PROFILE.filePath, 0], [PROFILE.filePath, 0]]);
  assert.deepEqual(h.calls.find(c => c.name === 'prepare').args, [{
    profileId: PROFILE.id, filePath: PROFILE.filePath, pageIndex: 0,
    width: 1404, height: 1872, pluginDir: DIR,
  }]);
  assert.deepEqual(h.calls.find(c => c.name === 'generateThumbnail').args,
    [PROFILE.filePath, 0, evidence().pngPath, {width: 1404, height: 1872}]);
  await h.controller.dispose();
});
test('missing or wrong canvas rejects before native output allocation', async () => {
  const missing = harness({getPageSize: null});
  assert.equal((await missing.controller.run(context())).reason, 'canvas_unavailable');
  assert.equal(missing.count('prepare'), 0);
  await missing.controller.dispose();
  for (const size of [null, {}, {success: false, result: {width: 1404, height: 1872}},
    {success: true, result: {width: 1872, height: 1404}},
    {success: true, result: {width: '1404', height: 1872}},
    {success: true, result: {width: 1404, height: NaN}}]) {
    const h = harness({getPageSize: async () => size});
    assert.equal((await h.controller.run(context())).reason, 'canvas_mismatch');
    assert.equal(h.count('prepare'), 0);
    await h.controller.dispose();
  }
});
test('canvas change after settled SDK rejects publication and cleans only that issued token', async () => {
  let sizeCalls = 0;
  const h = harness({getPageSize: async () => ({success: true, result:
    ++sizeCalls === 1 ? {width: 1404, height: 1872} : {width: 1872, height: 1404}})});
  assert.equal((await h.controller.run(context())).reason, 'canvas_mismatch');
  assert.equal(h.count('generateThumbnail'), 1);
  assert.equal(h.count('finish'), 0);
  assert.equal(h.count('discard'), 1);
  await h.controller.dispose();
});
test('mismatched profile, geometry, original hash or count cannot borrow T004/native authority', async () => {
  for (const patch of [{profileId: PROFILES[0].id}, {geometryId: PROFILES[0].id},
    {sourceSha256: PROFILES[0].sourceSha256}, {pageCount: 8}]) {
    const h = harness({prepare: async () => ({...evidence(), ...patch})});
    assert.equal((await h.controller.run(context())).reason, 'prepare_invalid');
    assert.equal(h.count('generateThumbnail'), 0);
    assert.equal(h.count('discard'), 1);
    await h.controller.dispose();
  }
});
test('cancellation during canvas query fences before allocation and waits real settlement', async () => {
  const size = deferred();
  const h = harness({getPageSize: () => size.promise});
  const work = h.controller.run(context());
  await entered(h, 'getPageSize');
  const cleanup = h.controller.dispose();
  assert.equal(h.count('prepare'), 0);
  size.resolve({success: true, result: {width: 1404, height: 1872}});
  assert.equal((await work).reason, 'cancelled');
  assert.deepEqual(await cleanup, {status: 'disposed'});
});
test('T008 page-away/back ABA during SDK cannot revive ink or delete live output early', async () => {
  const sdk = deferred();
  const h = harness({generateThumbnail: () => sdk.promise});
  const work = h.controller.run(context());
  await entered(h, 'generateThumbnail');
  h.change({pageIndex: 1}); h.controller.cancel(); h.change({pageIndex: 0});
  const cleanup = h.controller.dispose();
  assert.equal(h.count('discard'), 0);
  sdk.resolve({success: true, result: true});
  assert.equal((await work).reason, 'cancelled');
  assert.deepEqual(await cleanup, {status: 'disposed'});
  assert.equal(h.count('finish'), 0);
  assert.equal(h.count('discard'), 1);
});
