'use strict';
const assert = require('node:assert/strict');
const {test} = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const {observeSdkCanvas} = require('../overlay/sdkCanvasObservation');
const {createSavedInkController, PROFILES} = require('../overlay/savedInk');

for (const [response, sample] of [
  [{success: true, result: {width: 1404, height: 1872}}, {status: 'success', width: 1404, height: 1872, code: 'unknown'}],
  [{success: true, result: {width: 1872, height: 1404}}, {status: 'success', width: 1872, height: 1404, code: 'unknown'}],
  [{success: false, error: {code: 1503, message: '/private/path secret'}}, {status: 'error', width: 'invalid', height: 'invalid', code: 1503}],
  [{success: true, result: {width: '1404', height: NaN}}, {status: 'success', width: 'invalid', height: 'invalid', code: 'unknown'}],
  [null, {status: 'invalid', width: 'invalid', height: 'invalid', code: 'unknown'}],
]) {
  test(`observes only whitelisted numeric metadata and preserves ${sample.status} response identity`, async () => {
    const calls = [], samples = [];
    const result = await observeSdkCanvas(async (...args) => {calls.push(args); return response;},
      '/disposable.pdf', 1, value => samples.push(value));
    assert.strictEqual(result, response);
    assert.deepEqual(calls, [['/disposable.pdf', 1]]);
    assert.deepEqual(samples, [{pageIndex: 1, ...sample}]);
    assert.ok(!JSON.stringify(samples).includes('private') && !JSON.stringify(samples).includes('secret'));
  });
}
test('an SDK rejection is not swallowed or retried; observer rejection cannot mask it', async () => {
  const failure = new Error('sensitive path'); let calls = 0;
  await assert.rejects(observeSdkCanvas(async () => {calls++; throw failure;}, '/disposable.pdf', 1,
    () => {throw new Error('bad observer');}), error => error === failure);
  assert.equal(calls, 1);
});
test('logging failure and hostile diagnostic getters cannot replace the actual response', async () => {
  const response = {success: true, result: {width: 1404, height: 1872}};
  assert.strictEqual(await observeSdkCanvas(async () => response, '/disposable.pdf', 0,
    () => {throw new Error('logging failed');}), response);
  const opaque = {get success() {throw new Error('getter failed');}};
  const samples = [];
  assert.strictEqual(await observeSdkCanvas(async () => opaque, '/disposable.pdf', 0,
    sample => samples.push(sample)), opaque);
  assert.equal(samples[0].status, 'invalid');
});
test('the actual controller still rejects API errors and wrong dimensions before allocation', async () => {
  const profile = PROFILES[1];
  const context = {filePath: profile.filePath, pageIndex: 0, totalPages: 2,
    pluginDir: '/data/user/0/com.ratta.supernote.pluginhost/files/plugins/snrtl20260726001'};
  for (const response of [null, {success: false, error: {code: 123}},
    {success: true, result: {width: 0, height: 0}},
    {success: true, result: {width: 1872, height: 1404}}]) {
    let allocated = 0; const samples = [];
    const controller = createSavedInkController({currentContext: async () => context,
      getPageSize: (file, page) => observeSdkCanvas(async () => response, file, page,
        sample => samples.push(sample)),
      prepare: () => {allocated++; throw new Error('must not allocate');},
      finish: () => {throw new Error('must not finish');},
      discard: () => {throw new Error('no token to discard');},
      generateThumbnail: () => {throw new Error('must not generate');}});
    assert.equal((await controller.run(context)).reason, 'canvas_mismatch');
    assert.equal(allocated, 0);
    assert.equal(samples.length, 1);
    assert.deepEqual(await controller.dispose(), {status: 'disposed'});
  }
});
test('App uses the real observer and build ships it', () => {
  const root = path.resolve(__dirname, '..');
  const app = fs.readFileSync(path.join(root, 'overlay/App.js'), 'utf8');
  assert.ok(app.includes("from './sdkCanvasObservation'"));
  assert.ok(app.includes('getPageSize: (file, page) => observeSdkCanvas('));
  assert.ok(app.includes('RTL_READER_SDK_CANVAS page='));
  const build = fs.readFileSync(path.join(root, 'build.sh'), 'utf8');
  assert.ok(build.includes('cp "$ROOT/overlay/sdkCanvasObservation.js" "$PROJECT/sdkCanvasObservation.js"'));
});
