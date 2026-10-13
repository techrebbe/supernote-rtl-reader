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

test('observed T008 PAGE2 NO_PAGE1207 is not guessed to mean empty ink or a usable canvas', async () => {
  const profile = PROFILES[2];
  const context = {filePath: profile.filePath, pageIndex: profile.pageIndex, totalPages: 2,
    pluginDir: '/data/user/0/com.ratta.supernote.pluginhost/files/plugins/snrtl20260726001'};
  const response = {success: false, result: null, error: {code: 1207, message: 'NO_PAGE'}};
  const samples = [], calls = [];
  const forbidden = name => () => {calls.push(name); throw new Error(`Unexpected ${name}`);};
  const controller = createSavedInkController({currentContext: async () => ({...context}),
    getPageSize: (file, page) => observeSdkCanvas(async (...args) => {
      calls.push(args); return response;
    }, file, page, sample => samples.push(sample)),
    // An available API name is not a validated, snapshot-bound absence witness.
    getMarkPages: forbidden('unfenced mark enumeration'),
    prepare: forbidden('prepare'), finish: forbidden('finish'),
    discard: forbidden('discard'), generateThumbnail: forbidden('thumbnail')});
  assert.deepEqual(await controller.run(context), {status: 'error', reason: 'canvas_mismatch'});
  assert.deepEqual(calls, [[profile.filePath, 1]]);
  assert.deepEqual(samples, [{pageIndex: 1, status: 'error', width: 'invalid', height: 'invalid', code: 1207}]);
  assert.deepEqual(await controller.dispose(), {status: 'disposed'});
});

const noPage = () => ({success: false, result: null, error: {code: 1207, message: 'secret path'}});
function diagnostic(response, overrides = {}) {
  const calls = [], samples = [];
  const options = {attempted: false, totalPages: 2, isCurrent: async () => true,
    getMarkPages: async (...args) => {calls.push(args); return response;},
    observe: sample => samples.push(sample), ...overrides};
  return {options, calls, samples};
}
for (const indices of [[], [0], [1], [2], [0, 1], [1, 2]]) {
  test(`bounded raw enumeration ${JSON.stringify(indices)} remains diagnostic with index base unverified`, async () => {
    const h = diagnostic({success: true, result: indices, extra: '/private/secret'});
    const original = noPage();
    assert.strictEqual(await observeSdkCanvas(async () => original, '/disposable.pdf', 1, () => {}, h.options), original);
    assert.deepEqual(h.calls, [['/disposable.pdf']]);
    assert.deepEqual(h.samples, [{pageIndex: 1, indexBase: 'unverified', status: 'success', indices, code: 'unknown'}]);
    assert.ok(!JSON.stringify(h.samples).includes('secret'));
  });
}
for (const result of [[0, 0], [0, 1, 2], ['0'], [NaN], [-1], [3], [null], {}, null]) {
  test(`malformed mark list ${JSON.stringify(result)} cannot leak arbitrary values or authorize missing ink`, async () => {
    const h = diagnostic({success: true, result});
    const original = noPage();
    assert.strictEqual(await observeSdkCanvas(async () => original, '/disposable.pdf', 1, () => {}, h.options), original);
    assert.equal(h.samples[0].status, 'invalid');
    assert.equal(h.samples[0].indices, 'unavailable');
  });
}
test('one diagnostic is consumed before awaits and cannot retry on a second canvas failure', async () => {
  const h = diagnostic({success: false, error: {code: 1503, message: 'sensitive'}});
  const response = noPage();
  await Promise.all([0, 1].map(() => observeSdkCanvas(async () => response, '/disposable.pdf', 1, () => {}, h.options)));
  assert.deepEqual(h.calls, [['/disposable.pdf']]);
  assert.deepEqual(h.samples, [{pageIndex: 1, indexBase: 'unverified', status: 'error', indices: 'unavailable', code: 1503}]);
});
test('valid canvases and other SDK errors never dispatch mark enumeration', async () => {
  for (const response of [{success: true, result: {width: 1404, height: 1872}},
    {success: false, error: {code: 1302}}, null]) {
    const h = diagnostic({success: true, result: [0]});
    assert.strictEqual(await observeSdkCanvas(async () => response, '/disposable.pdf', 1, () => {}, h.options), response);
    assert.equal(h.options.attempted, false);
    assert.equal(h.calls.length, 0);
  }
});
test('retirement before dispatch consumes the diagnostic without an SDK call', async () => {
  const h = diagnostic({success: true, result: [0]}, {isCurrent: async () => false});
  const response = noPage();
  assert.strictEqual(await observeSdkCanvas(async () => response, '/disposable.pdf', 1, () => {}, h.options), response);
  assert.equal(h.calls.length, 0);
  assert.equal(h.samples[0].status, 'stale');
});
test('retirement while enumeration is pending suppresses its indices and waits real settlement', async () => {
  let settle, entered; const pending = new Promise(resolve => {settle = resolve;});
  const started = new Promise(resolve => {entered = resolve;});
  let current = true, completed = false;
  const h = diagnostic(null, {isCurrent: async () => current,
    getMarkPages: async () => {entered(); return pending;}});
  const response = noPage();
  const run = observeSdkCanvas(async () => response, '/disposable.pdf', 1, () => {}, h.options)
    .then(value => {completed = true; return value;});
  await started; current = false; await Promise.resolve();
  assert.equal(completed, false);
  settle({success: true, result: [0]});
  assert.strictEqual(await run, response);
  assert.deepEqual(h.samples, [{pageIndex: 1, indexBase: 'unverified', status: 'stale', indices: 'unavailable', code: 'unknown'}]);
});
test('SDK/query/fence/observer failures cannot replace the original canvas failure', async () => {
  for (const overrides of [
    {getMarkPages: async () => {throw new Error('private secret');}},
    {isCurrent: async () => {throw new Error('fence failed');}},
    {observe: () => {throw new Error('logger failed');}},
  ]) {
    const h = diagnostic({success: true, result: [0]}, overrides), response = noPage();
    assert.strictEqual(await observeSdkCanvas(async () => response, '/disposable.pdf', 1, () => {}, h.options), response);
  }
});
test('array entries are copied once before validation; a changing getter cannot leak a later value', async () => {
  let reads = 0;
  const array = [];
  Object.defineProperty(array, 0, {get: () => ++reads === 1 ? 0 : '/private/secret'});
  const h = diagnostic({success: true, result: array}), response = noPage();
  assert.strictEqual(await observeSdkCanvas(async () => response, '/disposable.pdf', 1, () => {}, h.options), response);
  assert.equal(reads, 1);
  assert.deepEqual(h.samples[0].indices, [0]);
});
test('real controller keeps NO_PAGE fail-closed even after successful enumeration', async () => {
  const profile = PROFILES[2];
  const context = {filePath: profile.filePath, pageIndex: 1, totalPages: 2,
    pluginDir: '/data/user/0/com.ratta.supernote.pluginhost/files/plugins/snrtl20260726001'};
  const h = diagnostic({success: true, result: [0]});
  const forbidden = () => {throw new Error('No allocation, thumbnail, finish or discard permitted');};
  const controller = createSavedInkController({currentContext: async () => ({...context}),
    getPageSize: (file, page) => observeSdkCanvas(async () => noPage(), file, page, () => {}, h.options),
    prepare: forbidden, finish: forbidden, generateThumbnail: forbidden, discard: forbidden});
  assert.deepEqual(await controller.run(context), {status: 'error', reason: 'canvas_mismatch'});
  assert.deepEqual(h.samples[0].indices, [0]);
  assert.deepEqual(await controller.dispose(), {status: 'disposed'});
});
test('actual App diagnostic uses the existing cancellation/presentation/current-file context', () => {
  const app = fs.readFileSync(path.join(__dirname, '../overlay/App.js'), 'utf8');
  assert.ok(app.includes('const markPagesDiagnostic = {attempted: false, totalPages: 2};'));
  assert.ok(app.includes('getMarkPages: file => PluginFileAPI.getMarkPages(file)'));
  assert.ok(app.includes('const live = await currentContext();'));
  assert.ok(app.includes('RTL_READER_SDK_MARK_PAGES page='));
  assert.ok(app.includes('          markPagesDiagnostic,'));
});

test('changing SDK error-code getters cannot leak a later path or message into either diagnostic', async () => {
  const canvasSamples = [];
  let canvasReads = 0;
  const canvasResponse = {success: false, error: {get code() {return ++canvasReads === 1 ? 1503 : '/private/secret';}}};
  assert.strictEqual(await observeSdkCanvas(async () => canvasResponse, '/disposable.pdf', 1,
    sample => canvasSamples.push(sample)), canvasResponse);
  assert.equal(canvasReads, 1);
  assert.equal(canvasSamples[0].code, 1503);
  let markReads = 0;
  const h = diagnostic({success: false, error: {get code() {return ++markReads === 1 ? 1503 : '/private/secret';}}});
  const original = noPage();
  assert.strictEqual(await observeSdkCanvas(async () => original, '/disposable.pdf', 1, () => {}, h.options), original);
  assert.equal(markReads, 1);
  assert.equal(h.samples[0].code, 1503);
  assert.ok(!JSON.stringify([...canvasSamples, ...h.samples]).includes('secret'));
});
