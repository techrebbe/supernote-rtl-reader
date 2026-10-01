'use strict';
// Tests real pure production-alpha control code. No API/device/files/timers.
const test = require('node:test');
const assert = require('node:assert/strict');
const {
  FIXTURE_NAME, WIDTH, HEIGHT, MAX_PNG_BYTES, supportedContext, createSavedInkController,
} = require('../overlay/savedInk');

const TOKEN = 'f3d09692-3a12-48cb-823b-62041968c761';
const OTHER_TOKEN = 'e3d09692-3a12-48cb-823b-62041968c761';
const FILE = `/storage/emulated/0/Document/${FIXTURE_NAME}`;
const DIR = '/data/user/0/com.ratta.supernote.pluginhost/files/plugins/snrtl20260726001';
const context = () => ({filePath: FILE, pageIndex: 2, totalPages: 8, pluginDir: DIR});
const png = token => `${DIR}/saved-ink-cache/${token}/ink.png`;
const prepared = (token = TOKEN) => ({
  token, filePath: FILE, pageIndex: 2, width: WIDTH, height: HEIGHT,
  sourceVerified: true, pngPath: png(token),
});
const finished = (token = TOKEN) => ({
  ...prepared(token), savedInkToken: token, sourceUnchanged: true, markUnchanged: true,
  decoded: true, sha256: 'a'.repeat(64), byteLength: 1000, alphaMin: 0, alphaMax: 255,
});

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}

function harness(overrides = {}) {
  const calls = [];
  let current = context();
  const defaults = {
    currentContext: async () => ({...current}),
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
    controller: createSavedInkController(deps), calls,
    change(patch) { current = {...current, ...patch}; },
    current() { return current; },
    count(name) { return calls.filter(call => call.name === name).length; },
  };
}

async function enter(h, name) {
  for (let step = 0; step < 40 && h.count(name) === 0; step += 1) await Promise.resolve();
  assert.equal(h.count(name), 1);
}

test('API uses original PAGE3, fixed canvas and token-only ready result', async () => {
  const h = harness();
  const result = await h.controller.run(context());
  assert.equal(result.status, 'ready');
  assert.equal(result.savedInkToken, TOKEN);
  assert.deepEqual(result.handle, {token: TOKEN});
  assert.equal(result.imageUri, undefined, 'native view takes an attested registry token, not a JS image path');
  assert.deepEqual(h.calls.find(c => c.name === 'prepare').args, [{...context(), width: WIDTH, height: HEIGHT}].map(({totalPages, ...rest}) => rest));
  assert.deepEqual(h.calls.find(c => c.name === 'generateThumbnail').args, [FILE, 2, png(TOKEN), {width: WIDTH, height: HEIGHT}]);
  assert.deepEqual(h.calls.find(c => c.name === 'finish').args, [{token: TOKEN, missingMark: false}]);
  assert.equal(h.count('discard'), 0);
  assert.deepEqual(await h.controller.run(context()), {status: 'unavailable', reason: 'ink_retained'});
  assert.deepEqual(await h.controller.dispose(), {status: 'disposed'});
  assert.equal(h.count('discard'), 1);
});

test('every unsupported page, file, type or plugin path is unavailable without native/API calls', async () => {
  for (const patch of [
    {filePath: '/Document/personal.pdf'}, {filePath: `${FILE}.mark`},
    {filePath: `relative/${FIXTURE_NAME}`}, {filePath: `/Document/../${FIXTURE_NAME}`},
    {filePath: `/Document//${FIXTURE_NAME}`}, {filePath: `/Document/\u0000${FIXTURE_NAME}`},
    {pageIndex: 1}, {pageIndex: 3}, {pageIndex: '2'}, {pageIndex: -1}, {pageIndex: NaN}, {pageIndex: 2.5},
    {totalPages: 7}, {totalPages: '8'}, {totalPages: Infinity},
    {pluginDir: '/sdcard/plugin'}, {pluginDir: `${DIR}/`}, {pluginDir: `${DIR}/..`},
    {pluginDir: DIR.replace('/plugins/', '/plugins//')}, {pluginDir: undefined},
  ]) {
    const h = harness();
    const bad = {...context(), ...patch};
    assert.equal(supportedContext(bad), false);
    assert.deepEqual(await h.controller.run(bad), {status: 'unavailable', reason: 'unsupported_context'});
    assert.equal(h.calls.length, 0, JSON.stringify(patch));
    assert.deepEqual(await h.controller.dispose(), {status: 'disposed'});
  }
  for (const value of [null, {}, [], 'context', undefined]) assert.equal(supportedContext(value), false);
  assert.equal(supportedContext(context()), true);
});

test('all dependencies required; no runtime IO imports', () => {
  assert.throws(() => createSavedInkController({}), /Missing saved ink dependency/);
});

test('malformed prepare identity/geometry/output rejects before SDK and cleans issued valid token', async () => {
  for (const patch of [
    {filePath: '/Document/other.pdf'}, {pageIndex: 3}, {pageIndex: '2'},
    {width: 1403}, {height: 1871}, {width: '1404'}, {height: NaN},
    {sourceVerified: false}, {sourceVerified: 'true'},
    {pngPath: `/data/user/0/another-plugin/${TOKEN}/ink.png`},
    {pngPath: `${png(TOKEN)}.png`}, {pngPath: png(TOKEN).replace('/saved-ink-cache/', '/saved-ink-cache/../')},
    {pngPath: png(TOKEN).replace(TOKEN, OTHER_TOKEN)}, {pngPath: `/sdcard/${TOKEN}/ink.png`},
  ]) {
    const h = harness({prepare: async () => ({...prepared(), ...patch})});
    assert.equal((await h.controller.run(context())).reason, 'prepare_invalid', JSON.stringify(patch));
    assert.equal(h.count('generateThumbnail'), 0);
    assert.equal(h.count('discard'), 1);
    assert.deepEqual(h.calls.find(c => c.name === 'discard').args, [{token: TOKEN}]);
    await h.controller.dispose();
  }
});

test('malformed token never becomes a raw-path cleanup capability', async () => {
  for (const token of [null, 'invalid', '', TOKEN.toUpperCase(), `${TOKEN} `, '../other']) {
    const h = harness({prepare: async () => ({...prepared(), token})});
    assert.equal((await h.controller.run(context())).reason, 'prepare_invalid');
    assert.equal(h.count('discard'), 0);
    assert.equal(h.count('generateThumbnail'), 0);
    await h.controller.dispose();
  }
});

test('requires SDK success AND result true; numeric1302 only is separately attested', async () => {
  for (const api of [
    null, {}, {success: true, result: false}, {success: true, result: 1},
    {success: 'true', result: true}, {success: false, result: true},
    {success: false, error: {code: 1201}}, {success: false, error: {code: '1302'}},
    {success: true, result: false, error: {code: 1302}},
  ]) {
    const h = harness({generateThumbnail: async () => api});
    assert.equal((await h.controller.run(context())).reason, 'generation_failed');
    assert.equal(h.count('finish'), 0);
    assert.equal(h.count('discard'), 1);
    await h.controller.dispose();
  }
});

test('missing mark becomes no_page only after native unchanged-source/mark attestation', async () => {
  const h = harness({
    generateThumbnail: async () => ({success: false, error: {code: 1302}}),
    finish: async () => ({token: TOKEN, filePath: FILE, pageIndex: 2, sourceUnchanged: true, markUnchanged: true, missingMark: true}),
  });
  const result = await h.controller.run(context());
  assert.equal(result.status, 'no_page');
  assert.equal(result.reason, 'missing_mark_page');
  assert.equal(result.savedInkToken, undefined);
  assert.equal(h.count('discard'), 1);
  assert.deepEqual(h.calls.find(c => c.name === 'finish').args, [{token: TOKEN, missingMark: true}]);
  await h.controller.dispose();
  for (const patch of [{sourceUnchanged: false}, {markUnchanged: 'true'}, {missingMark: false}]) {
    const bad = harness({generateThumbnail: async () => ({success: false, error: {code: 1302}}), finish: async () => ({...finished(), missingMark: true, ...patch})});
    assert.equal((await bad.controller.run(context())).reason, 'finish_invalid');
    assert.equal(bad.count('discard'), 1);
    await bad.controller.dispose();
  }
});

test('finish validates exact source/token and finite bounded decoded evidence', async () => {
  for (const patch of [
    {token: OTHER_TOKEN}, {savedInkToken: OTHER_TOKEN}, {savedInkToken: null},
    {filePath: '/Document/other.pdf'}, {pageIndex: 3}, {pageIndex: '2'},
    {sourceUnchanged: false}, {markUnchanged: false}, {missingMark: true},
    {pngPath: `${png(TOKEN)}.other`}, {width: 1403}, {height: '1872'}, {height: Infinity}, {decoded: false},
    {sha256: 'a'.repeat(63)}, {sha256: 'A'.repeat(64)}, {sha256: null},
    {byteLength: 0}, {byteLength: 1.5}, {byteLength: MAX_PNG_BYTES + 1}, {byteLength: '1000'},
    {alphaMin: -1}, {alphaMax: 256}, {alphaMin: 200, alphaMax: 100}, {alphaMin: NaN}, {alphaMax: '255'},
  ]) {
    const h = harness({finish: async () => ({...finished(), ...patch})});
    const result = await h.controller.run(context());
    assert.equal(result.reason, 'finish_invalid', JSON.stringify(patch));
    assert.equal(result.savedInkToken, undefined);
    assert.equal(h.count('discard'), 1);
    await h.controller.dispose();
  }
  const boundary = harness({finish: async () => ({...finished(), byteLength: MAX_PNG_BYTES, alphaMin: 255, alphaMax: 255})});
  assert.equal((await boundary.controller.run(context())).status, 'ready', 'opaque alpha is not assumed transparent');
  await boundary.controller.dispose();
});

test('initial live context must match request, before native prepare', async () => {
  for (const patch of [{filePath: '/Document/new.pdf'}, {pageIndex: 3}, {totalPages: 9}, {pluginDir: `${DIR}/other`}]) {
    const h = harness(); h.change(patch);
    assert.deepEqual(await h.controller.run(context()), {status: 'unavailable', reason: 'context_changed'});
    assert.equal(h.count('prepare'), 0);
    await h.controller.dispose();
  }
});

test('each asynchronous stage fences visible page/document/plugin context before publication', async () => {
  for (const [stage, patch] of [
    ['prepare', {pageIndex: 3}], ['generateThumbnail', {filePath: '/Document/replaced.pdf'}],
    ['finish', {totalPages: 9}], ['finish', {pluginDir: `${DIR}/other`}],
  ]) {
    let h;
    h = harness({[stage]: async () => {
      h.change(patch);
      return stage === 'prepare' ? prepared() : stage === 'finish' ? finished() : {success: true, result: true};
    }});
    const result = await h.controller.run(context());
    assert.equal(result.reason, 'context_changed');
    assert.equal(result.savedInkToken, undefined);
    assert.equal(h.count('discard'), 1);
    if (stage === 'prepare') assert.equal(h.count('generateThumbnail'), 0);
    if (stage === 'generateThumbnail') assert.equal(h.count('finish'), 0);
    await h.controller.dispose();
  }
});

test('request identity copied, never mutated by caller while awaiting context', async () => {
  const current = deferred();
  let count = 0;
  const h = harness({currentContext: async () => ++count === 1 ? current.promise : context()});
  const requested = context();
  const request = h.controller.run(requested);
  await enter(h, 'currentContext');
  requested.filePath = '/Document/changed.pdf'; requested.pageIndex = 3; requested.pluginDir = '/sdcard';
  current.resolve(context());
  assert.equal((await request).status, 'ready');
  assert.equal(h.calls.find(c => c.name === 'prepare').args[0].filePath, FILE);
  await h.controller.dispose();
});

test('cancel during prepare waits for issued token then prevents SDK call and cleans once', async () => {
  const prep = deferred();
  const h = harness({prepare: () => prep.promise});
  const request = h.controller.run(context());
  await enter(h, 'prepare');
  h.controller.cancel();
  assert.equal(h.count('discard'), 0);
  prep.resolve(prepared());
  assert.equal((await request).reason, 'cancelled');
  assert.equal(h.count('generateThumbnail'), 0);
  assert.equal(h.count('discard'), 1);
  await h.controller.dispose();
});

test('cancel/ABA during SDK retains lock/output until actual settlement', async () => {
  const api = deferred();
  const h = harness({generateThumbnail: () => api.promise});
  const request = h.controller.run(context());
  await enter(h, 'generateThumbnail');
  h.change({pageIndex: 3}); h.controller.cancel(); h.change({pageIndex: 2});
  assert.deepEqual(await h.controller.run(context()), {status: 'unavailable', reason: 'busy'});
  assert.deepEqual(await h.controller.release(), {status: 'unavailable', reason: 'busy'});
  assert.equal(h.count('discard'), 0);
  api.resolve({success: true, result: true});
  assert.equal((await request).reason, 'cancelled');
  assert.equal(h.count('finish'), 0);
  assert.equal(h.count('discard'), 1);
  await h.controller.dispose();
});

test('cancel during finish suppresses otherwise valid registry publication', async () => {
  const finishing = deferred();
  const h = harness({finish: () => finishing.promise});
  const request = h.controller.run(context());
  await enter(h, 'finish');
  h.controller.cancel();
  assert.equal(h.count('discard'), 0);
  finishing.resolve(finished());
  assert.equal((await request).reason, 'cancelled');
  assert.equal(h.count('discard'), 1);
  await h.controller.dispose();
});

test('dispose waits pending SDK then cleans without republishing; remount cannot overlap', async () => {
  const api = deferred();
  const old = harness({generateThumbnail: () => api.promise});
  const request = old.controller.run(context());
  await enter(old, 'generateThumbnail');
  const disposal = old.controller.dispose();
  assert.equal(old.count('discard'), 0);
  const remount = harness();
  assert.deepEqual(await remount.controller.run(context()), {status: 'unavailable', reason: 'ownership_pending'});
  assert.equal(remount.calls.length, 0);
  api.resolve({success: true, result: true});
  assert.equal((await request).reason, 'cancelled');
  assert.deepEqual(await disposal, {status: 'disposed'});
  assert.equal(old.count('discard'), 1);
  assert.equal((await old.controller.run(context())).reason, 'disposed');
  assert.equal((await remount.controller.run(context())).status, 'ready');
  await remount.controller.dispose();
});

test('retained ready token also blocks remount until owned disposal, which is idempotent', async () => {
  const old = harness();
  await old.controller.run(context());
  const remount = harness();
  assert.equal((await remount.controller.run(context())).reason, 'ownership_pending');
  const first = old.controller.dispose();
  assert.equal(old.controller.dispose(), first);
  assert.deepEqual(await first, {status: 'disposed'});
  assert.equal(old.count('discard'), 1);
  assert.equal((await remount.controller.run(context())).status, 'ready');
  await remount.controller.dispose();
});

test('cleanup failure is never success and remains globally owned until explicit retry', async () => {
  let fail = true;
  const old = harness({discard: async ({token}) => { if (fail) throw Error('failed'); return {token, discarded: true}; }});
  const ready = await old.controller.run(context());
  const failed = await old.controller.dispose();
  assert.equal(failed.reason, 'cleanup_failed');
  assert.equal(old.controller.getState().retained, true);
  const remount = harness();
  assert.equal((await remount.controller.run(context())).reason, 'ownership_pending');
  assert.equal((await old.controller.release({...ready.handle})).reason, 'unknown_handle');
  fail = false;
  assert.deepEqual(await old.controller.release(ready.handle), {status: 'released'});
  assert.equal((await remount.controller.run(context())).status, 'ready');
  await remount.controller.dispose();
});

test('failed run cleanup gets only one discard attempt and tracked retry handle', async () => {
  let fail = true;
  const h = harness({
    generateThumbnail: async () => ({success: true, result: false}),
    discard: async ({token}) => { if (fail) throw Error('failed'); return {token, discarded: true}; },
  });
  const result = await h.controller.run(context());
  assert.equal(result.reason, 'cleanup_failed');
  assert.equal(result.causeReason, 'generation_failed');
  assert.equal(h.count('discard'), 1);
  assert.equal((await h.controller.run(context())).reason, 'ink_retained');
  fail = false;
  assert.deepEqual(await h.controller.release(result.handle), {status: 'released'});
  await h.controller.dispose();
});

test('missing-page cleanup failure is retained, not retried twice in same run', async () => {
  let fail = true;
  const h = harness({
    generateThumbnail: async () => ({success: false, error: {code: 1302}}),
    finish: async () => ({...finished(), missingMark: true}),
    discard: async ({token}) => { if (fail) throw Error('failed'); return {token, discarded: true}; },
  });
  const result = await h.controller.run(context());
  assert.equal(result.status, 'error');
  assert.equal(result.reason, 'cleanup_failed');
  assert.equal(h.count('discard'), 1);
  fail = false;
  await h.controller.release(result.handle);
  await h.controller.dispose();
});

test('native discard must attest exact token and completion before releasing ownership', async () => {
  for (const response of [null, {}, {token: TOKEN, discarded: false}, {token: TOKEN, discarded: 'true'}, {token: OTHER_TOKEN, discarded: true}]) {
    let retry = false;
    const h = harness({discard: async ({token}) => retry ? {token, discarded: true} : response});
    const ready = await h.controller.run(context());
    assert.equal((await h.controller.release(ready.handle)).reason, 'cleanup_failed');
    assert.equal(h.controller.getState().retained, true);
    retry = true;
    await h.controller.release(ready.handle);
    await h.controller.dispose();
  }
});

test('release single-flight does not allow new API work while native cleanup pending', async () => {
  const cleanup = deferred();
  const h = harness({discard: () => cleanup.promise});
  const result = await h.controller.run(context());
  const releasing = h.controller.release(result.handle);
  assert.equal((await h.controller.run(context())).reason, 'busy');
  assert.equal((await h.controller.release(result.handle)).reason, 'busy');
  await enter(h, 'discard');
  cleanup.resolve({token: TOKEN, discarded: true});
  assert.deepEqual(await releasing, {status: 'released'});
  await h.controller.dispose();
});

test('every new activation generates a fresh token/SDK extraction, never stale cached evidence', async () => {
  let generation = 0;
  let token = TOKEN;
  const h = harness({
    prepare: async () => { token = ++generation === 1 ? TOKEN : OTHER_TOKEN; return prepared(token); },
    finish: async () => finished(token),
  });
  const first = await h.controller.run(context());
  await h.controller.release(first.handle);
  const second = await h.controller.run(context());
  assert.equal(second.savedInkToken, OTHER_TOKEN);
  assert.equal(h.count('prepare'), 2);
  assert.equal(h.count('generateThumbnail'), 2);
  assert.equal(h.count('finish'), 2);
  await h.controller.dispose();
});

test('dependency rejection remains error and cleans only after actual completion', async () => {
  for (const name of ['currentContext', 'prepare', 'generateThumbnail', 'finish']) {
    const h = harness({[name]: async () => { throw Error('failed'); }});
    const result = await h.controller.run(context());
    assert.equal(result.status, 'error');
    assert.equal(result.reason, `${name === 'currentContext' ? 'context' : name === 'generateThumbnail' ? 'generate' : name}_failed`);
    assert.equal(h.count('discard'), ['currentContext', 'prepare'].includes(name) ? 0 : 1);
    await h.controller.dispose();
  }
});

test('missing result is suppressed if context changes during completed cleanup', async () => {
  let h;
  h = harness({
    generateThumbnail: async () => ({success: false, error: {code: 1302}}),
    finish: async () => ({...finished(), missingMark: true}),
    discard: async ({token}) => { h.change({pageIndex: 3}); return {token, discarded: true}; },
  });
  assert.equal((await h.controller.run(context())).reason, 'context_changed');
  assert.equal(h.count('discard'), 1);
  await h.controller.dispose();
});
