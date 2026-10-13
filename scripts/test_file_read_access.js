'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {FILE_READ_PERMISSION, ensureFileReadAccess} = require('../overlay/fileReadAccess');
function deferred() {
  let resolve;
  const promise = new Promise(r => {resolve = r;});
  return {promise, resolve};
}
function manager(statuses, grant = 1) {
  const calls = [];
  return {calls, api: {
    async hasPermission(name) {calls.push(['check', name]); return statuses.shift();},
    async requestPermission(name) {calls.push(['request', name]); return grant;},
  }};
}
for (const status of [1, 2]) test(`already granted ${status} is checked afresh each entry and never prompts`, async () => {
  const h = manager([status, status]);
  await ensureFileReadAccess(h.api);
  await ensureFileReadAccess(h.api);
  assert.deepEqual(h.calls, [['check', FILE_READ_PERMISSION], ['check', FILE_READ_PERMISSION]]);
});
for (const grant of [1, 2]) for (const verified of [1, 2]) test(`numeric grant ${grant} is rechecked as ${verified} before access`, async () => {
  const h = manager([0, verified], grant);
  await ensureFileReadAccess(h.api);
  assert.deepEqual(h.calls, [['check', FILE_READ_PERMISSION], ['request', FILE_READ_PERMISSION], ['check', FILE_READ_PERMISSION]]);
});
for (const grant of [0, -1, true, '1', null, undefined]) test(`denied/cancelled/malformed ${String(grant)} cannot authorize access`, async () => {
  const h = manager([0], grant);
  // Default parameters cannot stand in for the actual undefined SDK response.
  h.api.requestPermission = async name => {h.calls.push(['request', name]); return grant;};
  await assert.rejects(ensureFileReadAccess(h.api), /not granted/);
  assert.equal(h.calls.length, 2);
});
test('expired grant does not authorize access', async () => {
  await assert.rejects(ensureFileReadAccess(manager([0, 0]).api), /expired/);
});
test('missing API, rejected check and malformed status fail closed', async () => {
  await assert.rejects(ensureFileReadAccess({}), /unavailable/);
  await assert.rejects(ensureFileReadAccess({hasPermission: async () => {throw Error('blocked');}, requestPermission() {}}), /blocked/);
  for (const value of [true, '1', 3, null, undefined]) {
    const h = manager([value]);
    await assert.rejects(ensureFileReadAccess(h.api), /could not be verified/);
    assert.equal(h.calls.length, 1);
  }
});
for (const phase of ['check', 'request', 'verify']) test(`unmount during ${phase} suppresses every later operation`, async () => {
  const pending = deferred();
  let active = true;
  let checks = 0;
  let requests = 0;
  const api = {
    async hasPermission() {checks++; return phase === 'check' || (phase === 'verify' && checks === 2) ? pending.promise : 0;},
    async requestPermission() {requests++; return phase === 'request' ? pending.promise : 1;},
  };
  const result = ensureFileReadAccess(api, () => active);
  await new Promise(setImmediate);
  active = false;
  pending.resolve(1);
  await assert.rejects(result, /session closed/);
  assert.equal(checks, phase === 'verify' ? 2 : 1);
  assert.equal(requests, phase === 'check' ? 0 : 1);
});
test('actual App context reader cannot call SDK document APIs until permission settles', async () => {
  const source = fs.readFileSync(path.join(__dirname, '../overlay/App.js'), 'utf8');
  const begin = source.indexOf('async function getDocumentContext(');
  const end = source.indexOf('function clampPage(', begin);
  assert.ok(begin >= 0 && end > begin);
  const gate = deferred();
  const calls = [];
  const contextReader = new Function('ensureFileReadAccess', 'PluginManager', 'PluginCommAPI', 'PluginDocAPI', 'requireResult',
    source.slice(begin, end) + '\nreturn getDocumentContext;')(
      ensureFileReadAccess,
      {hasPermission: () => gate.promise, requestPermission() {throw Error('unexpected request');}},
      {getCurrentFilePath: async () => {calls.push('file'); return {success: true, result: '/disposable.pdf'};},
       getCurrentPageNum: async () => {calls.push('page'); return {success: true, result: 0};}},
      {getCurrentTotalPages: async () => {calls.push('total'); return {success: true, result: 2};}},
      async promise => (await promise).result);
  const opening = contextReader(() => true);
  await new Promise(setImmediate);
  assert.deepEqual(calls, []);
  gate.resolve(1);
  assert.deepEqual(await opening, {filePath: '/disposable.pdf', pageIndex: 0, totalPages: 2});
  assert.deepEqual(calls, ['file', 'page', 'total']);
});
test('package declares READ only and normal build includes the real gate', () => {
  const root = path.resolve(__dirname, '..');
  const cfg = JSON.parse(fs.readFileSync(path.join(root, 'PluginConfig.json')));
  assert.deepEqual(cfg['uses-permissions'], [FILE_READ_PERMISSION]);
  assert.ok(!('usesPermissions' in cfg) && !('usePermissions' in cfg));
  const build = fs.readFileSync(path.join(root, 'build.sh'), 'utf8');
  assert.ok(build.includes('cp "$ROOT/overlay/fileReadAccess.js" "$PROJECT/fileReadAccess.js"'));
  const app = fs.readFileSync(path.join(root, 'overlay/App.js'), 'utf8');
  assert.ok(app.includes('getDocumentContext(() => mountedRef.current)'));
});
