'use strict';
// Execute the installed, integrity-pinned SDK's real JS and validators. Only
// the RN/native boundary is mocked. This does not claim a device handshake.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const sdk = path.resolve(process.argv[2]);
const babel = require(require.resolve('@babel/core', {paths: [sdk]}));
const commonjs = require.resolve('@babel/plugin-transform-modules-commonjs', {paths: [sdk]});
const pkg = JSON.parse(fs.readFileSync(path.join(sdk, 'package.json'), 'utf8'));
assert.equal(pkg.name, 'sn-plugin-lib');
assert.equal(pkg.version, '0.1.65');
assert.deepEqual(pkg.dependencies ?? {}, {});
assert.deepEqual(pkg.peerDependencies, {react: '*', 'react-native': '*'});
const calls = [];
const subscriptions = [];
const native = new Proxy({}, {get: (_, name) => (...args) => {
  calls.push([name, ...args]);
  return Promise.resolve({success: true, result: name});
}});
const cache = new Map();
function load(file) {
  file = path.resolve(file);
  if (cache.has(file)) return cache.get(file).exports;
  const module = {exports: {}};
  cache.set(file, module);
  const source = fs.readFileSync(file, 'utf8');
  const {code} = babel.transformSync(source, {
    babelrc: false, configFile: false, plugins: [commonjs], filename: file,
  });
  function mockedRequire(name) {
    if (name === 'react-native') return {DeviceEventEmitter: {
      addListener: (event, handler) => subscriptions.push([event, handler]),
    }};
    if (name === 'sn-plugin-lib/package.json') return pkg;
    if (/\/NativePlugin(?:Manager|API)$/.test(name)) return {__esModule: true, default: native};
    assert.ok(name.startsWith('.'), `unexpected SDK external dependency ${name}`);
    let target = path.resolve(path.dirname(file), name);
    if (!path.extname(target)) target += '.js';
    assert.ok(target.startsWith(sdk + path.sep), 'SDK import escapes package');
    return load(target);
  }
  vm.runInThisContext(`(function(require,module,exports){${code}\n})`, {filename: file})(
    mockedRequire, module, module.exports);
  return module.exports;
}
async function main() {
  const manager = load(path.join(sdk, 'lib/module/PluginManager.js')).default;
  await manager.init();
  assert.deepEqual(calls, [['onMounted'], ['reportSdkVersion', '0.1.65']]);
  assert.ok(subscriptions.length >= 4);
  await manager.init();
  assert.equal(calls.length, 2, 'init must not register/report twice');
  const comm = load(path.join(sdk, 'lib/module/sdk/PluginCommAPI.js')).default;
  const doc = load(path.join(sdk, 'lib/module/sdk/PluginDocAPI.js')).default;
  const file = load(path.join(sdk, 'lib/module/sdk/PluginFileAPI.js')).default;
  await comm.getCurrentFilePath();
  await comm.getCurrentPageNum();
  await doc.getCurrentTotalPages();
  await file.getPageSize('/disposable.pdf', 0);
  const size = {width: 1404, height: 1872};
  await file.generateMarkThumbnails('/disposable.pdf.mark', 0, '/owned.png', size);
  assert.deepEqual(calls.slice(2), [
    ['getCurrentFilePath'], ['getCurrentPageNum'], ['getCurrentTotalPages'],
    ['getPageSize', '/disposable.pdf', 0],
    ['generateMarkThumbnails', '/disposable.pdf.mark', 0, '/owned.png', size],
  ]);
  await manager.hasPermission('plugin.permission.FILE:READ');
  await manager.requestPermission('plugin.permission.FILE:READ');
  assert.deepEqual(calls.slice(-2), [
    ['hasPermission', 'plugin.permission.FILE:READ'],
    ['requestPermission', 'plugin.permission.FILE:READ', null],
  ]);
  const count = calls.length;
  await comm.jumpToPage(1);
  assert.deepEqual(calls.pop(), ['jumpToPage', 1]);
  for (const page of [-1, 1.5, '1', null, NaN]) {
    assert.equal((await comm.jumpToPage(page)).success, false);
  }
  for (const args of [
    ['/disposable.pdf.mark', -1, '/owned.png', size],
    ['/disposable.pdf.mark', 0, '/owned.jpg', size],
    ['/disposable.pdf.mark', 0, '/owned.png', {width: NaN, height: 1872}],
  ]) assert.equal((await file.generateMarkThumbnails(...args)).success, false);
  assert.equal((await file.getPageSize('/disposable.pdf', -1)).success, false);
  assert.equal(calls.length, count, 'invalid requests must not reach native APIs');
  console.log('Pinned SDK 0.1.65 actual init/read/thumbnail/validation checks: PASS');
}
main().catch(error => {console.error(error); process.exitCode = 1;});
