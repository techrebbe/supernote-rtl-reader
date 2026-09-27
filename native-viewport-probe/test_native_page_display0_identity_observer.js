'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SOURCE_PATH = path.join(__dirname, 'native_page_display0_identity_observer.js');
const SOURCE = fs.readFileSync(SOURCE_PATH, 'utf8');
const SHA = crypto.createHash('sha256').update(SOURCE).digest('hex');
const URI = 'file:///storage/emulated/0/Document/RTL_DISPLAY0_CAPTURE_20260927.pdf';
const MARK = '/storage/emulated/0/Document/RTL_DISPLAY0_CAPTURE_20260927.pdf.mark';
const CLASS = {
  activity: 'com.supernote.document.document.DocumentActivity',
  vm: 'com.supernote.document.document.DocumentViewModel',
  presenter: 'com.supernote.document.handwrite.HandWritePresenter',
  uri: 'android.net.Uri$StringUri',
  hierarchicalUri: 'android.net.Uri$HierarchicalUri'
};
const FAILURE_PAIRS = new Set([
  'MANIFEST/INVALID', 'RUNTIME/MISMATCH', 'BRIDGE/UNAVAILABLE',
  'JAVA_CHOOSE/FAILED', 'ACTIVITY/NONE', 'ACTIVITY/MULTIPLE',
  'ACTIVITY/LIMIT', 'IDENTITY/MISMATCH', 'URI/SUBTYPE', 'URI/WRAPPER',
  'URI/MISMATCH', 'CLEANUP/FAILED', 'DEADLINE/EXPIRED'
]);
let cases = 0;

function canonical(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return String(value);
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort().map(k =>
    JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
}
function manifest(markPath = null) {
  return {
    schemaVersion: 1, authority: 'rtl-reader-display0-identity-manifest-v1',
    attachment: {packageName: 'com.supernote.document',
      processName: 'com.supernote.document',
      pid: 2256, startTimeTicks: '4134',
      firmwareFingerprint:
        'Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys',
      observerSha256: SHA},
    expected: {documentUri: URI, markPath},
    coordinator: {maxJavaChooseWalks: 1, retainedRootSamples: 2,
      hardDeadlineMs: 1000, detachOnDeadline: true, abortOnAnyError: true,
      noRetry: true}
  };
}
function slot(value) { return {value}; }
function sequence(values) {
  let index = 0;
  return {get value() { return values[Math.min(index++, values.length - 1)]; }};
}
function object(className, id, fields = {}) {
  const item = {$className: className, $h: {id}};
  for (const [name, value] of Object.entries(fields)) item[name] = slot(value);
  return item;
}
function graph(options = {}) {
  function uriObject(id, value, className) {
    const uri = object(className, id,
      options.declaredBaseUri ? {} : {uriString: value});
    // A field declared android.net.Uri is wrapped as that base type even
    // though $className reports the runtime concrete subtype. Only cast can
    // expose that subtype's uriString field in this bridge-shaped fixture.
    if (options.declaredBaseUri && value !== undefined) uri.__concreteUriString = value;
    uri.toString = function () { throw new Error('target-toString-must-not-run'); };
    uri.getPath = function () { throw new Error('target-getPath-must-not-run'); };
    return uri;
  }
  const uriVm = uriObject('uri-vm', options.vmUri === undefined ? URI : options.vmUri,
    options.vmUriClass || CLASS.uri);
  const uriPresenter = uriObject('uri-presenter',
    options.presenterUri === undefined ? URI : options.presenterUri,
    options.presenterUriClass || CLASS.uri);
  const vmObject = object(CLASS.vm, 'vm', {uri: uriVm});
  const presenter = object(CLASS.presenter, 'presenter',
    {uri: uriPresenter, markPath: options.markPath === undefined ? null : options.markPath});
  const activity = object(CLASS.activity, 'activity', {
    mResumed: true, mFinished: false, mDestroyed: false,
    documentViewModel: vmObject, handWritePresenter: presenter
  });
  return {activity, vm: vmObject, presenter, uriVm, uriPresenter};
}
function run(options = {}) {
  const m = options.manifest || manifest();
  const wire = options.wire === undefined ? canonical(m) : options.wire;
  const bytes = options.bytes || Array.from(Buffer.from(wire, 'utf8'));
  const digest = options.digest || crypto.createHash('sha256').update(Buffer.from(bytes)).digest('hex');
  const g = options.graph || graph();
  const sent = [], retained = [], disposed = [];
  let chooseCalls = 0, sameCalls = 0, useCalls = 0, castCalls = 0;
  let pending = null, pendingPerform = null, timer = null;
  let clearCalls = 0;
  const context = {
    NATIVE_PAGE_DISPLAY0_IDENTITY_MANIFEST_UTF8: bytes,
    NATIVE_PAGE_DISPLAY0_IDENTITY_MANIFEST_SHA256: digest,
    Process: {arch: options.arch || 'arm64', pointerSize: options.pointerSize || 8,
      id: options.pid === undefined ? m.attachment.pid : options.pid},
    Java: {
      use(name) {
        useCalls++;
        assert([CLASS.uri, CLASS.hierarchicalUri].includes(name));
        return {name};
      },
      cast(value, klass) {
        castCalls++;
        assert([CLASS.uri, CLASS.hierarchicalUri].includes(klass.name));
        assert.strictEqual(klass.name, value.$className);
        if (options.castThrowAt === castCalls) throw new Error('sensitive-cast-error');
        if (value.__concreteUriString === undefined) return value;
        const concrete = Object.create(value);
        if (options.castMissingFieldAt !== castCalls) {
          concrete.uriString = slot(value.__concreteUriString);
        }
        return concrete;
      },
      retain(value) {
        const ordinal = retained.length + 1;
        if (options.retainThrowAt === ordinal) throw new Error('sensitive-retain-error');
        const copy = options.retainMalformedAt === ordinal ? {$h: null} : Object.create(value);
        copy.$dispose = function () {
          disposed.push(ordinal);
          if (options.disposeThrowAt === ordinal) throw new Error('sensitive-dispose-error');
        };
        retained.push(copy);
        return copy;
      },
      vm: {getEnv() {
        if (options.envThrow) throw new Error('sensitive-env-error');
        if (options.envUnavailable) return null;
        return {isSameObject(left, right) {
        sameCalls++;
        if (options.sameThrowAt === sameCalls) throw new Error('sensitive-same-error');
        if (options.sameFalseAt === sameCalls) return false;
        return left && right && left.id === right.id;
      }};
      }},
      choose(name, callbacks) {
        chooseCalls++;
        assert.strictEqual(name, CLASS.activity);
        for (const candidate of options.candidates || [g.activity]) {
          if (callbacks.onMatch(candidate) === 'stop') break;
        }
        if (options.chooseThrowAfterComplete) {
          callbacks.onComplete();
          throw new Error('sensitive-post-complete-choose-error');
        }
        if (options.chooseThrow) throw new Error('sensitive-choose-error');
        if (options.deferComplete) pending = callbacks.onComplete;
        else callbacks.onComplete();
      },
      perform(callback) {
        if (options.deferPerform) pendingPerform = callback;
        else callback();
      }
    },
    setTimeout(callback, delayMs) {
      assert.strictEqual(delayMs, m.coordinator.hardDeadlineMs);
      timer = callback;
      return 41;
    },
    clearTimeout(id) { assert.strictEqual(id, 41); clearCalls++; timer = null; },
    send(value) { sent.push(JSON.parse(JSON.stringify(value))); }
  };
  vm.runInNewContext(SOURCE, context, {filename: SOURCE_PATH, timeout: 1000});
  return {sent, retained, disposed, graph: g, get chooseCalls() { return chooseCalls; },
    get sameCalls() { return sameCalls; }, get useCalls() { return useCalls; },
    get castCalls() { return castCalls; }, get clearCalls() { return clearCalls; },
    complete() { assert(pending); const f = pending; pending = null; f(); },
    start() { assert(pendingPerform); const f = pendingPerform; pendingPerform = null; f(); },
    timeout() { assert(timer); const f = timer; timer = null; f(); }};
}
function success(result, expectedUseCalls = 1) {
  assert.strictEqual(result.sent.length, 2);
  const first = result.sent[0];
  assert.strictEqual(first.event, 'native_page_display0_identity');
  assert.strictEqual(first.authority, 'rtl-reader-display0-identity-observation-v1');
  assert.strictEqual(first.hardwareAdmission, false);
  assert.strictEqual(first.hostAssertionsOnly, true);
  assert.strictEqual(first.uriAgreementAndExpectedMatch, true);
  assert.strictEqual(first.heapWalks, 1);
  assert.strictEqual(first.retainedRootSamples, 2);
  assert.deepStrictEqual(result.sent[1],
    {event: 'native_page_display0_identity_complete', success: true});
  assert.strictEqual(result.chooseCalls, 1);
  assert.strictEqual(result.useCalls, expectedUseCalls);
  assert.strictEqual(result.castCalls, 4);
  assert.strictEqual(result.disposed.length, result.retained.length);
  assert.strictEqual(result.clearCalls, 1);
  assert(!JSON.stringify(result.sent).includes(URI));
  assert(!JSON.stringify(result.sent).includes(MARK));
  return first;
}
function failure(result, expectedPhase = null, expectedReason = null) {
  assert.strictEqual(result.sent.length, 2);
  const first = result.sent[0];
  assert.deepStrictEqual(Object.keys(first).sort(),
    ['code', 'event', 'phase', 'reason', 'schemaVersion']);
  assert.strictEqual(first.event, 'native_page_display0_identity_error');
  assert.strictEqual(first.schemaVersion, 1);
  assert.strictEqual(first.code, 'DISPLAY0_IDENTITY_REJECTED');
  assert(FAILURE_PAIRS.has(first.phase + '/' + first.reason));
  if (expectedPhase !== null) assert.strictEqual(first.phase, expectedPhase);
  if (expectedReason !== null) assert.strictEqual(first.reason, expectedReason);
  assert.deepStrictEqual(result.sent[1],
    {event: 'native_page_display0_identity_complete', success: false});
  assert.strictEqual(result.disposed.length, result.retained.length);
  assert(!JSON.stringify(result.sent).includes(URI));
  assert(!JSON.stringify(result.sent).includes(MARK));
  cases++;
}

success(run());
success(run({graph: graph({declaredBaseUri: true})}));
for (const vmUriClass of [CLASS.uri, CLASS.hierarchicalUri]) {
  for (const presenterUriClass of [CLASS.uri, CLASS.hierarchicalUri]) {
    success(run({graph: graph({declaredBaseUri: true, vmUriClass, presenterUriClass})}),
      vmUriClass === presenterUriClass ? 1 : 2);
  }
}
for (const role of ['vm', 'presenter']) {
  const subtypeOption = role === 'vm' ? 'vmUriClass' : 'presenterUriClass';
  const uriOption = role === 'vm' ? 'vmUri' : 'presenterUri';
  const absent = graph({declaredBaseUri: true,
    [subtypeOption]: CLASS.hierarchicalUri, [uriOption]: null});
  failure(run({graph: absent}), 'URI', 'WRAPPER');
  const noCacheField = graph({declaredBaseUri: true,
    [subtypeOption]: CLASS.hierarchicalUri});
  delete (role === 'vm' ? noCacheField.uriVm : noCacheField.uriPresenter)
    .__concreteUriString;
  failure(run({graph: noCacheField}), 'URI', 'WRAPPER');
  const uncached = graph({declaredBaseUri: true,
    [subtypeOption]: CLASS.hierarchicalUri, [uriOption]: 'NOT CACHED'});
  failure(run({graph: uncached}), 'URI', 'WRAPPER');
  const wrong = graph({declaredBaseUri: true,
    [subtypeOption]: CLASS.hierarchicalUri,
    [uriOption]: 'file:///private/other.pdf'});
  failure(run({graph: wrong}), 'URI', 'MISMATCH');
}
for (const className of ['android.net.Uri$OpaqueUri', 'android.net.Uri',
  'android.net.Uri$HierarchicalUriSuffix']) {
  failure(run({graph: graph({vmUriClass: className})}), 'URI', 'SUBTYPE');
  failure(run({graph: graph({presenterUriClass: className})}), 'URI', 'SUBTYPE');
}
for (const role of ['vm', 'presenter']) {
  for (const initial of [CLASS.uri, CLASS.hierarchicalUri]) {
    const changed = graph({declaredBaseUri: true,
      vmUriClass: initial, presenterUriClass: initial});
    const next = initial === CLASS.uri ? CLASS.hierarchicalUri : CLASS.uri;
    const replacement = object(next, role === 'vm' ? 'uri-vm' : 'uri-presenter');
    replacement.__concreteUriString = URI;
    if (role === 'vm') changed.vm.uri = sequence([changed.uriVm, replacement]);
    else changed.presenter.uri = sequence([changed.uriPresenter, replacement]);
    const result = run({graph: changed});
    failure(result, 'URI', 'SUBTYPE');
    assert.strictEqual(result.sameCalls, 2);
  }
}
failure(run({graph: graph({declaredBaseUri: true}), castThrowAt: 1}),
  'URI', 'WRAPPER');
failure(run({graph: graph({declaredBaseUri: true}), castMissingFieldAt: 1}),
  'URI', 'WRAPPER');
for (const castAt of [1, 2, 3, 4]) {
  failure(run({graph: graph({declaredBaseUri: true,
    vmUriClass: CLASS.hierarchicalUri,
    presenterUriClass: CLASS.hierarchicalUri}), castThrowAt: castAt}),
  'URI', 'WRAPPER');
  failure(run({graph: graph({declaredBaseUri: true,
    vmUriClass: CLASS.hierarchicalUri,
    presenterUriClass: CLASS.hierarchicalUri}), castMissingFieldAt: castAt}),
  'URI', 'WRAPPER');
}
const missingVmUri = graph();
delete missingVmUri.vm.uri;
failure(run({graph: missingVmUri}), 'IDENTITY', 'MISMATCH');
const missingPresenterUri = graph();
delete missingPresenterUri.presenter.uri;
failure(run({graph: missingPresenterUri}), 'IDENTITY', 'MISMATCH');
failure(run({disposeThrowAt: 1}), 'CLEANUP', 'FAILED');
failure(run({disposeThrowAt: 1, chooseThrowAfterComplete: true}),
  'CLEANUP', 'FAILED');
failure(run({retainMalformedAt: 2, disposeThrowAt: 2}),
  'CLEANUP', 'FAILED');
failure(run({envThrow: true}), 'BRIDGE', 'UNAVAILABLE');
failure(run({envUnavailable: true}), 'BRIDGE', 'UNAVAILABLE');
failure(run({pid: 9}), 'RUNTIME', 'MISMATCH');
assert.strictEqual(success(run({graph: graph({markPath: MARK})})).markPathPresent, true);
assert.strictEqual(success(run({manifest: manifest(MARK),
  graph: graph({markPath: MARK})})).markPathMatchedExpected, true);
failure(run({graph: graph({markPath: '/private/other.mark'})}));

for (const g of [graph({vmUri: 'file:///private/other.pdf'}),
  graph({presenterUri: 'file:///private/other.pdf'}),
  graph({vmUri: 'file:///private/other.pdf', presenterUri: 'file:///private/other.pdf'})]) {
  failure(run({graph: g}));
}
failure(run({manifest: manifest(MARK)}));
failure(run({candidates: []}), 'ACTIVITY', 'NONE');
const wrongCandidate = graph().activity;
wrongCandidate.$className = 'wrong.DocumentActivity';
failure(run({candidates: [wrongCandidate]}), 'IDENTITY', 'MISMATCH');
failure(run({candidates: [graph().activity, graph().activity]}),
  'ACTIVITY', 'MULTIPLE');
failure(run({candidates: Array.from({length: 65}, (_, i) => {
  const candidate = graph().activity;
  candidate.mResumed.value = false;
  candidate.$h.id = i;
  return candidate;
})}), 'ACTIVITY', 'LIMIT');

const stale = graph();
stale.activity.documentViewModel = sequence([stale.vm,
  object(CLASS.vm, 'replacement', {uri: stale.uriVm})]);
failure(run({graph: stale}));
const changedUri = graph();
changedUri.uriPresenter.uriString = sequence([URI, 'file:///private/other.pdf']);
failure(run({graph: changedUri}), 'URI', 'MISMATCH');
const changedMark = graph();
changedMark.presenter.markPath = sequence([null, '/private/other.mark']);
failure(run({graph: changedMark}));
const lifecycle = graph();
lifecycle.activity.mResumed = sequence([true, true, false]);
failure(run({graph: lifecycle}));
const badClass = graph(); badClass.vm.$className = 'wrong.ViewModel';
failure(run({graph: badClass}));
for (const option of [{sameFalseAt: 1}, {sameThrowAt: 1}, {retainThrowAt: 2},
  {retainMalformedAt: 2}, {disposeThrowAt: 1}, {chooseThrow: true},
  {chooseThrowAfterComplete: true}]) failure(run(option));
failure(run({arch: 'x86_64'}), 'RUNTIME', 'MISMATCH');
failure(run({pointerSize: 4}), 'RUNTIME', 'MISMATCH');

for (const mutate of [
  m => { m.schemaVersion = 2; },
  m => { m.extra = true; },
  m => { delete m.expected.documentUri; },
  m => { m.expected.documentUri = 'file:///private/other.pdf'; },
  m => { m.attachment.firmwareFingerprint = 'other'; },
  m => { m.attachment.pid = 0; },
  m => { m.attachment.startTimeTicks = '0'; },
  m => { m.coordinator.maxJavaChooseWalks = 2; },
  m => { m.coordinator.retainedRootSamples = 1; },
  m => { m.coordinator.noRetry = false; },
  m => { m.coordinator.hardDeadlineMs = 10001; },
  m => { m.expected.markPath = '/private/other.mark'; }
]) { const m = manifest(); mutate(m); failure(run({manifest: m})); }
failure(run({wire: JSON.stringify(manifest(), null, 2)}));
failure(run({wire: '{"authority":"a","authority":"b"}'}));
failure(run({digest: '0'.repeat(64)}));
failure(run({bytes: new Array(4097).fill(0)}));
failure(run({wire: canonical(manifest()).replace('com.supernote.document', 'Dócument')}));

const deferred = run({deferComplete: true});
assert.strictEqual(deferred.sent.length, 0);
deferred.complete(); success(deferred);
const timed = run({deferComplete: true});
timed.timeout(); failure(timed, 'DEADLINE', 'EXPIRED');
timed.complete(); assert.strictEqual(timed.sent.length, 2);
const beforeJava = run({deferPerform: true});
beforeJava.timeout(); failure(beforeJava);
beforeJava.start(); assert.strictEqual(beforeJava.chooseCalls, 0);

// A single hard-coded choose, no target setters, hooks, file reads, or raw
// path serialization. The exact concrete-URI cast is read-only JNI.
// The timer is the sole observer-side deadline mechanism.
const stripped = SOURCE.replace(/'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`/g, '')
  .replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
assert.strictEqual((stripped.match(/Java\s*\.\s*choose\s*\(/g) || []).length, 1);
for (const forbidden of ['Interceptor', 'Stalker', 'NativeFunction', 'NativeCallback',
  'Memory', 'Java.registerClass', 'Java.enumerateLoadedClasses',
  'File(', 'Socket(', 'recv(', 'rpc.', '.implementation', '.$new(', '.$init(']) {
  assert(!stripped.includes(forbidden), forbidden);
}
assert.strictEqual((stripped.match(/Java\s*\.\s*use\s*\(/g) || []).length, 1);
assert(/need\s*\(\s*subtype\s*===\s*CLASS\.uri\s*\|\|\s*subtype\s*===\s*CLASS\.hierarchicalUri\s*\)/
  .test(stripped));
assert(/Java\s*\.\s*use\s*\(\s*subtype\s*\)/.test(stripped));
assert.strictEqual((stripped.match(/Java\s*\.\s*cast\s*\(/g) || []).length, 1);
assert(/Java\s*\.\s*cast\s*\(\s*value\s*,\s*concreteUriClasses\s*\[\s*subtype\s*\]\s*\)/
  .test(stripped));
assert(!/\.\s*(?:toString|getPath)\s*\(/.test(stripped.replace(/v\.toString\(16\)/g, '')));
assert(!/\.\s*value\s*=/.test(stripped));
console.log(`display-0 identity observer: ${cases} negative cases and success paths passed`);
