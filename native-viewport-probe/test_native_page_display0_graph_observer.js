'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SOURCE = fs.readFileSync(path.join(__dirname,
  'native_page_display0_graph_observer.js'), 'utf8');
const SOURCE_SHA = crypto.createHash('sha256').update(SOURCE).digest('hex');
const URI = 'file:///storage/emulated/0/Document/RTL_DISPLAY0_CAPTURE_20260927.pdf';
const MARK = '/storage/emulated/0/Document/RTL_DISPLAY0_CAPTURE_20260927.pdf.mark';
const C = {
  activity: 'com.supernote.document.document.DocumentActivity',
  vm: 'com.supernote.document.document.DocumentViewModel',
  presenter: 'com.supernote.document.handwrite.HandWritePresenter',
  page: 'com.supernote.document.document.PageInfo',
  matrix: 'com.artifex.mupdf.fitz.Matrix',
  rect: 'android.graphics.RectF', bitmap: 'android.graphics.Bitmap',
  handWriteView: 'com.supernote.document.handwrite.HandWriteView',
  documentImage: 'com.supernote.document.utils.view.DocumentImageView',
  digestImage: 'com.supernote.document.utils.view.DigestImageView',
  contentView: 'android.widget.FrameLayout', documentLayout: 'android.widget.RelativeLayout',
  attachInfo: 'android.view.View$AttachInfo',
  stringUri: 'android.net.Uri$StringUri',
  hierarchicalUri: 'android.net.Uri$HierarchicalUri'
};
const FAILURES = new Set([
  'MANIFEST/INVALID', 'RUNTIME/MISMATCH', 'BRIDGE/UNAVAILABLE',
  'JAVA_CHOOSE/FAILED', 'ACTIVITY/NONE', 'ACTIVITY/MULTIPLE',
  'ACTIVITY/LIMIT', 'GRAPH/MISMATCH', 'URI/SUBTYPE', 'URI/WRAPPER',
  'URI/MISMATCH', 'CLEANUP/FAILED', 'DEADLINE/EXPIRED', 'OUTPUT/OVERSIZE'
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
  return {schemaVersion: 1, authority: 'rtl-reader-display0-graph-manifest-v1',
    attachment: {packageName: 'com.supernote.document',
      processName: 'com.supernote.document', pid: 2256, startTimeTicks: '4134',
      firmwareFingerprint:
        'Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys',
      observerSha256: SOURCE_SHA},
    expected: {documentUri: URI, markPath},
    coordinator: {maxJavaChooseWalks: 1, retainedRootSamples: 2,
      hardDeadlineMs: 1000, detachOnDeadline: true, abortOnAnyError: true,
      noRetry: true}};
}
function slot(value) { return {value}; }
function sequence(values) {
  let next = 0;
  return {get value() { return values[Math.min(next++, values.length - 1)]; }};
}
function object(name, id, fields = {}) {
  const result = {$className: name, $h: {id}};
  for (const [field, value] of Object.entries(fields)) result[field] = slot(value);
  return result;
}
function graph(options = {}) {
  const shape = object(C.rect, 'crop', {left: 10, top: 20, right: 220, bottom: 310});
  const matrix = object(C.matrix, 'matrix', {a: 1, b: -0, c: 0,
    d: 1, e: 4, f: 6});
  const inverse = object(C.matrix, 'inverse', {a: 1, b: 0, c: 0,
    d: 1, e: -4, f: -6});
  const origin = object(C.bitmap, 'origin', {mWidth: 1404, mHeight: 1872});
  const display = object(C.bitmap, 'display', {mWidth: 1404, mHeight: 1872});
  const digest = object(C.bitmap, 'digest', {mWidth: 500, mHeight: 500});
  const penBitmap = object(C.bitmap, 'pen-bitmap', {mWidth: 1404, mHeight: 1872});
  const page = object(C.page, 'page', {page: 1, ctm: matrix, revertCtm: inverse,
    trimmingRect: shape, originBitmap: origin, displayBitmap: display,
    digestBitmap: digest, offsetX: 12, offsetY: -7, scale: 1.25});
  function uri(id, name, cached) {
    const value = object(name, id, options.declaredBaseUri ? {} : {uriString: cached});
    if (options.declaredBaseUri) value.__concreteUriString = cached;
    value.toString = () => { throw new Error('target URI method invoked'); };
    value.getPath = () => { throw new Error('target URI method invoked'); };
    return value;
  }
  const vmUri = uri('uri-vm', options.vmUriClass || C.stringUri,
    options.vmUri === undefined ? URI : options.vmUri);
  const presenterUri = uri('uri-presenter',
    options.presenterUriClass || C.stringUri,
    options.presenterUri === undefined ? URI : options.presenterUri);
  const viewModel = object(C.vm, 'vm', {uri: vmUri, currentPage: 1,
    pageCount: 7, pageInfo: page});
  const presenter = object(C.presenter, 'presenter', {uri: presenterUri,
    currentPage: 1, markPath: options.markPath === undefined ? null : options.markPath,
    screenRotation: 0, bitmap: penBitmap});
  const views = {}, attaches = {};
  for (const name of ['handWriteView', 'documentImage', 'digestImage',
    'contentView', 'documentLayout']) {
    const attach = object(C.attachInfo, name + '-attach');
    const view = object(C[name], name, {mLeft: 0, mTop: 0,
      mRight: 1404, mBottom: 1872, mWindowAttachCount: 1,
      mAttachInfo: attach});
    views[name] = view; attaches[name] = attach;
  }
  const activity = object(C.activity, 'activity', {mResumed: true,
    mFinished: false, mDestroyed: false,
    documentViewModel: viewModel, handWritePresenter: presenter,
    handWriteView: views.handWriteView, mImage: views.documentImage,
    digestImage: views.digestImage, mContentView: views.contentView,
    documentViewLayout: views.documentLayout});
  return {activity, viewModel, presenter, page, vmUri, presenterUri,
    views, attaches, matrix, inverse, shape, origin, display, digest, penBitmap};
}
function run(options = {}) {
  const m = options.manifest || manifest();
  const wire = options.wire === undefined ? canonical(m) : options.wire;
  const bytes = options.bytes || Array.from(Buffer.from(wire, 'utf8'));
  const digest = options.digest || crypto.createHash('sha256')
    .update(Buffer.from(bytes)).digest('hex');
  const g = options.graph || graph();
  const sent = [], retained = [], disposed = [];
  let chooseCalls = 0, sameCalls = 0, castCalls = 0, useCalls = 0;
  let pending = null, pendingPerform = null, timer = null, clearCalls = 0;
  const context = {
    NATIVE_PAGE_DISPLAY0_GRAPH_MANIFEST_UTF8: bytes,
    NATIVE_PAGE_DISPLAY0_GRAPH_MANIFEST_SHA256: digest,
    Process: {arch: options.arch || 'arm64',
      pointerSize: options.pointerSize || 8,
      id: options.pid === undefined ? m.attachment.pid : options.pid},
    Java: {
      use(name) { useCalls++; assert([C.stringUri, C.hierarchicalUri].includes(name));
        return {name}; },
      cast(value, type) {
        castCalls++;
        assert.strictEqual(value.$className, type.name);
        if (options.castThrowAt === castCalls) throw new Error('cast');
        if (value.__concreteUriString === undefined) return value;
        const concrete = Object.create(value);
        concrete.uriString = slot(value.__concreteUriString);
        return concrete;
      },
      retain(value) {
        const ordinal = retained.length + 1;
        if (options.retainThrowAt === ordinal) throw new Error('retain');
        const copy = Object.create(value);
        copy.$dispose = () => {
          disposed.push(ordinal);
          if (options.disposeThrowAt === ordinal) throw new Error('dispose');
        };
        retained.push(copy);
        return copy;
      },
      vm: {getEnv() {
        if (options.envUnavailable) return null;
        return {isSameObject(left, right) {
          sameCalls++;
          if (options.sameFalseAt === sameCalls) return false;
          return left && right && left.id === right.id;
        }};
      }},
      choose(name, callbacks) {
        chooseCalls++;
        assert.strictEqual(name, C.activity);
        for (const candidate of options.candidates || [g.activity]) {
          if (callbacks.onMatch(candidate) === 'stop') break;
        }
        if (options.chooseThrowAfterComplete) {
          callbacks.onComplete();
          throw new Error('choose post-completion');
        }
        if (options.chooseThrow) throw new Error('choose');
        if (options.deferComplete) pending = callbacks.onComplete;
        else callbacks.onComplete();
      },
      perform(callback) {
        if (options.deferPerform) pendingPerform = callback;
        else callback();
      }
    },
    setTimeout(callback, timeout) {
      assert.strictEqual(timeout, m.coordinator.hardDeadlineMs);
      timer = callback; return 41;
    },
    clearTimeout(id) { assert.strictEqual(id, 41); clearCalls++; timer = null; },
    send(value) { sent.push(JSON.parse(JSON.stringify(value))); }
  };
  vm.runInNewContext(SOURCE, context, {timeout: 1000});
  return {sent, g, retained, disposed,
    get chooseCalls() { return chooseCalls; },
    get sameCalls() { return sameCalls; },
    get castCalls() { return castCalls; },
    get useCalls() { return useCalls; },
    get clearCalls() { return clearCalls; },
    complete() { assert(pending); pending(); pending = null; },
    start() { assert(pendingPerform); pendingPerform(); pendingPerform = null; },
    timeout() { assert(timer); timer(); timer = null; }};
}
function success(result) {
  assert.strictEqual(result.sent.length, 2);
  const value = result.sent[0];
  assert.strictEqual(value.event, 'native_page_display0_graph');
  assert.strictEqual(value.authority, 'rtl-reader-display0-graph-observation-v1');
  assert.strictEqual(value.observationOnly, true);
  assert.strictEqual(value.hardwareAdmission, false);
  assert.strictEqual(value.semanticCalibration, false);
  assert.strictEqual(value.runtimePidMatched, true);
  assert.strictEqual(value.graphStable, true);
  assert.deepStrictEqual(value.rawPageTuple, [1, 7, 1, 1]);
  if (value.pageInfo.ctm !== null)
    assert.strictEqual(value.pageInfo.ctm[1], '0x8000000000000000');
  assert.deepStrictEqual(Object.keys(value.views).sort(),
    ['contentView', 'digestImage', 'documentImage',
      'documentLayout', 'handWriteView']);
  assert.strictEqual(typeof value.pageInfo.bitmaps.origin.present, 'boolean');
  assert.strictEqual(result.sameCalls > 10, true);
  assert.strictEqual(result.chooseCalls, 1);
  assert.strictEqual(result.disposed.length, result.retained.length);
  assert.strictEqual(result.clearCalls, 1);
  assert.deepStrictEqual(result.sent[1],
    {event: 'native_page_display0_graph_complete', success: true});
  assert(Buffer.byteLength(JSON.stringify(value)) <= 8192);
  assert(!JSON.stringify(result.sent).includes(URI));
  assert(!JSON.stringify(result.sent).includes(MARK));
  cases++;
  return value;
}
function failure(result, wanted = null) {
  assert.strictEqual(result.sent.length, 2);
  const value = result.sent[0];
  assert.deepStrictEqual(Object.keys(value).sort(),
    ['code', 'event', 'phase', 'reason', 'schemaVersion']);
  assert.strictEqual(value.event, 'native_page_display0_graph_error');
  assert.strictEqual(value.code, 'DISPLAY0_GRAPH_REJECTED');
  assert(FAILURES.has(value.phase + '/' + value.reason));
  if (wanted) assert.strictEqual(value.phase + '/' + value.reason, wanted);
  assert.deepStrictEqual(result.sent[1],
    {event: 'native_page_display0_graph_complete', success: false});
  assert.strictEqual(result.disposed.length, result.retained.length);
  assert(!JSON.stringify(result.sent).includes(URI));
  assert(!JSON.stringify(result.sent).includes(MARK));
  cases++;
}

success(run());
for (const a of [C.stringUri, C.hierarchicalUri]) {
  for (const b of [C.stringUri, C.hierarchicalUri]) {
    const result = run({graph: graph({declaredBaseUri: true,
      vmUriClass: a, presenterUriClass: b})});
    success(result);
    assert.strictEqual(result.useCalls, a === b ? 1 : 2);
    assert.strictEqual(result.castCalls, 4);
  }
}
const nullable = graph();
nullable.page.ctm = slot(null);
nullable.page.revertCtm = slot(null);
nullable.page.trimmingRect = slot(null);
nullable.page.displayBitmap = slot(null);
nullable.presenter.bitmap = slot(null);
nullable.activity.digestImage = slot(null);
const nullableRecord = success(run({graph: nullable}));
assert.strictEqual(nullableRecord.pageInfo.ctm, null);
assert.strictEqual(nullableRecord.pageInfo.bitmaps.display.present, false);
assert.strictEqual(nullableRecord.views.digestImage.present, false);

for (const [field, value, pair] of [
  ['uri', null, 'URI/SUBTYPE'],
  ['uri', object('android.net.Uri$OpaqueUri', 'opaque'), 'URI/SUBTYPE']
]) {
  const g = graph(); g.viewModel[field] = slot(value);
  failure(run({graph: g}), pair);
}
for (const bad of ['NOT CACHED', 'file:///private/wrong.pdf']) {
  const g = graph({declaredBaseUri: true, vmUriClass: C.hierarchicalUri,
    vmUri: bad});
  failure(run({graph: g}), bad === 'NOT CACHED' ?
    'URI/WRAPPER' : 'URI/MISMATCH');
}
for (const field of ['ctm', 'revertCtm', 'displayBitmap', 'trimmingRect']) {
  const g = graph();
  const previous = g.page[field].value;
  const replacement = object(previous.$className, 'replacement',
    Object.fromEntries(Object.keys(previous).filter(k => !k.startsWith('$'))
      .filter(k => previous[k] && 'value' in previous[k])
      .map(k => [k, previous[k].value])));
  g.page[field] = sequence([previous, replacement]);
  failure(run({graph: g}), 'GRAPH/MISMATCH');
}
for (const field of ['documentViewModel', 'handWritePresenter', 'mImage']) {
  const g = graph();
  const previous = g.activity[field].value;
  g.activity[field] = sequence([previous,
    object(previous.$className, 'replacement')]);
  failure(run({graph: g}), 'GRAPH/MISMATCH');
}
const changedPage = graph();
changedPage.viewModel.currentPage = sequence([1, 2]);
failure(run({graph: changedPage}), 'GRAPH/MISMATCH');
const nonfinite = graph();
nonfinite.matrix.a = slot(Infinity);
failure(run({graph: nonfinite}), 'GRAPH/MISMATCH');
const nanScale = graph();
nanScale.page.scale = slot(NaN);
failure(run({graph: nanScale}), 'GRAPH/MISMATCH');
const badBitmap = graph();
badBitmap.origin.mWidth = slot(0);
failure(run({graph: badBitmap}), 'GRAPH/MISMATCH');
const wrongView = graph();
wrongView.activity.mImage = slot(object('android.view.View', 'wrong-view'));
failure(run({graph: wrongView}), 'GRAPH/MISMATCH');
failure(run({pid: 9}), 'RUNTIME/MISMATCH');
failure(run({envUnavailable: true}), 'BRIDGE/UNAVAILABLE');
failure(run({candidates: []}), 'ACTIVITY/NONE');
const duplicate = graph();
failure(run({graph: duplicate, candidates: [duplicate.activity, duplicate.activity]}),
  'ACTIVITY/MULTIPLE');
failure(run({chooseThrow: true}), 'JAVA_CHOOSE/FAILED');
failure(run({chooseThrowAfterComplete: true}), 'JAVA_CHOOSE/FAILED');
failure(run({sameFalseAt: 1}), 'GRAPH/MISMATCH');
failure(run({castThrowAt: 1}), 'URI/WRAPPER');
failure(run({retainThrowAt: 1}), 'BRIDGE/UNAVAILABLE');
failure(run({disposeThrowAt: 1}), 'CLEANUP/FAILED');
const late = run({deferComplete: true});
assert.strictEqual(late.sent.length, 0);
late.timeout();
failure(late, 'DEADLINE/EXPIRED');
late.complete();
assert.strictEqual(late.sent.length, 2);
const delayed = run({deferPerform: true});
assert.strictEqual(delayed.sent.length, 0);
delayed.start();
success(delayed);
const malformed = manifest();
malformed.extra = true;
failure(run({manifest: malformed}), 'MANIFEST/INVALID');
failure(run({wire: '{"a":1,"a":2}'}), 'MANIFEST/INVALID');
failure(run({digest: '0'.repeat(64)}), 'MANIFEST/INVALID');
console.log('PASS display-0 graph observer: ' + cases + ' bounded cases');
