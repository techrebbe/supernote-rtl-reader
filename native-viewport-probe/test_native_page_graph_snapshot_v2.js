'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SOURCE_PATH = path.join(__dirname, 'native_page_graph_snapshot_v2.js');
const SOURCE = fs.readFileSync(SOURCE_PATH, 'utf8');
const SOURCE_SHA256 = crypto.createHash('sha256').update(SOURCE).digest('hex');
const Z64 = '0'.repeat(64);
const CLASS = Object.freeze({
  activity: 'com.supernote.document.document.DocumentActivity',
  viewModel: 'com.supernote.document.document.DocumentViewModel',
  pageInfo: 'com.supernote.document.document.PageInfo',
  presenter: 'com.supernote.document.handwrite.HandWritePresenter',
  handWriteView: 'com.supernote.document.handwrite.HandWriteView',
  imageView: 'com.supernote.document.utils.view.DocumentImageView',
  digestImageView: 'com.supernote.document.utils.view.DigestImageView',
  contentView: 'android.view.View',
  documentLayout: 'android.widget.RelativeLayout',
  matrix: 'com.artifex.mupdf.fitz.Matrix', rect: 'android.graphics.RectF',
  bitmap: 'android.graphics.Bitmap', note: 'com.example.libsupernote.SuperNoteNote',
  client: 'com.supernote.document.handwrite.HandWriteClient',
  uri: 'android.net.Uri$StringUri', attachInfo: 'android.view.View$AttachInfo'
});

function canonical(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    assert(Number.isSafeInteger(value) && !Object.is(value, -0));
    return String(value);
  }
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((key) => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
}

function stat(seed) {
  return {device: '17', inode: String(1000 + seed), mode: '33188', uid: 1000,
    gid: 1000, mtimeNs: '1700000000000000000', ctimeNs: '1700000000000000001'};
}

function manifest() {
  const pdfPath = '/storage/emulated/0/Document/graph-v2.pdf';
  const uri = 'file://' + pdfPath;
  return {
    schemaVersion: 2,
    authority: 'rtl-reader-native-page-graph-manifest-v2',
    attachment: {
      packageName: 'com.supernote.document', processName: 'Document', pid: 3141,
      startTimeTicks: '9000001',
      firmwareFingerprint: 'Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys',
      apk: {path: '/data/app/document/base.apk', size: 138486560,
        sha256: 'f008c86ddc42008c36b431410cbc3b29057b4aad9bc26c3577ee13b39b230482'},
      framework: {path: '/system/framework/framework.jar', size: 30186065,
        sha256: 'c3a525a7ef16363a93412182cce693f46dfa1395a570e9620da0d4e27a59631d'},
      module: {name: 'libart.so', path: '/apex/com.android.runtime/lib64/libart.so',
        size: 1234567, sha256: '1'.repeat(64)}, observerSha256: SOURCE_SHA256
    },
    externalSession: {
      authority: 'rtl-reader-native-page-external-session-v2',
      authorizedSerial: 'SN078C10015092', taskId: 41, displayId: 0,
      hostSessionId: 'host-session-v2:0001', displayGeneration: 9
    },
    files: {
      authority: 'rtl-reader-native-page-file-authority-v1',
      verification: 'external-before-and-after-exact',
      originalPdf: {present: true, path: pdfPath, size: '4096', sha256: '2'.repeat(64),
        stat: stat(1), documentUri: uri,
        uriResolution: {authority: 'rtl-reader-file-uri-resolution-v1', documentUri: uri,
          resolvedPath: pdfPath, evidenceSha256: '3'.repeat(64)}},
      mark: {present: true, path: pdfPath + '.mark', size: '512', sha256: '4'.repeat(64),
        stat: stat(2)}
    },
    coordinator: {
      authority: 'rtl-reader-native-page-graph-coordinator-v2',
      observerSessionId: 'observer-session-v2:0001',
      absoluteMonotonicDeadlineNs: '2000000', hardDeadlineMs: 250,
      maxJavaChooseWalks: 1, retainedRootSamples: 2, detachOnDeadline: true,
      abortOnAnyError: true, verifyTargetLivenessAfter: true, noRetry: true
    },
    expected: {documentUri: uri, calibrationProfile: {
      authority: 'rtl-reader-native-page-calibration-raw-v1', status: 'calibration-only',
      pageIndexSemantics: 'independent-raw', matrixSemantics: 'independent-raw'
    }}
  };
}

function slot(value) { return {value}; }
function sequenceSlot(values) {
  let index = 0;
  return {get value() { const selected = values[Math.min(index, values.length - 1)]; index++; return selected; }};
}
function jobject(className, id, fields) {
  const value = {$className: className, $h: {id}};
  for (const [key, item] of Object.entries(fields || {})) value[key] = slot(item);
  return value;
}
function jlong(hex) {
  return {toString(radix) { assert.strictEqual(radix, 16); return hex; }};
}

function graph(options) {
  options = options || {};
  let serial = 1;
  const edges = [];
  const refs = {};
  function make(className, fields, name) {
    const value = jobject(className, name + ':' + serial++, fields);
    refs[name] = value;
    return value;
  }
  function edge(parent, field, child, name, nullable) {
    parent[field] = slot(child);
    edges.push({name, parent, field, child, nullable: !!nullable, expectedClass: child && child.$className});
  }
  function rect(name, values) {
    const v = values || [0, 0, 100, 200];
    return make(CLASS.rect, {left: v[0], top: v[1], right: v[2], bottom: v[3]}, name);
  }
  function matrix(name, values) {
    const v = values || [1, 0, 0, 1, 0, 0];
    return make(CLASS.matrix, {a: v[0], b: v[1], c: v[2], d: v[3], e: v[4], f: v[5]}, name);
  }
  function bitmap(name, width, height, pointer) {
    return make(CLASS.bitmap, {mWidth: width || 1404, mHeight: height || 1872,
      mNativePtr: jlong(pointer || '1234')}, name);
  }
  function view(name, className, bounds) {
    const b = bounds || [0, 0, 1404, 1872];
    const attach = make(CLASS.attachInfo, {}, name + 'AttachInfo');
    const v = make(className, {mLeft: b[0], mTop: b[1], mRight: b[2], mBottom: b[3],
      mScrollX: 0, mScrollY: 0, mWindowAttachCount: 2}, name);
    edge(v, 'mAttachInfo', attach, name + 'AttachInfo', false);
    return v;
  }

  const pageInfo = make(CLASS.pageInfo, {page: 3, offsetX: 11, offsetY: -7, scale: -0}, 'pageInfo');
  edge(pageInfo, 'ctm', matrix('ctm', [2, 0, 0, 3, 17, 19]), 'ctm');
  edge(pageInfo, 'revertCtm', matrix('revertCtm', [7, 1, 2, 11, 23, 29]), 'revertCtm');
  edge(pageInfo, 'trimmingRect', rect('pageTrimmingRect', [1, 2, 99, 198]), 'pageTrimmingRect');
  edge(pageInfo, 'originBitmap', bitmap('originBitmap'), 'originBitmap', true);
  edge(pageInfo, 'displayBitmap', null, 'displayBitmap', true);
  edge(pageInfo, 'digestBitmap', bitmap('digestBitmap', 700, 936, '0'), 'digestBitmap', true);

  const uri = manifest().expected.documentUri;
  const vmUri = make(CLASS.uri, {uriString: uri}, 'viewModelUri');
  const presenterUri = make(CLASS.uri, {uriString: uri}, 'presenterUri');
  const viewModel = make(CLASS.viewModel, {currentPage: 2, pageCount: 7}, 'viewModel');
  edge(viewModel, 'pageInfo', pageInfo, 'pageInfo');
  edge(viewModel, 'uri', vmUri, 'viewModelUri');
  for (const name of ['scaleRect', 'portraitScaleRect', 'landscapeScaleRect', 'showRect',
    'trimmingRect', 'landscapeTrimmingRect']) edge(viewModel, name, rect(name), name);

  const binder = make('android.os.BinderProxy', {}, 'binder');
  const sfBinder = make('android.os.BinderProxy', {}, 'sfBinder');
  const client = make(CLASS.client, {}, 'client');
  edge(client, 'iBinder', binder, 'binder', true);
  edge(client, 'mSFBinder', sfBinder, 'sfBinder', true);
  const note = make(CLASS.note, {pointer: jlong('feed')}, 'note');
  const presenter = make(CLASS.presenter, {currentPage: 4,
    markPath: manifest().files.mark.path, screenRotation: 1}, 'presenter');
  edge(presenter, 'uri', presenterUri, 'presenterUri');
  edge(presenter, 'bitmap', bitmap('presenterBitmap'), 'presenterBitmap', true);
  edge(presenter, 'superNoteNote', note, 'note');
  edge(presenter, 'handWriteClient', client, 'client');

  const handWriteView = view('handWriteView', CLASS.handWriteView);
  const image = view('image', CLASS.imageView);
  const digestImage = view('digestImage', CLASS.digestImageView);
  const contentView = view('contentView', CLASS.contentView);
  const documentLayout = view('documentLayout', CLASS.documentLayout);
  const activity = make(CLASS.activity, {mResumed: true, mFinished: false, mDestroyed: false}, 'activity');
  edge(activity, 'documentViewModel', viewModel, 'viewModel');
  edge(activity, 'handWritePresenter', presenter, 'presenter');
  edge(activity, 'handWriteView', handWriteView, 'handWriteView');
  edge(activity, 'mImage', image, 'image');
  edge(activity, 'digestImage', digestImage, 'digestImage');
  edge(activity, 'mContentView', contentView, 'contentView');
  edge(activity, 'documentViewLayout', documentLayout, 'documentLayout');
  return {activity, candidates: options.candidates || [activity], edges, refs};
}

function execute(options) {
  options = options || {};
  const m = options.manifest || manifest();
  const wire = options.wire === undefined ? canonical(m) : options.wire;
  const bytes = options.bytes || Array.from(Buffer.from(wire, 'utf8'));
  const digest = options.digest || crypto.createHash('sha256').update(Buffer.from(bytes)).digest('hex');
  const g = options.graph || graph();
  const sent = [];
  const retained = [];
  const disposed = [];
  let chooseCalls = 0;
  let pendingComplete = null;
  let sameCalls = 0;
  let sendCalls = 0;
  const context = {
    NATIVE_PAGE_GRAPH_MANIFEST_UTF8: bytes,
    NATIVE_PAGE_GRAPH_MANIFEST_SHA256: digest,
    Process: {
      arch: options.arch || 'arm64', pointerSize: options.pointerSize || 8,
      id: options.pid || m.attachment.pid,
      getModuleByName(name) {
        if (options.moduleThrow) throw new Error('module');
        return options.module || {name, path: m.attachment.module.path, size: m.attachment.module.size};
      }
    },
    Java: {
      retain(value) {
        if (options.retainThrowAt === retained.length + 1) throw new Error('retain');
        const ordinal = retained.length + 1;
        const copy = options.retainMalformedAt === ordinal ? {$h: null} : Object.create(value);
        copy.$dispose = function () {
          disposed.push(ordinal);
          if (options.disposeThrowAt === ordinal) throw new Error('dispose');
        };
        retained.push(copy);
        return copy;
      },
      vm: {getEnv() { return {isSameObject(left, right) {
        sameCalls++;
        if (options.sameThrowAt === sameCalls) throw new Error('same');
        if (options.sameFalseAt === sameCalls) return false;
        return left && right && left.id === right.id;
      }};}},
      choose(className, callbacks) {
        chooseCalls++;
        assert.strictEqual(className, CLASS.activity);
        for (const candidate of g.candidates) {
          if (callbacks.onMatch(candidate) === 'stop') break;
        }
        if (options.deferComplete) pendingComplete = callbacks.onComplete;
        else callbacks.onComplete();
      },
      perform(callback) { callback(); }
    },
    send(message) {
      sendCalls++;
      if (options.sendThrowAt === sendCalls) throw new Error('send');
      sent.push(JSON.parse(JSON.stringify(message)));
    },
    console
  };
  vm.runInNewContext(SOURCE, context, {filename: SOURCE_PATH, timeout: 1000});
  return {sent, retained, disposed, get chooseCalls() { return chooseCalls; },
    get sameCalls() { return sameCalls; }, get sendCalls() { return sendCalls; }, complete() {
    assert(pendingComplete); pendingComplete(); pendingComplete = null;
  }, graph: g, manifest: m};
}

function assertSuccess(result) {
  assert.strictEqual(result.sent.length, 2);
  assert.strictEqual(result.sent[0].event, 'native_page_graph_snapshot');
  assert.deepStrictEqual(result.sent[1], {event: 'native_page_graph_snapshot_complete', success: true});
  assert.strictEqual(result.chooseCalls, 1);
  assert(result.sameCalls > 0);
  assert.strictEqual(result.disposed.length, result.retained.length);
  assert.deepStrictEqual(result.disposed, Array.from({length: result.retained.length}, (_, i) => result.retained.length - i));
  return result.sent[0];
}
function assertFailure(result) {
  assert.deepStrictEqual(result.sent, [
    {event: 'native_page_graph_snapshot_error', schemaVersion: 2, code: 'GRAPH_SNAPSHOT_REJECTED'},
    {event: 'native_page_graph_snapshot_complete', success: false}
  ]);
  assert.strictEqual(result.disposed.length, result.retained.length);
}

let tests = 0;
let cases = 0;
function test(name, body) {
  try { body(); tests++; process.stdout.write('.'); }
  catch (error) { error.message = name + ': ' + error.message; throw error; }
}
function each(name, values, body) {
  test(name, () => { for (const value of values) { body(value); cases++; } });
}
function clone(value) { return JSON.parse(JSON.stringify(value)); }
function at(value, dotted) {
  const parts = dotted.split('.');
  let cursor = value;
  for (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];
  return {parent: cursor, key: parts[parts.length - 1]};
}
function scalarFields(g) {
  const referenceSlots = new Set(g.edges.map((edge) => edge.parent[edge.field]));
  const result = [];
  for (const [name, object] of Object.entries(g.refs)) {
    for (const [field, value] of Object.entries(object)) {
      if (field[0] === '$' || value === null || typeof value !== 'object' ||
          !Object.prototype.hasOwnProperty.call(value, 'value') || referenceSlots.has(value)) continue;
      result.push({name, object, field, slot: value});
    }
  }
  return result;
}
function changedScalar(value) {
  if (typeof value === 'boolean') return !value;
  if (typeof value === 'number') return Object.is(value, -0) ? 0 : value + 1;
  if (typeof value === 'string') return value + '.mutated';
  if (value && typeof value.toString === 'function') {
    const current = value.toString(16);
    return jlong(current === 'beef' ? 'feed' : 'beef');
  }
  throw new Error('unsupported scalar fixture');
}
function keys(value) { return Object.keys(value).sort(); }
function exact(value, expected) {
  assert(value !== null && typeof value === 'object' && !Array.isArray(value));
  assert.deepStrictEqual(keys(value), expected.slice().sort());
}
function stringValue(value) { assert.strictEqual(typeof value, 'string'); assert(value.length > 0); }
function integerValue(value) { assert(Number.isSafeInteger(value) && !Object.is(value, -0)); }
function booleanValue(value) { assert.strictEqual(typeof value, 'boolean'); }
function shaValue(value) { assert.strictEqual(typeof value, 'string'); assert(/^[0-9a-f]{64}$/.test(value)); }
function binaryValue(value) {
  exact(value, ['binary64']); stringValue(value.binary64); assert(/^0x[0-9a-f]{16}$/.test(value.binary64));
  const decoded = Buffer.from(value.binary64.slice(2), 'hex').readDoubleBE(0);
  assert(Number.isFinite(decoded) && Math.abs(decoded) <= 1e12);
  return decoded;
}
function pointerValue(value) {
  exact(value, ['present', 'value']); booleanValue(value.present);
  if (value.present) { stringValue(value.value); assert(/^0x[0-9a-f]{16}$/.test(value.value)); }
  else assert.strictEqual(value.value, null);
}
function statValue(value) {
  exact(value, ['device', 'inode', 'mode', 'uid', 'gid', 'mtimeNs', 'ctimeNs']);
  for (const name of ['device', 'inode', 'mode', 'mtimeNs', 'ctimeNs']) {
    stringValue(value[name]); assert(/^(0|[1-9][0-9]*)$/.test(value[name]));
  }
  integerValue(value.uid); integerValue(value.gid);
}
function fileValue(value, original) {
  const expected = ['present', 'path', 'size', 'sha256', 'stat'];
  if (original) expected.push('documentUri', 'uriResolution');
  exact(value, expected); booleanValue(value.present);
  if (!value.present) {
    assert.strictEqual(value.path, null); assert.strictEqual(value.size, null);
    assert.strictEqual(value.sha256, null); assert.strictEqual(value.stat, null); return;
  }
  stringValue(value.path); stringValue(value.size); assert(/^[1-9][0-9]*$/.test(value.size));
  shaValue(value.sha256); statValue(value.stat);
  if (!original) return;
  stringValue(value.documentUri);
  const content = value.documentUri.startsWith('content://');
  exact(value.uriResolution, content
    ? ['authority', 'documentUri', 'resolvedPath', 'providerPackage', 'providerApkSha256', 'evidenceSha256']
    : ['authority', 'documentUri', 'resolvedPath', 'evidenceSha256']);
  stringValue(value.uriResolution.authority); stringValue(value.uriResolution.documentUri);
  stringValue(value.uriResolution.resolvedPath); shaValue(value.uriResolution.evidenceSha256);
  if (content) { stringValue(value.uriResolution.providerPackage); shaValue(value.uriResolution.providerApkSha256); }
}
function bitmapValue(value) {
  exact(value, ['present', 'width', 'height', 'nativePointer']); booleanValue(value.present);
  if (!value.present) {
    assert.strictEqual(value.width, null); assert.strictEqual(value.height, null);
    assert.strictEqual(value.nativePointer, null); return;
  }
  integerValue(value.width); integerValue(value.height);
  assert(value.width >= 1 && value.width <= 10000000 && value.height >= 1 && value.height <= 10000000);
  pointerValue(value.nativePointer);
}
function viewValue(value) {
  exact(value, ['className', 'bounds', 'scroll', 'windowAttachCount', 'attached',
    'referenceStable', 'attachInfoStable']);
  stringValue(value.className); assert.strictEqual(value.bounds.length, 4);
  assert.strictEqual(value.scroll.length, 2); value.bounds.forEach(integerValue);
  value.scroll.forEach(integerValue); integerValue(value.windowAttachCount);
  assert(value.bounds[2] > value.bounds[0] && value.bounds[3] > value.bounds[1]);
  for (const item of value.bounds.concat(value.scroll)) assert(item >= -2147483648 && item <= 2147483647);
  assert(value.windowAttachCount >= 0 && value.windowAttachCount <= 2147483647);
  booleanValue(value.attached); booleanValue(value.referenceStable); booleanValue(value.attachInfoStable);
}
function validateSuccessRecord(value, expectedManifest) {
  assert(expectedManifest);
  exact(value, ['event', 'schemaVersion', 'authority', 'manifestSha256', 'observationOnly',
    'atomic', 'attachment', 'externalSession', 'fileAuthority', 'coordinator',
    'calibrationProfile', 'lifecycle', 'document', 'pageInfo', 'presenter', 'views', 'layers']);
  assert.strictEqual(value.event, 'native_page_graph_snapshot'); assert.strictEqual(value.schemaVersion, 2);
  assert.strictEqual(value.authority, 'rtl-reader-native-page-graph-snapshot-v2'); shaValue(value.manifestSha256);
  assert.strictEqual(value.manifestSha256,
    crypto.createHash('sha256').update(Buffer.from(canonical(expectedManifest))).digest('hex'));
  assert.strictEqual(value.observationOnly, true); assert.strictEqual(value.atomic, false);
  exact(value.attachment, ['packageName', 'processName', 'pid', 'processStartTimeTicks',
    'architecture', 'pointerSize', 'firmwareFingerprint', 'apk', 'framework', 'module',
    'observerExternallyVerifiedSha256']);
  for (const name of ['packageName', 'processName', 'processStartTimeTicks', 'architecture',
    'firmwareFingerprint']) stringValue(value.attachment[name]);
  integerValue(value.attachment.pid); integerValue(value.attachment.pointerSize);
  assert.strictEqual(value.attachment.packageName, 'com.supernote.document');
  assert.strictEqual(value.attachment.processName, 'Document');
  assert.strictEqual(value.attachment.architecture, 'arm64');
  assert.strictEqual(value.attachment.pointerSize, 8);
  assert.strictEqual(value.attachment.firmwareFingerprint,
    'Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys');
  for (const name of ['apk', 'framework']) {
    exact(value.attachment[name], ['path', 'size', 'externallyVerifiedSha256']);
    stringValue(value.attachment[name].path); integerValue(value.attachment[name].size);
    shaValue(value.attachment[name].externallyVerifiedSha256);
  }
  assert.strictEqual(value.attachment.apk.size, 138486560);
  assert.strictEqual(value.attachment.apk.externallyVerifiedSha256,
    'f008c86ddc42008c36b431410cbc3b29057b4aad9bc26c3577ee13b39b230482');
  assert.strictEqual(value.attachment.framework.size, 30186065);
  assert.strictEqual(value.attachment.framework.externallyVerifiedSha256,
    'c3a525a7ef16363a93412182cce693f46dfa1395a570e9620da0d4e27a59631d');
  assert.deepStrictEqual(value.attachment.apk, {
    path: expectedManifest.attachment.apk.path, size: expectedManifest.attachment.apk.size,
    externallyVerifiedSha256: expectedManifest.attachment.apk.sha256});
  assert.deepStrictEqual(value.attachment.framework, {
    path: expectedManifest.attachment.framework.path, size: expectedManifest.attachment.framework.size,
    externallyVerifiedSha256: expectedManifest.attachment.framework.sha256});
  exact(value.attachment.module, ['name', 'path', 'size', 'externallyVerifiedSha256']);
  stringValue(value.attachment.module.name); stringValue(value.attachment.module.path);
  integerValue(value.attachment.module.size); shaValue(value.attachment.module.externallyVerifiedSha256);
  shaValue(value.attachment.observerExternallyVerifiedSha256);
  assert.deepStrictEqual(value.attachment.module, {
    name: expectedManifest.attachment.module.name, path: expectedManifest.attachment.module.path,
    size: expectedManifest.attachment.module.size,
    externallyVerifiedSha256: expectedManifest.attachment.module.sha256});
  assert.strictEqual(value.attachment.pid, expectedManifest.attachment.pid);
  assert.strictEqual(value.attachment.processStartTimeTicks, expectedManifest.attachment.startTimeTicks);
  assert.strictEqual(value.attachment.observerExternallyVerifiedSha256,
    expectedManifest.attachment.observerSha256);
  exact(value.externalSession, ['authority', 'source', 'authorizedSerial', 'taskId', 'displayId',
    'hostSessionId', 'displayGeneration']);
  for (const name of ['authority', 'source', 'authorizedSerial', 'hostSessionId']) stringValue(value.externalSession[name]);
  for (const name of ['taskId', 'displayId', 'displayGeneration']) integerValue(value.externalSession[name]);
  assert.strictEqual(value.externalSession.authority, 'rtl-reader-native-page-external-session-v2');
  assert.strictEqual(value.externalSession.source, 'external-coordinator');
  assert.strictEqual(value.externalSession.authorizedSerial, 'SN078C10015092');
  assert.deepStrictEqual(value.externalSession, {
    authority: expectedManifest.externalSession.authority, source: 'external-coordinator',
    authorizedSerial: expectedManifest.externalSession.authorizedSerial,
    taskId: expectedManifest.externalSession.taskId, displayId: expectedManifest.externalSession.displayId,
    hostSessionId: expectedManifest.externalSession.hostSessionId,
    displayGeneration: expectedManifest.externalSession.displayGeneration});
  exact(value.fileAuthority, ['authority', 'verification', 'originalPdf', 'mark']);
  stringValue(value.fileAuthority.authority); stringValue(value.fileAuthority.verification);
  assert.strictEqual(value.fileAuthority.authority, 'rtl-reader-native-page-file-authority-v1');
  assert.strictEqual(value.fileAuthority.verification, 'external-before-and-after-exact');
  fileValue(value.fileAuthority.originalPdf, true); fileValue(value.fileAuthority.mark, false);
  assert.deepStrictEqual(value.fileAuthority, expectedManifest.files);
  exact(value.coordinator, ['authority', 'observerSessionId', 'absoluteMonotonicDeadlineNs',
    'hardDeadlineMs', 'heapWalks', 'retainedRootSamples', 'externalDetachOnDeadline',
    'externalTargetLivenessPostconditionRequired', 'noRetry']);
  stringValue(value.coordinator.authority); stringValue(value.coordinator.observerSessionId);
  assert.strictEqual(value.coordinator.authority, 'rtl-reader-native-page-graph-coordinator-v2');
  stringValue(value.coordinator.absoluteMonotonicDeadlineNs);
  assert(/^[1-9][0-9]*$/.test(value.coordinator.absoluteMonotonicDeadlineNs));
  for (const name of ['hardDeadlineMs', 'heapWalks', 'retainedRootSamples']) integerValue(value.coordinator[name]);
  for (const name of ['externalDetachOnDeadline', 'externalTargetLivenessPostconditionRequired', 'noRetry']) booleanValue(value.coordinator[name]);
  assert.strictEqual(value.coordinator.heapWalks, 1); assert.strictEqual(value.coordinator.retainedRootSamples, 2);
  assert.strictEqual(value.coordinator.externalDetachOnDeadline, true);
  assert.strictEqual(value.coordinator.externalTargetLivenessPostconditionRequired, true);
  assert.strictEqual(value.coordinator.noRetry, true);
  assert.deepStrictEqual(value.coordinator, {
    authority: expectedManifest.coordinator.authority,
    observerSessionId: expectedManifest.coordinator.observerSessionId,
    absoluteMonotonicDeadlineNs: expectedManifest.coordinator.absoluteMonotonicDeadlineNs,
    hardDeadlineMs: expectedManifest.coordinator.hardDeadlineMs,
    heapWalks: 1, retainedRootSamples: 2, externalDetachOnDeadline: true,
    externalTargetLivenessPostconditionRequired: true, noRetry: true});
  exact(value.calibrationProfile, ['authority', 'status', 'pageIndexSemantics', 'matrixSemantics']);
  Object.values(value.calibrationProfile).forEach(stringValue);
  assert.deepStrictEqual(value.calibrationProfile, {
    authority: 'rtl-reader-native-page-calibration-raw-v1', matrixSemantics: 'independent-raw',
    pageIndexSemantics: 'independent-raw', status: 'calibration-only'});
  exact(value.lifecycle, ['resumed', 'finished', 'destroyed', 'graphStable']);
  Object.values(value.lifecycle).forEach(booleanValue);
  assert.deepStrictEqual(value.lifecycle, {resumed: true, finished: false, destroyed: false, graphStable: true});
  exact(value.document, ['uri', 'rawCurrentPage', 'pageCount', 'rawPageInfoPage', 'rectangles']);
  stringValue(value.document.uri); integerValue(value.document.rawCurrentPage);
  integerValue(value.document.pageCount); integerValue(value.document.rawPageInfoPage);
  assert.strictEqual(value.document.uri, expectedManifest.expected.documentUri);
  assert(value.document.pageCount >= 1 && value.document.pageCount <= 10000000);
  assert(value.document.rawCurrentPage >= 0 && value.document.rawCurrentPage <= value.document.pageCount);
  assert(value.document.rawPageInfoPage >= 0 && value.document.rawPageInfoPage <= value.document.pageCount);
  exact(value.document.rectangles, ['scaleRect', 'portraitScaleRect', 'landscapeScaleRect',
    'showRect', 'trimmingRect', 'landscapeTrimmingRect']);
  Object.values(value.document.rectangles).forEach((rect) => {
    assert(Array.isArray(rect)); assert.strictEqual(rect.length, 4);
    const decoded = rect.map(binaryValue); assert(decoded[2] > decoded[0] && decoded[3] > decoded[1]);
  });
  exact(value.pageInfo, ['ctm', 'revertCtm', 'offset', 'scale', 'trimmingRect', 'bitmaps']);
  for (const name of ['ctm', 'revertCtm']) {
    assert(Array.isArray(value.pageInfo[name])); assert.strictEqual(value.pageInfo[name].length, 6);
    const decoded = value.pageInfo[name].map(binaryValue);
    const determinant = decoded[0] * decoded[3] - decoded[1] * decoded[2];
    const norm = Math.max(Math.abs(decoded[0]), Math.abs(decoded[1]),
      Math.abs(decoded[2]), Math.abs(decoded[3]));
    assert(norm > 0 && Math.abs(determinant) > Number.EPSILON * norm * norm * 64 &&
      (norm * norm) / Math.abs(determinant) <= 1e12);
  }
  assert.strictEqual(value.pageInfo.offset.length, 2); value.pageInfo.offset.forEach(integerValue);
  value.pageInfo.offset.forEach((item) => assert(item >= -2147483648 && item <= 2147483647));
  binaryValue(value.pageInfo.scale); assert.strictEqual(value.pageInfo.trimmingRect.length, 4);
  const trimming = value.pageInfo.trimmingRect.map(binaryValue);
  assert(trimming[2] > trimming[0] && trimming[3] > trimming[1]);
  exact(value.pageInfo.bitmaps, ['originBitmap', 'displayBitmap', 'digestBitmap']);
  Object.values(value.pageInfo.bitmaps).forEach(bitmapValue);
  exact(value.presenter, ['uri', 'rawPresenterPage', 'markPath', 'rawRotationCode', 'bitmap',
    'notePointer', 'binders']);
  stringValue(value.presenter.uri); integerValue(value.presenter.rawPresenterPage);
  if (value.presenter.markPath !== null) stringValue(value.presenter.markPath);
  integerValue(value.presenter.rawRotationCode); bitmapValue(value.presenter.bitmap);
  assert(value.presenter.rawRotationCode >= -2147483648 && value.presenter.rawRotationCode <= 2147483647);
  assert.strictEqual(value.presenter.uri, expectedManifest.expected.documentUri);
  assert(value.presenter.rawPresenterPage >= 0 &&
    value.presenter.rawPresenterPage <= value.document.pageCount);
  assert.strictEqual(value.presenter.markPath,
    expectedManifest.files.mark.present ? expectedManifest.files.mark.path : null);
  pointerValue(value.presenter.notePointer);
  exact(value.presenter.binders, ['iBinder', 'mSFBinder']);
  for (const binder of Object.values(value.presenter.binders)) {
    exact(binder, ['present', 'referenceStable']); booleanValue(binder.present); booleanValue(binder.referenceStable);
    assert.strictEqual(binder.referenceStable, true);
  }
  exact(value.views, ['handWriteView', 'documentImage', 'digestImage', 'contentView', 'documentLayout']);
  Object.values(value.views).forEach(viewValue);
  assert.deepStrictEqual(Object.values(value.views).map((view) => view.className),
    [CLASS.handWriteView, CLASS.imageView, CLASS.digestImageView, CLASS.contentView, CLASS.documentLayout]);
  for (const view of Object.values(value.views)) {
    assert.strictEqual(view.attached, true); assert.strictEqual(view.referenceStable, true);
    assert.strictEqual(view.attachInfoStable, true);
  }
  exact(value.layers, ['status', 'reasonCode', 'evidenceId']); Object.values(value.layers).forEach(stringValue);
  assert.deepStrictEqual(value.layers, {status: 'unavailable',
    reasonCode: 'DIRECT_LAYER_PROVENANCE_NOT_PINNED', evidenceId: 'native-page-graph-v2-static-map'});
}

test('baseline emits an exact bounded two-frame raw calibration record', () => {
  const result = execute();
  const record = assertSuccess(result);
  validateSuccessRecord(record, result.manifest);
  assert.strictEqual(record.authority, 'rtl-reader-native-page-graph-snapshot-v2');
  assert.strictEqual(record.observationOnly, true);
  assert.strictEqual(record.atomic, false);
  assert.strictEqual(record.externalSession.source, 'external-coordinator');
  assert.strictEqual(record.document.rawCurrentPage, 2);
  assert.strictEqual(record.document.rawPageInfoPage, 3);
  assert.strictEqual(record.presenter.rawPresenterPage, 4);
  assert.deepStrictEqual(record.pageInfo.scale, {binary64: '0x8000000000000000'});
  assert.strictEqual(record.layers.status, 'unavailable');
  assert.strictEqual(record.coordinator.heapWalks, 1);
  assert.deepStrictEqual(keys(record), ['atomic', 'attachment', 'authority', 'calibrationProfile',
    'coordinator', 'document', 'event', 'externalSession', 'fileAuthority', 'layers',
    'lifecycle', 'manifestSha256', 'observationOnly', 'pageInfo', 'presenter',
    'schemaVersion', 'views'].sort());
  assert.deepStrictEqual(keys(record.document),
    ['pageCount', 'rawCurrentPage', 'rawPageInfoPage', 'rectangles', 'uri'].sort());
  assert.deepStrictEqual(keys(record.pageInfo),
    ['bitmaps', 'ctm', 'offset', 'revertCtm', 'scale', 'trimmingRect'].sort());
  assert.deepStrictEqual(keys(record.presenter),
    ['binders', 'bitmap', 'markPath', 'notePointer', 'rawPresenterPage', 'rawRotationCode', 'uri'].sort());
  assert(Buffer.byteLength(canonical(record)) < 2097152);
});

test('independent exact output schema rejects every key/type/array mutation', () => {
  const result = execute(); const baseline = assertSuccess(result); const expectedManifest = result.manifest;
  validateSuccessRecord(baseline, expectedManifest);
  const objects = [], arrays = [], leaves = [];
  function walk(value, pathParts) {
    if (Array.isArray(value)) {
      arrays.push(pathParts); value.forEach((item, index) => walk(item, pathParts.concat(index))); return;
    }
    if (value !== null && typeof value === 'object') {
      objects.push(pathParts);
      for (const [key, child] of Object.entries(value)) walk(child, pathParts.concat(key));
      return;
    }
    leaves.push(pathParts);
  }
  function locate(root, pathParts) {
    let value = root;
    for (let index = 0; index < pathParts.length - 1; index++) value = value[pathParts[index]];
    return {parent: value, key: pathParts[pathParts.length - 1]};
  }
  walk(baseline, []);
  for (const pathParts of objects) {
    const mutated = clone(baseline);
    let target = mutated; for (const part of pathParts) target = target[part];
    target.__unexpected = true;
    assert.throws(() => validateSuccessRecord(mutated, expectedManifest), pathParts.join('.')); cases++;
    for (const key of Object.keys(target)) {
      if (key === '__unexpected') continue;
      const missing = clone(baseline); let missingTarget = missing;
      for (const part of pathParts) missingTarget = missingTarget[part];
      delete missingTarget[key]; assert.throws(() => validateSuccessRecord(missing, expectedManifest)); cases++;
    }
  }
  for (const pathParts of arrays) {
    for (const mode of ['short', 'long']) {
      const mutated = clone(baseline); let target = mutated;
      for (const part of pathParts) target = target[part];
      if (mode === 'short') target.pop(); else target.push(null);
      assert.throws(() => validateSuccessRecord(mutated, expectedManifest)); cases++;
    }
  }
  for (const pathParts of leaves) {
    const mutated = clone(baseline); const location = locate(mutated, pathParts);
    const before = location.parent[location.key];
    location.parent[location.key] = before === null ? {} :
      typeof before === 'string' ? 1 : typeof before === 'number' ? '1' : 'true';
    assert.throws(() => validateSuccessRecord(mutated, expectedManifest), pathParts.join('.')); cases++;
  }
});

test('independent output validator rejects same-type semantic pin mutations', () => {
  const result = execute(); const baseline = assertSuccess(result); const expectedManifest = result.manifest;
  const paths = [
    'event', 'schemaVersion', 'authority', 'manifestSha256', 'observationOnly', 'atomic',
    'attachment.packageName', 'attachment.processName', 'attachment.architecture',
    'attachment.pointerSize', 'attachment.firmwareFingerprint', 'attachment.apk.size',
    'attachment.apk.path', 'attachment.apk.externallyVerifiedSha256', 'attachment.framework.size',
    'attachment.framework.path', 'attachment.framework.externallyVerifiedSha256',
    'attachment.module.name', 'attachment.module.path', 'attachment.module.size',
    'attachment.module.externallyVerifiedSha256', 'attachment.pid',
    'attachment.processStartTimeTicks', 'attachment.observerExternallyVerifiedSha256',
    'externalSession.authority', 'externalSession.source', 'externalSession.authorizedSerial',
    'externalSession.taskId', 'externalSession.displayId', 'externalSession.hostSessionId',
    'externalSession.displayGeneration', 'fileAuthority.authority',
    'fileAuthority.verification', 'coordinator.authority', 'coordinator.heapWalks',
    'coordinator.observerSessionId', 'coordinator.absoluteMonotonicDeadlineNs',
    'coordinator.hardDeadlineMs', 'coordinator.retainedRootSamples', 'coordinator.externalDetachOnDeadline',
    'coordinator.externalTargetLivenessPostconditionRequired', 'coordinator.noRetry',
    'calibrationProfile.authority', 'calibrationProfile.status',
    'calibrationProfile.pageIndexSemantics', 'calibrationProfile.matrixSemantics',
    'lifecycle.resumed', 'lifecycle.finished', 'lifecycle.destroyed', 'lifecycle.graphStable',
    'presenter.binders.iBinder.referenceStable', 'presenter.binders.mSFBinder.referenceStable',
    'views.handWriteView.className', 'views.documentImage.className',
    'views.digestImage.className', 'views.contentView.className', 'views.documentLayout.className',
    'fileAuthority.originalPdf.path', 'fileAuthority.originalPdf.size',
    'fileAuthority.originalPdf.sha256', 'fileAuthority.originalPdf.documentUri',
    'fileAuthority.originalPdf.stat.inode', 'fileAuthority.originalPdf.uriResolution.authority',
    'fileAuthority.originalPdf.uriResolution.documentUri',
    'fileAuthority.originalPdf.uriResolution.resolvedPath',
    'fileAuthority.originalPdf.uriResolution.evidenceSha256',
    'fileAuthority.mark.path', 'fileAuthority.mark.size', 'fileAuthority.mark.sha256',
    'document.uri', 'presenter.uri', 'presenter.markPath',
    'layers.status', 'layers.reasonCode', 'layers.evidenceId'
  ];
  for (const pathName of paths) {
    const mutated = clone(baseline); const target = at(mutated, pathName);
    const before = target.parent[target.key];
    target.parent[target.key] = typeof before === 'boolean' ? !before :
      typeof before === 'number' ? before + 1 :
        /^[0-9a-f]{64}$/.test(before) ? (before === '0'.repeat(64) ? '1' : '0').repeat(64) :
          /^[1-9][0-9]*$/.test(before) ? String(BigInt(before) + 1n) : before + '.changed';
    assert.throws(() => validateSuccessRecord(mutated, expectedManifest), pathName); cases++;
  }
});

test('independent output validator rejects numeric and relational edge cases', () => {
  const result = execute(); const baseline = assertSuccess(result); const expectedManifest = result.manifest;
  const mutations = [
    (v) => { v.document.pageCount = 0; },
    (v) => { v.document.pageCount = 10000001; },
    (v) => { v.document.rawCurrentPage = -1; },
    (v) => { v.document.rawCurrentPage = v.document.pageCount + 1; },
    (v) => { v.document.rawPageInfoPage = v.document.pageCount + 1; },
    (v) => { v.presenter.rawPresenterPage = v.document.pageCount + 1; },
    (v) => { v.presenter.rawRotationCode = 2147483648; },
    (v) => { v.pageInfo.offset[0] = -2147483649; },
    (v) => { v.pageInfo.scale.binary64 = '0x7ff8000000000000'; },
    (v) => { v.pageInfo.ctm[0].binary64 = '0x7ff0000000000000'; },
    (v) => { v.pageInfo.ctm[0].binary64 = '0x0000000000000000'; v.pageInfo.ctm[3].binary64 = '0x0000000000000000'; },
    (v) => { v.document.rectangles.scaleRect[2] = clone(v.document.rectangles.scaleRect[0]); },
    (v) => { v.pageInfo.trimmingRect[3] = clone(v.pageInfo.trimmingRect[1]); },
    (v) => { v.pageInfo.bitmaps.originBitmap.width = 0; },
    (v) => { v.pageInfo.bitmaps.originBitmap.height = 10000001; },
    (v) => { v.pageInfo.bitmaps.originBitmap.present = false; },
    (v) => { v.presenter.notePointer.present = false; },
    (v) => { v.views.handWriteView.bounds[2] = v.views.handWriteView.bounds[0]; },
    (v) => { v.views.handWriteView.windowAttachCount = -1; }
  ];
  for (const mutate of mutations) {
    const value = clone(baseline); mutate(value);
    assert.throws(() => validateSuccessRecord(value, expectedManifest)); cases++;
  }
});

test('raw page values and raw matrices remain independent', () => {
  const g = graph();
  g.refs.viewModel.currentPage.value = 0;
  g.refs.pageInfo.page.value = 7;
  g.refs.presenter.currentPage.value = 5;
  const record = assertSuccess(execute({graph: g}));
  assert.strictEqual(record.document.rawCurrentPage, 0);
  assert.strictEqual(record.document.rawPageInfoPage, 7);
  assert.strictEqual(record.presenter.rawPresenterPage, 5);
  assert.notDeepStrictEqual(record.pageInfo.ctm, record.pageInfo.revertCtm);
});

test('nullable mark, bitmaps, and binders have exact absence records', () => {
  const m = manifest();
  m.files.mark = {present: false, path: null, size: null, sha256: null, stat: null};
  const g = graph();
  g.refs.presenter.markPath.value = null;
  for (const name of ['originBitmap', 'digestBitmap', 'presenterBitmap', 'binder', 'sfBinder']) {
    const edge = g.edges.find((candidate) => candidate.name === name);
    edge.parent[edge.field].value = null;
  }
  const record = assertSuccess(execute({manifest: m, graph: g}));
  assert.strictEqual(record.presenter.markPath, null);
  assert.strictEqual(record.pageInfo.bitmaps.originBitmap.present, false);
  assert.strictEqual(record.presenter.binders.iBinder.present, false);
});

each('rejects zero, multiple, and non-live root selections', [
  () => [],
  () => { const first = graph().activity; const second = graph().activity; second.$h = {id: 'other'}; return [first, second]; },
  () => { const root = graph().activity; root.mResumed.value = false; return [root]; },
  () => { const root = graph().activity; root.mFinished.value = true; return [root]; },
  () => { const root = graph().activity; root.mDestroyed.value = true; return [root]; }
], (factory) => {
  const g = graph(); g.candidates = factory(); assertFailure(execute({graph: g}));
});

test('ignores stale roots but accepts exactly one live root', () => {
  const g = graph();
  const stale = graph().activity; stale.mResumed.value = false;
  g.candidates = [stale, g.activity];
  assertSuccess(execute({graph: g}));
});

test('rejects wrong-class and wrapper-shaped root candidates', () => {
  for (const candidate of [
    jobject('invalid.Activity', 'wrong-root', {mResumed: true, mFinished: false, mDestroyed: false}),
    {$className: CLASS.activity, value: graph().activity}
  ]) {
    const g = graph(); g.candidates = [candidate]; assertFailure(execute({graph: g})); cases++;
  }
});

test('heap candidate bound includes stale candidates at the exact boundary', () => {
  function stale(index) {
    const root = graph().activity; root.$h = {id: 'stale:' + index}; root.mResumed.value = false;
    return root;
  }
  const accepted = graph(); accepted.candidates = Array.from({length: 63}, (_, i) => stale(i)).concat(accepted.activity);
  assertSuccess(execute({graph: accepted}));
  const rejected = graph(); rejected.candidates = Array.from({length: 64}, (_, i) => stale(i)).concat(rejected.activity);
  assertFailure(execute({graph: rejected}));
});

each('every required reference rejects null', graph().edges.filter((e) => !e.nullable).map((e) => e.name), (name) => {
  const g = graph(); const edge = g.edges.find((e) => e.name === name);
  edge.parent[edge.field].value = null; assertFailure(execute({graph: g}));
});

each('every reference field rejects a missing direct slot', graph().edges.map((e) => e.name), (name) => {
  const g = graph(); const edge = g.edges.find((e) => e.name === name);
  delete edge.parent[edge.field]; assertFailure(execute({graph: g}));
});

each('every nullable reference independently accepts null', graph().edges.filter((e) => e.nullable).map((e) => e.name), (name) => {
  const g = graph(); const edge = g.edges.find((e) => e.name === name);
  edge.parent[edge.field].value = null;
  const record = assertSuccess(execute({graph: g}));
  assert(record);
});

each('every nullable reference rejects a null/present transition', graph().edges.filter((e) => e.nullable).map((e) => e.name), (name) => {
  const g = graph(); const edge = g.edges.find((e) => e.name === name);
  if (edge.child === null) {
    const replacement = jobject(CLASS.bitmap, 'late-bitmap',
      {mWidth: 10, mHeight: 10, mNativePtr: jlong('1')});
    edge.parent[edge.field] = sequenceSlot([null, replacement]);
  } else edge.parent[edge.field] = sequenceSlot([edge.child, null]);
  assertFailure(execute({graph: g}));
});

each('every class-pinned edge rejects wrong class and wrapper shapes', graph().edges.map((e) => e.name), (name) => {
  for (const mode of ['class', 'wrapper']) {
    const g = graph(); const edge = g.edges.find((e) => e.name === name);
    if (edge.child === null) {
      edge.parent[edge.field].value = mode === 'class'
        ? jobject('invalid.Class', 'wrong-nullable', {})
        : {$className: CLASS.bitmap, value: g.refs.originBitmap};
      assertFailure(execute({graph: g}));
      continue;
    }
    if (mode === 'class' && (name === 'binder' || name === 'sfBinder')) continue;
    edge.parent[edge.field].value = mode === 'class'
      ? jobject('invalid.Class', 'wrong', {}) : {$className: edge.child.$className, value: edge.child};
    assertFailure(execute({graph: g}));
  }
});

each('every graph edge rejects replacement between retained samples', graph().edges.filter((e) => e.child !== null).map((e) => e.name), (name) => {
  const g = graph(); const edge = g.edges.find((e) => e.name === name);
  const replacement = Object.create(edge.child); replacement.$h = {id: 'replacement:' + name};
  edge.parent[edge.field] = sequenceSlot([edge.child, replacement]);
  assertFailure(execute({graph: g}));
});

test('every JNI identity rejection and exception fails closed with cleanup', () => {
  const baseline = execute(); assertSuccess(baseline);
  for (let ordinal = 1; ordinal <= baseline.sameCalls; ordinal++) {
    assertFailure(execute({sameFalseAt: ordinal})); cases++;
    assertFailure(execute({sameThrowAt: ordinal})); cases++;
  }
});

test('retention and every disposal failure fail closed while cleanup continues', () => {
  assertFailure(execute({retainThrowAt: 3}));
  const malformed = execute({retainMalformedAt: 3});
  assertFailure(malformed);
  assert.strictEqual(malformed.disposed.length, malformed.retained.length);
  const baseline = execute(); assertSuccess(baseline);
  for (let ordinal = 1; ordinal <= baseline.retained.length; ordinal++) {
    const result = execute({disposeThrowAt: ordinal});
    assertFailure(result);
    assert.strictEqual(result.disposed.length, result.retained.length);
    cases++;
  }
});

each('rejects runtime attachment mutations', [
  {arch: 'x64'}, {pointerSize: 4}, {pid: 3142},
  {module: {name: 'libart.so', path: '/wrong', size: 1234567}},
  {module: {name: 'libart.so', path: '/apex/com.android.runtime/lib64/libart.so', size: 1234568}},
  {moduleThrow: true}
], (change) => assertFailure(execute(change)));

test('every direct scalar rejects missing/null and mutation across samples', () => {
  const descriptors = scalarFields(graph()).map(({name, field}) => ({name, field}));
  assert(descriptors.length >= 80);
  for (const descriptor of descriptors) {
    for (const mode of ['missing', 'null', 'mutated']) {
      const g = graph();
      const item = scalarFields(g).find((candidate) => candidate.name === descriptor.name &&
        candidate.field === descriptor.field);
      assert(item);
      if (mode === 'missing') delete item.object[item.field];
      else if (mode === 'null') item.object[item.field].value = null;
      else {
        const before = item.slot.value;
        const after = changedScalar(before);
        item.object[item.field] = descriptor.name === 'activity'
          ? sequenceSlot([before, before, after]) : sequenceSlot([before, after]);
      }
      try { assertFailure(execute({graph: g})); }
      catch (_) { throw new Error(`unexpected scalar acceptance: ${descriptor.name}.${descriptor.field}/${mode}`); }
      cases++;
    }
  }
});

each('rejects URI and mark authority disagreement', ['bad-subtype', 'vm-uri', 'presenter-uri', 'mark-present', 'mark-absent'], (kind) => {
  const m = manifest(); const g = graph();
  if (kind === 'bad-subtype') g.refs.viewModelUri.$className = 'android.net.Uri$HierarchicalUri';
  if (kind === 'vm-uri') g.refs.viewModelUri.uriString.value = 'file:///wrong.pdf';
  if (kind === 'presenter-uri') g.refs.presenterUri.uriString.value = 'file:///wrong.pdf';
  if (kind === 'mark-present') g.refs.presenter.markPath.value = '/wrong.mark';
  if (kind === 'mark-absent') m.files.mark = {present: false, path: null, size: null, sha256: null, stat: null};
  assertFailure(execute({manifest: m, graph: g}));
});

each('rejects page and integer range violations', [
  ['viewModel', 'pageCount', 0], ['viewModel', 'pageCount', 10000001],
  ['viewModel', 'currentPage', -1], ['viewModel', 'currentPage', 8],
  ['pageInfo', 'page', 8], ['presenter', 'currentPage', 8],
  ['viewModel', 'currentPage', 1.5], ['presenter', 'screenRotation', -0]
], ([name, field, value]) => {
  const g = graph(); g.refs[name][field].value = value; assertFailure(execute({graph: g}));
});

each('rejects non-finite, singular, and ill-conditioned matrices', [
  [NaN, 0, 0, 1, 0, 0], [Infinity, 0, 0, 1, 0, 0],
  [1, 2, 2, 4, 0, 0], [1e12, 0, 0, 1e-12, 0, 0],
  [1, 0, 0, 1, 1e13, 0]
], (values) => {
  const g = graph(); ['a', 'b', 'c', 'd', 'e', 'f'].forEach((field, i) => { g.refs.ctm[field].value = values[i]; });
  assertFailure(execute({graph: g}));
});

each('rejects malformed rectangles, bitmaps, pointers, and views', [
  (g) => { g.refs.scaleRect.right.value = 0; },
  (g) => { g.refs.scaleRect.left.value = NaN; },
  (g) => { g.refs.originBitmap.mWidth.value = 0; },
  (g) => { g.refs.originBitmap.mHeight.value = 10000001; },
  (g) => { g.refs.originBitmap.mNativePtr.value = jlong('xyz'); },
  (g) => { g.refs.note.pointer.value = -1; },
  (g) => { g.refs.handWriteView.mRight.value = 0; },
  (g) => { g.refs.handWriteView.mWindowAttachCount.value = -1; },
  (g) => { g.refs.handWriteView.mLeft.value = 1.2; }
], (mutate) => { const g = graph(); mutate(g); assertFailure(execute({graph: g})); });

test('external deadline authority is validated and echoed but never measured in-process', () => {
  const exact = manifest();
  exact.coordinator.absoluteMonotonicDeadlineNs = '999999999999999999999999999999';
  exact.coordinator.hardDeadlineMs = 10000;
  const record = assertSuccess(execute({manifest: exact}));
  assert.strictEqual(record.coordinator.absoluteMonotonicDeadlineNs,
    exact.coordinator.absoluteMonotonicDeadlineNs);
  assert.strictEqual(record.coordinator.hardDeadlineMs, 10000);
  const deferred = execute({manifest: exact, deferComplete: true});
  assert.strictEqual(deferred.sent.length, 0);
  deferred.complete(); assertSuccess(deferred);
  assert.strictEqual(deferred.chooseCalls, 1);
});

test('late duplicate completion cannot emit a third frame', () => {
  let callback;
  const g = graph();
  const m = manifest();
  const wire = canonical(m); const bytes = Array.from(Buffer.from(wire));
  const sent = [];
  const context = {
    NATIVE_PAGE_GRAPH_MANIFEST_UTF8: bytes,
    NATIVE_PAGE_GRAPH_MANIFEST_SHA256: crypto.createHash('sha256').update(Buffer.from(bytes)).digest('hex'),
    Process: {arch: 'arm64', pointerSize: 8, id: m.attachment.pid,
      getModuleByName: () => ({...m.attachment.module})},
    Java: {perform: (fn) => fn(), retain: (v) => { const c = Object.create(v); c.$dispose = () => {}; return c; },
      vm: {getEnv: () => ({isSameObject: (a, b) => a.id === b.id})},
      choose: (_, cb) => { cb.onMatch(g.activity); callback = cb.onComplete; cb.onComplete(); }},
    send: (message) => sent.push(JSON.parse(JSON.stringify(message)))
  };
  vm.runInNewContext(SOURCE, context, {timeout: 1000});
  assert.strictEqual(sent.length, 2); callback(); assert.strictEqual(sent.length, 2);
});

test('manifest wire requires exact canonical UTF-8, digest, and duplicate-key rejection', () => {
  const m = manifest();
  assertFailure(execute({wire: JSON.stringify(m, null, 2)}));
  assertFailure(execute({digest: Z64}));
  assertFailure(execute({wire: '{"a":1,"a":2}'}));
  assertFailure(execute({bytes: [0xc0, 0x80], digest: crypto.createHash('sha256').update(Buffer.from([0xc0, 0x80])).digest('hex')}));
  assertFailure(execute({bytes: new Array(131073).fill(0), digest: Z64}));
});

test('every top-level manifest subsystem rejects unknown or missing keys', () => {
  for (const pathName of ['attachment', 'externalSession', 'files', 'coordinator', 'expected',
    'files.originalPdf', 'files.originalPdf.stat', 'files.originalPdf.uriResolution',
    'files.mark', 'attachment.apk', 'attachment.framework', 'attachment.module',
    'expected.calibrationProfile']) {
    for (const mode of ['unknown', 'missing']) {
      const m = manifest(); const target = at(m, pathName).parent[at(m, pathName).key];
      if (mode === 'unknown') target.unexpected = true;
      else delete target[Object.keys(target)[0]];
      assertFailure(execute({manifest: m})); cases++;
    }
  }
});

test('every security-critical manifest pin and coordinator invariant rejects mutation', () => {
  const changes = [
    ['schemaVersion', 1], ['authority', 'old'], ['attachment.packageName', 'evil'],
    ['attachment.processName', 'evil'], ['attachment.pid', 0], ['attachment.startTimeTicks', '01'],
    ['attachment.firmwareFingerprint', 'other'], ['attachment.apk.size', 138486559],
    ['attachment.apk.sha256', Z64], ['attachment.framework.size', 1],
    ['attachment.framework.sha256', Z64], ['attachment.observerSha256', 'A'.repeat(64)],
    ['externalSession.authority', 'other'], ['externalSession.authorizedSerial', 'OTHER'],
    ['externalSession.taskId', -1], ['externalSession.displayId', 1025],
    ['externalSession.hostSessionId', 'short'], ['externalSession.displayGeneration', -1],
    ['files.authority', 'other'], ['files.verification', 'echoed'],
    ['coordinator.authority', 'other'], ['coordinator.observerSessionId', 'short'],
    ['coordinator.absoluteMonotonicDeadlineNs', '0'], ['coordinator.hardDeadlineMs', 249],
    ['coordinator.hardDeadlineMs', 10001], ['coordinator.maxJavaChooseWalks', 2],
    ['coordinator.retainedRootSamples', 1], ['coordinator.detachOnDeadline', false],
    ['coordinator.abortOnAnyError', false], ['coordinator.verifyTargetLivenessAfter', false],
    ['coordinator.noRetry', false], ['expected.documentUri', 'file:///wrong'],
    ['expected.calibrationProfile.status', 'production'],
    ['expected.calibrationProfile.pageIndexSemantics', 'zero-based'],
    ['expected.calibrationProfile.matrixSemantics', 'inverse']
  ];
  for (const [pathName, value] of changes) {
    const m = manifest(); const target = at(m, pathName); target.parent[target.key] = value;
    assertFailure(execute({manifest: m})); cases++;
  }
});

test('file and URI authority fail closed for malformed present/absent and content records', () => {
  const mutations = [
    (m) => { m.files.originalPdf.present = false; },
    (m) => { m.files.originalPdf.size = '0'; },
    (m) => { m.files.originalPdf.sha256 = 'A'.repeat(64); },
    (m) => { m.files.originalPdf.stat.inode = '0'; },
    (m) => { m.files.originalPdf.stat.uid = -1; },
    (m) => { m.files.originalPdf.uriResolution.resolvedPath = '/wrong'; },
    (m) => { m.files.mark.present = false; },
    (m) => { m.files.originalPdf.documentUri = 'http://example.test/a.pdf'; m.expected.documentUri = m.files.originalPdf.documentUri; },
    (m) => { m.files.originalPdf.documentUri = 'content://provider/doc/1'; m.expected.documentUri = m.files.originalPdf.documentUri; },
    (m) => { m.files.originalPdf.documentUri = 'content://provider/doc/1'; m.expected.documentUri = m.files.originalPdf.documentUri;
      m.files.originalPdf.uriResolution = {authority: 'rtl-reader-content-uri-resolution-v1',
        documentUri: m.expected.documentUri, resolvedPath: m.files.originalPdf.path,
        providerPackage: '', providerApkSha256: Z64, evidenceSha256: Z64}; }
  ];
  for (const mutate of mutations) { const m = manifest(); mutate(m); assertFailure(execute({manifest: m})); cases++; }
  const m = manifest(); const oldUri = m.expected.documentUri;
  const newUri = 'content://com.supernote.files/document/7';
  m.expected.documentUri = newUri; m.files.originalPdf.documentUri = newUri;
  m.files.originalPdf.uriResolution = {authority: 'rtl-reader-content-uri-resolution-v1',
    documentUri: newUri, resolvedPath: m.files.originalPdf.path,
    providerPackage: 'com.supernote.files', providerApkSha256: '5'.repeat(64), evidenceSha256: '6'.repeat(64)};
  const g = graph(); g.refs.viewModelUri.uriString.value = newUri; g.refs.presenterUri.uriString.value = newUri;
  assertSuccess(execute({manifest: m, graph: g}));
  assert.notStrictEqual(oldUri, newUri);
});

test('manifest cannot inject class, field, selector, shell, or command contracts', () => {
  for (const key of ['classes', 'fields', 'selectors', 'command', 'shell']) {
    const m = manifest(); m[key] = {activity: 'evil'}; assertFailure(execute({manifest: m})); cases++;
  }
});

test('fixed failure framing never leaks hostile thrown values', () => {
  for (const option of [{moduleThrow: true}, {retainThrowAt: 1}, {sameThrowAt: 1}]) {
    const result = execute(option); assertFailure(result);
    assert(!JSON.stringify(result.sent).includes('module'));
    assert(!JSON.stringify(result.sent).includes('retain'));
    assert(!JSON.stringify(result.sent).includes('same'));
  }
});

test('static source permits one heap walk and no target mutation or forbidden capability', () => {
  const stripped = SOURCE.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '')
    .replace(/'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`/g, '');
  assert.strictEqual((stripped.match(/Java\s*\.\s*choose\s*\(/g) || []).length, 1);
  for (const forbidden of ['Interceptor', 'Stalker', 'NativeFunction', 'NativeCallback',
    'Memory', 'setTimeout', 'setInterval', 'enumerateLoadedClasses', 'registerClass',
    'rpc.', 'recv(', 'sendInput', 'screenshot', 'NATIVE_PAGE_GRAPH_MONOTONIC_NOW_NS',
    'Date.now', 'performance.now', 'nanoTime']) {
    assert(!stripped.includes(forbidden), forbidden);
  }
  assert(!/\bnew\s+(File|Socket)\s*\(/.test(stripped));
  assert(!/\.\s*implementation\s*=/.test(stripped));
  assert(!/\.\s*value\s*=/.test(stripped));
  assert(!/\.\s*\$new\s*\(/.test(stripped));
  assert(!/\.\s*\$init\s*\(/.test(stripped));
  assert(!/Java\s*\.\s*use\s*\(/.test(stripped));
  assert(!/\.\s*(readByteArray|writeByteArray|readPointer|writePointer)\s*\(/.test(stripped));
  assert(SOURCE.includes('DIRECT_LAYER_PROVENANCE_NOT_PINNED'));
  assert(SOURCE.includes('MAX_OUTPUT_BYTES = 2097152'));
});

test('send transport faults do not cause retries or duplicate heap walks', () => {
  for (const ordinal of [1, 2]) {
    const result = execute({sendThrowAt: ordinal});
    assert.strictEqual(result.chooseCalls, 1);
    assert.strictEqual(result.sendCalls, 2);
    assert.strictEqual(result.sent.length, 1);
    if (ordinal === 1) assert.deepStrictEqual(result.sent[0],
      {event: 'native_page_graph_snapshot_complete', success: true});
    else assert.strictEqual(result.sent[0].event, 'native_page_graph_snapshot');
    cases++;
  }
});

process.stdout.write('\n');
console.log(`native page graph v2 tests: ${tests} groups, ${cases} adversarial cases passed`);
