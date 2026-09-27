'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SOURCE = fs.readFileSync(path.join(__dirname,
  'native_page_display0_hierarchy_observer.js'), 'utf8');
const SHA = crypto.createHash('sha256').update(SOURCE).digest('hex');
const URI = 'file:///storage/emulated/0/Document/RTL_DISPLAY0_CAPTURE_20260927.pdf';
const C = {
  activity: 'com.supernote.document.document.DocumentActivity',
  vm: 'com.supernote.document.document.DocumentViewModel',
  root: 'android.widget.FrameLayout',
  pdf: 'com.supernote.document.utils.view.DocumentImageView',
  digest: 'com.supernote.document.utils.view.DigestImageView',
  pen: 'com.supernote.document.handwrite.HandWriteView',
  uri: 'android.net.Uri$StringUri'
};
function canonical(v) {
  if (v === null) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') return String(v);
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonical).join(',') + ']';
  return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' +
    canonical(v[k])).join(',') + '}';
}
function slot(value) { return {value}; }
function make(className, id, fields = {}) {
  const result = {$className: className, $h: {id}};
  for (const [name, value] of Object.entries(fields)) result[name] = slot(value);
  return result;
}
function view(className, id, parent, position) {
  const v = make(className, id, {mLeft: 0, mTop: 0,
    mRight: 1404, mBottom: 1872});
  v.getId = () => 1000 + position;
  v.getVisibility = () => 0;
  v.getZ = () => 0;
  v.getParent = () => parent;
  return v;
}
function scene() {
  const uri = make(C.uri, 'uri', {uriString: URI});
  const model = make(C.vm, 'vm', {uri});
  const root = view(C.root, 'root', null, 0);
  const classes = [C.pdf, C.digest, C.pen, 'android.widget.RelativeLayout',
    'android.widget.RelativeLayout', 'android.widget.FrameLayout'];
  const children = classes.map((name, i) => view(name, 'child-' + i, root, i));
  root.getChildCount = () => children.length;
  root.getChildAt = i => children[i];
  root.isChildrenDrawingOrderEnabled = () => false;
  const activity = make(C.activity, 'activity', {mResumed: true,
    mFinished: false, mDestroyed: false, documentViewModel: model,
    mContentView: root, mImage: children[0], digestImage: children[1],
    handWriteView: children[2]});
  return {activity, model, uri, root, children};
}
function manifest() {
  return {schemaVersion: 1,
    authority: 'rtl-reader-display0-hierarchy-manifest-v1',
    attachment: {packageName: 'com.supernote.document',
      processName: 'com.supernote.document', pid: 2256,
      startTimeTicks: '4134', firmwareFingerprint:
        'Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys',
      observerSha256: SHA},
    expected: {documentUri: URI, markPath: null},
    coordinator: {maxJavaChooseWalks: 1, retainedRootSamples: 2,
      hardDeadlineMs: 1000, detachOnDeadline: true,
      abortOnAnyError: true, noRetry: true}};
}
function run(changes = () => {}, options = {}) {
  const g = scene(), m = manifest();
  changes(g, m);
  const wire = options.wire || canonical(m);
  const bytes = [...Buffer.from(wire, 'utf8')];
  const digest = options.badDigest ? '0'.repeat(64) :
    crypto.createHash('sha256').update(Buffer.from(bytes)).digest('hex');
  const sent = [], retained = [], disposed = [];
  let chooseCalls = 0, envCalls = 0, onMain = false;
  const context = {
    NATIVE_PAGE_HIERARCHY_MANIFEST_UTF8: bytes,
    NATIVE_PAGE_HIERARCHY_MANIFEST_SHA256: digest,
    Process: {arch: 'arm64', pointerSize: 8, id: m.attachment.pid},
    Java: {
      use(name) { assert.strictEqual(name, C.uri); return {name}; },
      cast(value, clazz) { assert.strictEqual(value.$className, clazz.name); return value; },
      retain(value) {
        const copy = Object.create(value);
        const ordinal = retained.length;
        copy.$dispose = () => disposed.push(ordinal);
        retained.push(copy);
        return copy;
      },
      vm: {getEnv() {
        assert.strictEqual(onMain, true, 'JNIEnv must be acquired on UI thread');
        envCalls++;
        return {isSameObject(a, b) {
        return a && b && a.id === b.id;
      }}; }},
      choose(name, callback) {
        chooseCalls++;
        assert.strictEqual(name, C.activity);
        callback.onMatch(g.activity);
        callback.onComplete();
      },
      perform(callback) { callback(); },
      scheduleOnMainThread(callback) {
        onMain = true;
        try { callback(); } finally { onMain = false; }
      }
    },
    send(value) { sent.push(JSON.parse(JSON.stringify(value))); },
    setTimeout() { return 1; }, clearTimeout() {}
  };
  vm.runInNewContext(SOURCE, context);
  return {g, sent, chooseCalls, envCalls, retained, disposed};
}
function positive(result) {
  assert.strictEqual(result.sent.length, 2);
  assert.strictEqual(result.sent[0].event, 'native_page_hierarchy');
  assert.strictEqual(result.sent[1].success, true);
  assert.strictEqual(result.sent[0].childCount, 6);
  assert.deepStrictEqual(result.sent[0].fieldIndex, {pdf: 0, digest: 1, pen: 2});
  assert.strictEqual(result.sent[0].effectiveCompositingAdmitted, false);
  assert.strictEqual(result.chooseCalls, 1);
  assert.strictEqual(result.envCalls, 1);
  assert.deepStrictEqual(result.disposed, [0]);
}
function negative(result, phase, reason) {
  assert.strictEqual(result.sent.length, 2);
  assert.strictEqual(result.sent[0].event, 'native_page_hierarchy_error');
  assert.strictEqual(result.sent[0].phase, phase);
  assert.strictEqual(result.sent[0].reason, reason);
  assert.strictEqual(result.sent[1].success, false);
}

positive(run());
for (const visibility of [4, 8]) {
  const zeroSize = run(g => {
    g.children[5].getVisibility = () => visibility;
    g.children[5].mRight = slot(0);
    g.children[5].mBottom = slot(0);
  });
  positive(zeroSize);
  assert.deepStrictEqual(zeroSize.sent[0].children[5].bounds, [0, 0, 0, 0]);
}
negative(run(() => {}, {badDigest: true}), 'MANIFEST', 'INVALID');
negative(run((g, m) => { m.attachment.pid = 0; }), 'MANIFEST', 'INVALID');
negative(run(g => { g.activity.mContentView = slot(g.children[3]); }),
  'HIERARCHY', 'MISMATCH');
negative(run(g => { g.children[1].getParent = () => null; }),
  'HIERARCHY', 'MISMATCH');
negative(run(g => { g.root.getChildAt = i => g.children[i === 1 ? 0 : i]; }),
  'HIERARCHY', 'MISMATCH');
negative(run(g => { g.children[2].getZ = () => NaN; }),
  'HIERARCHY', 'MISMATCH');
negative(run(g => { g.children[0].mRight = slot(0); }),
  'HIERARCHY', 'MISMATCH');
negative(run(g => {
  g.children[5].getVisibility = () => 8;
  g.children[5].mRight = slot(-1);
}), 'HIERARCHY', 'MISMATCH');
negative(run(g => {
  const prior = g.children[2].getZ;
  let calls = 0;
  g.children[2].getZ = () => ++calls === 1 ? prior() : 3;
}), 'HIERARCHY', 'MISMATCH');
console.log('native_page_display0_hierarchy_observer: 12 cases PASS');
