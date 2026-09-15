'use strict';

// Executes the real observer against a closed Frida-shaped mock. The mock only
// exposes class enumeration, field values, runtime identity and message output.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const path = require('node:path');
const crypto = require('node:crypto');

const source = fs.readFileSync(path.join(__dirname, 'native_page_snapshot.js'), 'utf8');

const roleTypes = {
  activity: {
    identity: 'string', taskId: 'int32', displayId: 'int32',
    sessionGeneration: 'safeInt'
  },
  viewModel: {
    identity: 'string', uri: 'string', currentPageIndex: 'int32', pageCount: 'int32'
  },
  pageInfo: {
    identity: 'string', pageIndex: 'int32', width: 'finite', height: 'finite',
    cropLeft: 'finite', cropTop: 'finite', cropRight: 'finite', cropBottom: 'finite',
    ctmA: 'finite', ctmB: 'finite', ctmC: 'finite', ctmD: 'finite',
    ctmE: 'finite', ctmF: 'finite', inverseA: 'finite', inverseB: 'finite',
    inverseC: 'finite', inverseD: 'finite', inverseE: 'finite', inverseF: 'finite',
    offsetX: 'finite', offsetY: 'finite', bitmapWidth: 'int32', bitmapHeight: 'int32'
  },
  presenter: {
    identity: 'string', currentPageIndex: 'int32', markPath: 'nullableString',
    rotation: 'int32', noteIdentity: 'string', clientIdentity: 'string',
    binderIdentity: 'string'
  },
  layers: {
    identity: 'string', backgroundIdentity: 'string', committedHandwritingIdentity: 'string',
    digestLayerIdentity: 'string'
  }
};

function fields(role) {
  const result = {};
  for (const [name, type] of Object.entries(roleTypes[role])) {
    result[name] = {field: 'f_' + role + '_' + name, type};
  }
  return result;
}

function binding(role) {
  return {
    className: 'com.supernote.document.snapshot.' + role[0].toUpperCase() + role.slice(1),
    fields: fields(role),
    selector: {identity: role + '-identity'}
  };
}

function manifest() {
  return {
    schemaVersion: 1,
    authority: 'rtl-reader-native-page-snapshot-manifest-v1',
    attachment: {
      packageName: 'com.supernote.document', processName: 'Document', pid: 4312,
      startTimeTicks: '6336417',
      apk: {path: '/system_ext/priv-app/Document/Document.apk', size: 12345678,
        sha256: '2'.repeat(64)},
      module: {name: 'libdocument_snapshot.so',
        path: '/system_ext/priv-app/Document/lib/arm64/libdocument_snapshot.so',
        size: 7654321, sha256: '3'.repeat(64)}
    },
    files: {
      authority: 'rtl-reader-native-page-file-authority-v1',
      verification: 'external-before-and-after-exact',
      originalPdf: {
        present: true, path: '/storage/emulated/0/Document/fixture.pdf',
        documentUri: 'file:///storage/emulated/0/Document/fixture.pdf',
        uriResolution: {
          authority: 'rtl-reader-file-uri-resolution-v1',
          documentUri: 'file:///storage/emulated/0/Document/fixture.pdf',
          resolvedPath: '/storage/emulated/0/Document/fixture.pdf',
          evidenceSha256: '8'.repeat(64)
        },
        size: '987654', sha256: '4'.repeat(64),
        stat: {device: '1032', inode: '81234', mode: '33188', uid: 1023, gid: 1023,
          mtimeNs: '1789000000000000000', ctimeNs: '1789000000000000000'}
      },
      mark: {
        present: true, path: '/storage/emulated/0/Document/fixture.pdf.mark',
        size: '5756', sha256: '5'.repeat(64),
        stat: {device: '1032', inode: '81235', mode: '33188', uid: 1023, gid: 1023,
          mtimeNs: '1789000000000000001', ctimeNs: '1789000000000000001'}
      }
    },
    coordinator: {
      authority: 'rtl-reader-native-page-snapshot-coordinator-v1',
      observerSessionId: 'session-20260911-0001', hardDeadlineMs: 5000,
      maxJavaChooseWalks: 10, detachOnDeadline: true, abortOnAnyError: true,
      verifyTargetLivenessAfter: true
    },
    expected: {
      taskId: 17, displayId: 0, sessionGeneration: 99,
      uri: 'file:///storage/emulated/0/Document/fixture.pdf',
      currentPageIndex: 142, pageCount: 300
    },
    bindings: {
      activity: binding('activity'), viewModel: binding('viewModel'),
      pageInfo: binding('pageInfo'), presenter: binding('presenter'),
      layers: Object.assign({status: 'bound'}, binding('layers'))
    }
  };
}

function canonicalJson(value) {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') return String(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  return '{' + Object.keys(value).sort().map(key =>
    JSON.stringify(key) + ':' + canonicalJson(value[key])).join(',') + '}';
}

function records() {
  return {
    activity: {identity: 'activity-identity', taskId: 17, displayId: 0,
      sessionGeneration: 99},
    viewModel: {identity: 'viewModel-identity',
      uri: 'file:///storage/emulated/0/Document/fixture.pdf', currentPageIndex: 142,
      pageCount: 300},
    pageInfo: {identity: 'pageInfo-identity', pageIndex: 142, width: 936, height: 1404,
      cropLeft: 0, cropTop: 0, cropRight: 936, cropBottom: 1404,
      ctmA: 2, ctmB: -0, ctmC: 0, ctmD: 2, ctmE: 10, ctmF: 20,
      inverseA: 0.5, inverseB: -0, inverseC: 0, inverseD: 0.5,
      inverseE: -5, inverseF: -10, offsetX: 78, offsetY: 0,
      bitmapWidth: 1872, bitmapHeight: 1404},
    presenter: {identity: 'presenter-identity', currentPageIndex: 142,
      markPath: '/storage/emulated/0/Document/fixture.pdf.mark', rotation: 0,
      noteIdentity: 'note-identity', clientIdentity: 'client-identity',
      binderIdentity: 'binder-identity'},
    layers: {identity: 'layers-identity', backgroundIdentity: 'background-identity',
      committedHandwritingIdentity: 'committed-identity',
      digestLayerIdentity: 'digest-identity'}
  };
}

function cloneRecord(value) {
  return Object.assign({}, value);
}

function setTransform(record, matrix) {
  const [a, b, c, d, e, f] = matrix;
  const determinant = a * d - b * c;
  Object.assign(record, {
    ctmA: a, ctmB: b, ctmC: c, ctmD: d, ctmE: e, ctmF: f,
    inverseA: d / determinant, inverseB: -b / determinant,
    inverseC: -c / determinant, inverseD: a / determinant,
    inverseE: (c * f - d * e) / determinant,
    inverseF: (b * e - a * f) / determinant
  });
}

function wrapRecord(role, record, activeManifest, options, sampleNumber) {
  const instance = {};
  const descriptors = activeManifest.bindings[role].fields;
  for (const name of Object.keys(roleTypes[role])) {
    if (options.missingField === role + '.' + name) continue;
    instance[descriptors[name].field] = {value: record[name]};
  }
  if (options.replaceFieldSlot === role) {
    instance[descriptors.identity.field] = function () {};
  }
  return instance;
}

function run(options = {}) {
  const activeManifest = manifest();
  if (options.manifestMutator) options.manifestMutator(activeManifest);
  let wireText = canonicalJson(activeManifest);
  if (options.rawWireMutator) wireText = options.rawWireMutator(wireText);
  const wire = Array.from(Buffer.from(wireText, 'utf8'));
  if (options.wireMutatorBeforeDigest) options.wireMutatorBeforeDigest(wire);
  let wireDigest = crypto.createHash('sha256').update(Buffer.from(wire)).digest('hex');
  if (options.wireByteMutationAfterDigest) {
    const index = Math.min(options.wireByteMutationAfterDigest.index || 0, wire.length - 1);
    wire[index] ^= options.wireByteMutationAfterDigest.xor || 1;
  }
  if (options.digestMutator) wireDigest = options.digestMutator(wireDigest);
  const sent = [];
  const calls = [];
  let moduleSample = 0;
  let clockReads = 0;

  const Process = {
    arch: options.arch || 'arm64', pointerSize: options.pointerSize || 8,
    id: options.pid === undefined ? 4312 : options.pid,
    getModuleByName(name) {
      calls.push('Process.getModuleByName:' + name);
      moduleSample += 1;
      if (options.moduleMissing) return null;
      const expected = activeManifest.attachment.module;
      const current = {name: expected.name, path: expected.path, size: expected.size};
      if (options.replaceModule && moduleSample === 2) current.path += '.replacement';
      if (options.resizeModule && moduleSample === 2) current.size += 1;
      return current;
    }
  };

  const Java = {
    perform(action) {
      calls.push('Java.perform');
      if (options.performError) throw 'P'.repeat(1000);
      if (options.hostilePerformError) throw options.hostilePerformError;
      action();
    },
    choose(className, callbacks) {
      let role = null;
      for (const candidate of Object.keys(roleTypes)) {
        const configured = activeManifest.bindings[candidate];
        if (configured.status !== 'unavailable' && configured.className === className) role = candidate;
      }
      calls.push('Java.choose:' + (role || className));
      if (options.chooseError === role) throw 'choose failed';
      if (role === null || options.missingClass === role) {
        callbacks.onComplete();
        return;
      }
      const sampleNumber = moduleSample;
      const base = cloneRecord(records()[role]);
      if (options.recordMutator) options.recordMutator(role, sampleNumber, base);
      const candidates = [base];
      if (options.ambiguous === role) candidates.push(cloneRecord(base));
      if (options.tooMany === role) {
        for (let i = 1; i < 34; i++) {
          const extra = cloneRecord(base);
          extra.identity = role + '-nonmatch-' + i;
          candidates.push(extra);
        }
      }
      for (const candidate of candidates) {
        const result = callbacks.onMatch(wrapRecord(role, candidate, activeManifest,
          options, sampleNumber));
        if (result === 'stop') break;
      }
      callbacks.onComplete();
    }
  };

  const DateApi = {
    now() {
      clockReads += 1;
      if (options.clock) return options.clock(clockReads);
      return 1000;
    }
  };

  vm.runInNewContext(source, {
    Process, Java, Date: DateApi,
    NATIVE_PAGE_SNAPSHOT_MANIFEST_UTF8: wire,
    NATIVE_PAGE_SNAPSHOT_MANIFEST_SHA256: wireDigest,
    send: value => sent.push(value)
  }, {timeout: 1000});
  return {sent, calls, activeManifest, wire, wireDigest, clockReads};
}

let checks = 0;

function assertTerminal(sent, success) {
  assert.equal(sent.length, 2, 'exactly one record/error and one terminal frame');
  assert.equal(sent.at(-1).event, 'native_page_snapshot_complete');
  assert.equal(sent.at(-1).success, success,
    sent[0] && sent[0].message ? sent[0].message : 'unexpected terminal state');
  if (success) {
    assert.equal(sent[0].event, 'native_page_snapshot');
    assert.equal(sent[0].observationOnly, true);
    assert.equal(sent[0].atomic, false);
  } else {
    assert.equal(sent[0].event, 'native_page_snapshot_error');
    assert.equal(sent[0].code, 'SNAPSHOT_REJECTED');
    assert(sent[0].message.length <= 512);
    assert(!sent.some(item => item.event === 'native_page_snapshot'));
  }
}

function passed(options, inspect) {
  const result = run(options);
  assertTerminal(result.sent, true);
  if (inspect) inspect(result);
  checks += 1;
}

function failed(options, pattern) {
  const result = run(options);
  assertTerminal(result.sent, false);
  if (pattern) assert.match(result.sent[0].message, pattern);
  checks += 1;
}

// Static deny-list plus a closed runtime API catches accidental expansion from
// field observation into mutation, interception, target-code execution or bytes.
for (const denied of [
  /\bInterceptor\b/, /\bNativeFunction\b/, /\bNativeCallback\b/, /\bMemory\b/,
  /Java\.use\s*\(/, /Java\.registerClass\s*\(/,
  /\.read(?:Pointer|ByteArray|Utf8String|U(?:8|16|32|64)|S(?:8|16|32|64))\s*\(/,
  /\.write[A-Za-z0-9_]*\s*\(/
]) assert(!denied.test(source), 'forbidden observer capability: ' + denied);
assert(!/\.value\s*=/.test(source), 'observer assigns a Java field value');
assert.deepEqual([...source.matchAll(/\bProcess\.([A-Za-z_$][A-Za-z0-9_$]*)/g)]
  .map(match => match[1]).filter((value, index, all) => all.indexOf(value) === index).sort(),
['arch', 'getModuleByName', 'id', 'pointerSize']);
assert.deepEqual([...source.matchAll(/\bJava\.([A-Za-z_$][A-Za-z0-9_$]*)/g)]
  .map(match => match[1]).filter((value, index, all) => all.indexOf(value) === index).sort(),
['choose', 'perform']);
checks += 1;

passed({}, ({sent, calls, wireDigest}) => {
  assert.deepEqual(calls, [
    'Java.perform',
    'Process.getModuleByName:libdocument_snapshot.so',
    'Java.choose:activity', 'Java.choose:viewModel', 'Java.choose:pageInfo',
    'Java.choose:presenter', 'Java.choose:layers',
    'Process.getModuleByName:libdocument_snapshot.so',
    'Java.choose:activity', 'Java.choose:viewModel', 'Java.choose:pageInfo',
    'Java.choose:presenter', 'Java.choose:layers'
  ]);
  const event = sent[0];
  assert.equal(event.attachment.packageName, 'com.supernote.document');
  assert.equal(event.session.taskId, 17);
  assert.equal(event.document.currentPageIndex, 142);
  assert.equal(event.document.pageInfo.ctm[1].binary64, '0x8000000000000000');
  assert.equal(event.presenter.markPath, '/storage/emulated/0/Document/fixture.pdf.mark');
  assert.equal(event.manifestSha256, wireDigest);
  assert.equal(event.fileAuthority.originalPdf.stat.inode, '81234');
  assert.equal(event.coordinator.javaChooseWalks, 10);
  assert.equal(event.coordinator.externalDetachOnDeadline, true);
  assert.equal(event.coordinator.externalTargetLivenessPostconditionRequired, true);
  assert.equal(event.layers.committedHandwritingIdentity, 'committed-identity');
  assert.equal(event.drawPathPrerequisite.status, 'external-prerequisite');
});

passed({manifestMutator: m => {
  m.bindings.layers = {status: 'unavailable', reasonCode: 'FIELD_MAP_NOT_ESTABLISHED',
    evidenceId: 'pinned-firmware-review-pending'};
}}, ({sent, calls}) => {
  assert.equal(sent[0].layers.status, 'unavailable');
  assert.equal(sent[0].coordinator.javaChooseWalks, 8);
  assert(!calls.includes('Java.choose:layers'));
});

passed({
  manifestMutator: m => {
    m.files.mark = {present: false, path: null, size: null, sha256: null, stat: null};
  },
  recordMutator: (role, _sample, record) => {
    if (role === 'presenter') record.markPath = null;
  }
}, ({sent}) => assert.equal(sent[0].presenter.markPath, null));

passed({
  manifestMutator: m => {
    const uri = 'file:///storage/emulated/0/Document/%D7%91%D7%93%D7%99%D7%A7%D7%94%20copy.pdf';
    const resolved = '/storage/emulated/0/Document/בדיקה copy.pdf';
    m.expected.uri = uri;
    m.files.originalPdf.path = resolved;
    m.files.originalPdf.documentUri = uri;
    m.files.originalPdf.uriResolution.documentUri = uri;
    m.files.originalPdf.uriResolution.resolvedPath = resolved;
    m.files.mark.path = resolved + '.mark';
  },
  recordMutator: (role, _sample, record) => {
    if (role === 'viewModel') {
      record.uri = 'file:///storage/emulated/0/Document/%D7%91%D7%93%D7%99%D7%A7%D7%94%20copy.pdf';
    }
    if (role === 'presenter') {
      record.markPath = '/storage/emulated/0/Document/בדיקה copy.pdf.mark';
    }
  }
}, ({sent}) => assert.equal(sent[0].fileAuthority.originalPdf.path,
  '/storage/emulated/0/Document/בדיקה copy.pdf'));

passed({
  manifestMutator: m => {
    const uri = 'content://com.supernote.fileprovider/document/fixture';
    m.expected.uri = uri;
    m.files.originalPdf.documentUri = uri;
    m.files.originalPdf.uriResolution = {
      authority: 'rtl-reader-content-uri-resolution-v1', documentUri: uri,
      resolvedPath: m.files.originalPdf.path,
      providerPackage: 'com.supernote.fileprovider',
      providerApkSha256: '6'.repeat(64), evidenceSha256: '7'.repeat(64)
    };
  },
  recordMutator: (role, _sample, record) => {
    if (role === 'viewModel') {
      record.uri = 'content://com.supernote.fileprovider/document/fixture';
    }
  }
}, ({sent}) => assert.equal(sent[0].fileAuthority.originalPdf.uriResolution.authority,
  'rtl-reader-content-uri-resolution-v1'));

{
  let conversionCalled = false;
  const result = run({recordMutator: (role, _sample, record) => {
    if (role === 'viewModel') {
      record.uri = {toString() { conversionCalled = true; return 'forbidden'; }};
    }
  }});
  assertTerminal(result.sent, false);
  assert.equal(conversionCalled, false, 'observer invoked a target-style string conversion');
  checks += 1;
}

{
  let hostileTouched = false;
  const hostile = new Proxy({}, {
    get() { hostileTouched = true; throw new Error('coercion'); },
    getOwnPropertyDescriptor() { hostileTouched = true; throw new Error('coercion'); },
    ownKeys() { hostileTouched = true; throw new Error('coercion'); }
  });
  const result = run({hostilePerformError: hostile});
  assertTerminal(result.sent, false);
  assert.equal(result.sent[0].message, 'non-primitive observation failure');
  assert.equal(hostileTouched, false, 'observer inspected or coerced a hostile thrown object');
  checks += 1;
}

failed({digestMutator: digest => (digest[0] === '0' ? '1' : '0') + digest.slice(1)},
  /detached manifest SHA-256 mismatch/);
failed({wireByteMutationAfterDigest: {index: 12, xor: 1}},
  /detached manifest SHA-256 mismatch/);
failed({rawWireMutator: text => text.replace(
  '"authority":"rtl-reader-native-page-snapshot-manifest-v1"',
  '"authority":"rtl-reader-native-page-snapshot-manifest-v1",' +
  '"authority":"rtl-reader-native-page-snapshot-manifest-v1"')},
  /manifest wire is not canonical/);
failed({rawWireMutator: text => text + ' '}, /manifest wire is not canonical/);
failed({wireMutatorBeforeDigest: wire => { wire[0] = 0xc0; }}, /UTF-8/);

failed({arch: 'arm'}, /architecture/);
failed({pointerSize: 4}, /architecture/);
failed({pid: 4313}, /PID/);
failed({moduleMissing: true}, /module is missing/);
failed({replaceModule: true}, /module identity changed|snapshot changed/);
failed({resizeModule: true}, /module identity changed|snapshot changed/);
failed({missingClass: 'presenter'}, /presenter selection is missing/);
failed({missingField: 'pageInfo.bitmapWidth'}, /field is unavailable/);
failed({replaceFieldSlot: 'activity'}, /field is unavailable/);
failed({ambiguous: 'viewModel'}, /ambiguous/);
failed({tooMany: 'pageInfo'}, /candidate bound exceeded/);
failed({chooseError: 'presenter'}, /choose failed/);
failed({performError: true}, /P{100}/);
failed({clock: read => read < 3 ? 1000 : 7001}, /deadline exceeded/);

failed({recordMutator: (role, _sample, record) => {
  if (role === 'activity') record.taskId = 18;
}}, /wrong task/);
failed({recordMutator: (role, _sample, record) => {
  if (role === 'activity') record.displayId = 4;
}}, /wrong display/);
failed({recordMutator: (role, _sample, record) => {
  if (role === 'activity') record.sessionGeneration = 100;
}}, /session generation/);
failed({recordMutator: (role, _sample, record) => {
  if (role === 'viewModel') record.currentPageIndex = 143;
}}, /wrong current page/);
failed({recordMutator: (role, _sample, record) => {
  if (role === 'viewModel') record.uri += '.replacement';
}}, /document URI/);
failed({recordMutator: (role, _sample, record) => {
  if (role === 'viewModel') record.pageCount = 301;
}}, /page count/);
failed({recordMutator: (role, _sample, record) => {
  if (role === 'pageInfo') record.pageIndex = 141;
}}, /PageInfo page mismatch/);
failed({recordMutator: (role, _sample, record) => {
  if (role === 'presenter') record.currentPageIndex = 141;
}}, /presenter page mismatch/);

for (const bad of [NaN, Infinity, -Infinity]) {
  failed({recordMutator: (role, _sample, record) => {
    if (role === 'pageInfo') record.ctmA = bad;
  }}, /must be finite/);
}
failed({recordMutator: (role, _sample, record) => {
  if (role === 'pageInfo') record.ctmD = 0;
}}, /singular|inverse mismatch/);
failed({recordMutator: (role, _sample, record) => {
  if (role === 'pageInfo') record.inverseE = -4;
}}, /inverse mismatch/);
passed({recordMutator: (role, _sample, record) => {
  if (role === 'pageInfo') setTransform(record, [0.000001, 0, 0, 0.000002, 0.1, -0.25]);
}});
passed({recordMutator: (role, _sample, record) => {
  if (role === 'pageInfo') setTransform(record, [1.5, 0.25, -0.5, 2, 1000000000, -800000000]);
}});
failed({recordMutator: (role, _sample, record) => {
  if (role === 'pageInfo') {
    setTransform(record, [1.5, 0.25, -0.5, 2, 1000000000, -800000000]);
    record.inverseE += 0.1;
  }
}}, /translation inverse mismatch/);
failed({recordMutator: (role, _sample, record) => {
  if (role === 'pageInfo') {
    setTransform(record, [1.5, 0.25, -0.5, 2, 1000000000, -800000000]);
    record.inverseA += 0.000001;
  }
}}, /linear inverse mismatch/);
failed({recordMutator: (role, _sample, record) => {
  if (role === 'pageInfo') record.cropRight = record.cropLeft;
}}, /crop rectangle/);
failed({recordMutator: (role, _sample, record) => {
  if (role === 'pageInfo') record.bitmapWidth = 0;
}}, /bitmap dimensions/);

failed({recordMutator: (role, sample, record) => {
  if (role === 'presenter' && sample === 2) record.noteIdentity += '.changed';
}}, /snapshot changed/);
failed({recordMutator: (role, _sample, record) => {
  if (role === 'presenter') record.markPath = 'x'.repeat(4097);
}}, /byte bound/);
failed({recordMutator: (role, sample, record) => {
  if (role === 'activity' && sample === 2) record.identity = 'replacement-activity';
}}, /selection is missing|snapshot changed/);

failed({manifestMutator: m => { m.extra = true; }}, /manifest fields mismatch/);
failed({manifestMutator: m => { m.manifestSha256 = '1'.repeat(64); }},
  /manifest fields mismatch/);
failed({manifestMutator: m => { m.bindings.pageInfo.fields.width.extra = true; }},
  /descriptor fields mismatch/);
failed({manifestMutator: m => { m.bindings.activity.fields.identity.field = '$h'; }},
  /field is unsafe/);
failed({manifestMutator: m => { m.bindings.activity.selector = {}; }}, /selector/);
failed({manifestMutator: m => { m.bindings.layers.status = 'optional'; }}, /status/);
failed({manifestMutator: m => { m.attachment.packageName = 'com.example.other'; }},
  /package identity/);
failed({manifestMutator: m => { m.attachment.processName = 'Other'; }}, /process identity/);
failed({manifestMutator: m => { m.attachment.module.sha256 = 'A'.repeat(64); }}, /SHA-256/);
failed({manifestMutator: m => { m.files.originalPdf.stat.inode = '0'; }}, /decimal integer/);
failed({manifestMutator: m => { m.files.originalPdf.sha256 = '6'.repeat(63); }}, /SHA-256/);
failed({manifestMutator: m => {
  m.files.originalPdf.documentUri = 'file:///storage/emulated/0/Document/replacement.pdf';
  m.files.originalPdf.uriResolution.documentUri =
    'file:///storage/emulated/0/Document/replacement.pdf';
}}, /descriptor documentUri does not match expected URI/);
failed({manifestMutator: m => {
  m.files.originalPdf.uriResolution = null;
}}, /URI resolution must be an object/);
failed({manifestMutator: m => {
  m.files.originalPdf.uriResolution.documentUri =
    'file:///storage/emulated/0/Document/other.pdf';
}}, /file URI resolution documentUri mismatch/);
failed({manifestMutator: m => {
  m.files.originalPdf.uriResolution.resolvedPath =
    '/storage/emulated/0/Document/other.pdf';
}}, /file URI resolution path mismatch/);
failed({manifestMutator: m => {
  m.files.originalPdf.uriResolution.evidenceSha256 = '8'.repeat(63);
}}, /SHA-256/);
failed({manifestMutator: m => {
  m.files.originalPdf.path = '/storage/emulated/0/Document/different.pdf';
  m.files.originalPdf.sha256 = '9'.repeat(64);
}}, /file URI resolution path mismatch/);
failed({manifestMutator: m => {
  const uri = 'content://com.supernote.fileprovider/document/fixture';
  m.expected.uri = uri;
  m.files.originalPdf.documentUri = uri;
  m.files.originalPdf.uriResolution = null;
}}, /URI resolution must be an object/);
failed({
  manifestMutator: m => {
    const uri = 'content://com.supernote.fileprovider/document/fixture';
    m.expected.uri = uri;
    m.files.originalPdf.documentUri = uri;
    m.files.originalPdf.uriResolution = {
      authority: 'rtl-reader-content-uri-resolution-v1', documentUri: uri,
      resolvedPath: '/storage/emulated/0/Document/wrong.pdf',
      providerPackage: 'com.supernote.fileprovider',
      providerApkSha256: '6'.repeat(64), evidenceSha256: '7'.repeat(64)
    };
  },
  recordMutator: (role, _sample, record) => {
    if (role === 'viewModel') {
      record.uri = 'content://com.supernote.fileprovider/document/fixture';
    }
  }
}, /content URI resolution path mismatch/);
failed({manifestMutator: m => { m.files.mark.present = false; }}, /explicit nulls/);
failed({recordMutator: (role, _sample, record) => {
  if (role === 'presenter') record.markPath = '/storage/emulated/0/Document/replaced.mark';
}}, /mark path does not match/);
failed({
  manifestMutator: m => {
    m.files.mark = {present: false, path: null, size: null, sha256: null, stat: null};
  }
}, /mark path exists without file authority/);
failed({manifestMutator: m => { m.coordinator.hardDeadlineMs = 10001; }}, /deadline is invalid/);
failed({manifestMutator: m => { m.coordinator.maxJavaChooseWalks = 9; }}, /walk budget/);
failed({manifestMutator: m => { m.coordinator.detachOnDeadline = false; }}, /postconditions/);
failed({manifestMutator: m => { m.coordinator.verifyTargetLivenessAfter = false; }},
  /postconditions/);
failed({manifestMutator: m => { m.expected.currentPageIndex = 300; }}, /current page/);
failed({manifestMutator: m => { m.expected.uri = 'x'.repeat(4097); }}, /byte bound/);

console.log('PASS ' + checks +
  ' closed native-page snapshot cases; observation contract only, no hardware claim.');
