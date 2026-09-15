'use strict';

// Read-only Java-heap observation for one already-loaded native Document page.
// The exact firmware field map is supplied by an externally authenticated
// manifest. This script only enumerates exact classes and reads field values.
(function () {
  const SCHEMA_VERSION = 1;
  const MANIFEST_AUTHORITY = 'rtl-reader-native-page-snapshot-manifest-v1';
  const RECORD_AUTHORITY = 'rtl-reader-native-page-snapshot-v1';
  const PACKAGE_NAME = 'com.supernote.document';
  const PROCESS_NAME = 'Document';
  const MAX_CANDIDATES = 32;
  const MAX_MANIFEST_BYTES = 131072;
  const MAX_STRING_BYTES = 4096;
  const MAX_ERROR_CHARS = 512;
  const MAX_MODULE_BYTES = 536870912;
  const MAX_PAGE_COUNT = 10000000;
  const MAX_DIMENSION = 10000000;
  const MAX_MATRIX_ABS = 1000000000000;
  const COORDINATOR_AUTHORITY = 'rtl-reader-native-page-snapshot-coordinator-v1';
  const FILE_AUTHORITY = 'rtl-reader-native-page-file-authority-v1';

  const ROLE_FIELDS = {
    activity: {
      identity: 'string', taskId: 'int32', displayId: 'int32',
      sessionGeneration: 'safeInt'
    },
    viewModel: {
      identity: 'string', uri: 'string', currentPageIndex: 'int32',
      pageCount: 'int32'
    },
    pageInfo: {
      identity: 'string', pageIndex: 'int32', width: 'finite', height: 'finite',
      cropLeft: 'finite', cropTop: 'finite', cropRight: 'finite',
      cropBottom: 'finite', ctmA: 'finite', ctmB: 'finite', ctmC: 'finite',
      ctmD: 'finite', ctmE: 'finite', ctmF: 'finite', inverseA: 'finite',
      inverseB: 'finite', inverseC: 'finite', inverseD: 'finite',
      inverseE: 'finite', inverseF: 'finite', offsetX: 'finite',
      offsetY: 'finite', bitmapWidth: 'int32', bitmapHeight: 'int32'
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

  let terminalSent = false;
  let chooseWalks = 0;
  let localDeadlineMs = 0;

  function requireThat(condition, message) {
    if (!condition) throw message;
  }

  function isRecord(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }

  function exactKeys(value, expected, label) {
    requireThat(isRecord(value), label + ' must be an object');
    const actual = Object.keys(value).sort();
    const wanted = expected.slice().sort();
    requireThat(actual.length === wanted.length, label + ' fields mismatch');
    for (let i = 0; i < wanted.length; i++) {
      requireThat(actual[i] === wanted[i], label + ' fields mismatch');
    }
  }

  function utf8Bytes(value) {
    let bytes = 0;
    for (let i = 0; i < value.length; i++) {
      const first = value.charCodeAt(i);
      requireThat(first !== 0, 'string contains NUL');
      if (first <= 0x7f) {
        bytes += 1;
      } else if (first <= 0x7ff) {
        bytes += 2;
      } else if (first >= 0xd800 && first <= 0xdbff) {
        requireThat(i + 1 < value.length, 'unpaired high surrogate');
        const second = value.charCodeAt(++i);
        requireThat(second >= 0xdc00 && second <= 0xdfff, 'unpaired high surrogate');
        bytes += 4;
      } else {
        requireThat(first < 0xdc00 || first > 0xdfff, 'unpaired low surrogate');
        bytes += 3;
      }
      requireThat(bytes <= MAX_STRING_BYTES, 'string exceeds byte bound');
    }
    return bytes;
  }

  function checkedString(value, nullable, label) {
    if (nullable && value === null) return null;
    requireThat(typeof value === 'string' && value.length > 0, label + ' must be a nonempty string');
    utf8Bytes(value);
    return value;
  }

  function checkedInteger(value, label) {
    requireThat(typeof value === 'number' && Number.isSafeInteger(value) &&
      !Object.is(value, -0), label + ' must be a safe integer');
    return value;
  }

  function checkedValue(value, type, label) {
    if (type === 'string') return checkedString(value, false, label);
    if (type === 'nullableString') return checkedString(value, true, label);
    if (type === 'int32') {
      checkedInteger(value, label);
      requireThat(value >= -2147483648 && value <= 2147483647, label + ' exceeds int32');
      return value;
    }
    if (type === 'safeInt') return checkedInteger(value, label);
    if (type === 'finite') {
      requireThat(typeof value === 'number' && Number.isFinite(value), label + ' must be finite');
      requireThat(Math.abs(value) <= MAX_MATRIX_ABS, label + ' exceeds numeric bound');
      return value;
    }
    throw label + ' has unsupported type';
  }

  function checkedSha256(value, label) {
    requireThat(typeof value === 'string' && /^[0-9a-f]{64}$/.test(value),
      label + ' must be lowercase SHA-256');
    return value;
  }

  function checkedDecimal(value, label, allowZero) {
    checkedString(value, false, label);
    const expression = allowZero ? /^(0|[1-9][0-9]{0,39})$/ : /^[1-9][0-9]{0,39}$/;
    requireThat(expression.test(value), label + ' must be a bounded decimal integer');
    return value;
  }

  function utf8Encode(value) {
    const result = [];
    for (let i = 0; i < value.length; i++) {
      let point = value.charCodeAt(i);
      requireThat(point !== 0, 'string contains NUL');
      if (point >= 0xd800 && point <= 0xdbff) {
        requireThat(i + 1 < value.length, 'unpaired high surrogate');
        const low = value.charCodeAt(++i);
        requireThat(low >= 0xdc00 && low <= 0xdfff, 'unpaired high surrogate');
        point = 0x10000 + ((point - 0xd800) << 10) + (low - 0xdc00);
      } else {
        requireThat(point < 0xdc00 || point > 0xdfff, 'unpaired low surrogate');
      }
      if (point <= 0x7f) result.push(point);
      else if (point <= 0x7ff) {
        result.push(0xc0 | (point >>> 6), 0x80 | (point & 0x3f));
      } else if (point <= 0xffff) {
        result.push(0xe0 | (point >>> 12), 0x80 | ((point >>> 6) & 0x3f),
          0x80 | (point & 0x3f));
      } else {
        result.push(0xf0 | (point >>> 18), 0x80 | ((point >>> 12) & 0x3f),
          0x80 | ((point >>> 6) & 0x3f), 0x80 | (point & 0x3f));
      }
    }
    return result;
  }

  function utf8Decode(bytes) {
    let result = '';
    for (let i = 0; i < bytes.length;) {
      const first = bytes[i++];
      let point;
      if (first <= 0x7f) {
        requireThat(first !== 0, 'manifest contains NUL');
        point = first;
      } else if (first >= 0xc2 && first <= 0xdf) {
        requireThat(i < bytes.length, 'truncated UTF-8');
        const second = bytes[i++];
        requireThat((second & 0xc0) === 0x80, 'invalid UTF-8 continuation');
        point = ((first & 0x1f) << 6) | (second & 0x3f);
      } else if (first >= 0xe0 && first <= 0xef) {
        requireThat(i + 1 < bytes.length, 'truncated UTF-8');
        const second = bytes[i++];
        const third = bytes[i++];
        requireThat((second & 0xc0) === 0x80 && (third & 0xc0) === 0x80,
          'invalid UTF-8 continuation');
        requireThat(!(first === 0xe0 && second < 0xa0) &&
          !(first === 0xed && second >= 0xa0), 'noncanonical UTF-8');
        point = ((first & 0x0f) << 12) | ((second & 0x3f) << 6) | (third & 0x3f);
      } else if (first >= 0xf0 && first <= 0xf4) {
        requireThat(i + 2 < bytes.length, 'truncated UTF-8');
        const second = bytes[i++];
        const third = bytes[i++];
        const fourth = bytes[i++];
        requireThat((second & 0xc0) === 0x80 && (third & 0xc0) === 0x80 &&
          (fourth & 0xc0) === 0x80, 'invalid UTF-8 continuation');
        requireThat(!(first === 0xf0 && second < 0x90) &&
          !(first === 0xf4 && second >= 0x90), 'noncanonical UTF-8');
        point = ((first & 7) << 18) | ((second & 0x3f) << 12) |
          ((third & 0x3f) << 6) | (fourth & 0x3f);
      } else {
        throw 'invalid UTF-8 lead byte';
      }
      if (point <= 0xffff) result += String.fromCharCode(point);
      else {
        point -= 0x10000;
        result += String.fromCharCode(0xd800 | (point >>> 10), 0xdc00 | (point & 0x3ff));
      }
    }
    return result;
  }

  function canonicalJson(value) {
    if (value === null) return 'null';
    if (typeof value === 'boolean') return value ? 'true' : 'false';
    if (typeof value === 'string') return JSON.stringify(value);
    if (typeof value === 'number') {
      requireThat(Number.isSafeInteger(value) && !Object.is(value, -0),
        'manifest numbers must be non-negative-zero safe integers');
      return String(value);
    }
    if (Array.isArray(value)) {
      return '[' + value.map(canonicalJson).join(',') + ']';
    }
    requireThat(isRecord(value), 'manifest contains unsupported JSON value');
    const keys = Object.keys(value).sort();
    return '{' + keys.map(function (key) {
      return JSON.stringify(key) + ':' + canonicalJson(value[key]);
    }).join(',') + '}';
  }

  function sha256(bytes) {
    const constants = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
      0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
      0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
      0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
      0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    const data = bytes.slice();
    const bitLength = data.length * 8;
    data.push(0x80);
    while ((data.length % 64) !== 56) data.push(0);
    for (let shift = 56; shift >= 0; shift -= 8) {
      data.push(shift >= 32 ? 0 : (bitLength / Math.pow(2, shift)) & 0xff);
    }
    const state = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const rotate = function (value, count) { return (value >>> count) | (value << (32 - count)); };
    for (let offset = 0; offset < data.length; offset += 64) {
      const words = new Array(64);
      for (let i = 0; i < 16; i++) {
        const at = offset + i * 4;
        words[i] = ((data[at] << 24) | (data[at + 1] << 16) |
          (data[at + 2] << 8) | data[at + 3]) >>> 0;
      }
      for (let i = 16; i < 64; i++) {
        const s0 = rotate(words[i - 15], 7) ^ rotate(words[i - 15], 18) ^
          (words[i - 15] >>> 3);
        const s1 = rotate(words[i - 2], 17) ^ rotate(words[i - 2], 19) ^
          (words[i - 2] >>> 10);
        words[i] = (words[i - 16] + s0 + words[i - 7] + s1) >>> 0;
      }
      let a = state[0], b = state[1], c = state[2], d = state[3];
      let e = state[4], f = state[5], g = state[6], h = state[7];
      for (let i = 0; i < 64; i++) {
        const upper1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25);
        const choice = (e & f) ^ (~e & g);
        const first = (h + upper1 + choice + constants[i] + words[i]) >>> 0;
        const upper0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22);
        const majority = (a & b) ^ (a & c) ^ (b & c);
        const second = (upper0 + majority) >>> 0;
        h = g; g = f; f = e; e = (d + first) >>> 0;
        d = c; c = b; b = a; a = (first + second) >>> 0;
      }
      state[0] = (state[0] + a) >>> 0; state[1] = (state[1] + b) >>> 0;
      state[2] = (state[2] + c) >>> 0; state[3] = (state[3] + d) >>> 0;
      state[4] = (state[4] + e) >>> 0; state[5] = (state[5] + f) >>> 0;
      state[6] = (state[6] + g) >>> 0; state[7] = (state[7] + h) >>> 0;
    }
    return state.map(function (word) { return word.toString(16).padStart(8, '0'); }).join('');
  }

  function parseManifestWire() {
    const bytes = globalThis.NATIVE_PAGE_SNAPSHOT_MANIFEST_UTF8;
    const expectedDigest = globalThis.NATIVE_PAGE_SNAPSHOT_MANIFEST_SHA256;
    requireThat(Array.isArray(bytes) && bytes.length > 0 && bytes.length <= MAX_MANIFEST_BYTES,
      'manifest wire is missing or oversized');
    const copy = [];
    for (let i = 0; i < bytes.length; i++) {
      requireThat(Number.isInteger(bytes[i]) && bytes[i] >= 0 && bytes[i] <= 255,
        'manifest wire contains a non-byte');
      copy.push(bytes[i]);
    }
    checkedSha256(expectedDigest, 'detached manifest SHA-256');
    requireThat(sha256(copy) === expectedDigest, 'detached manifest SHA-256 mismatch');
    const text = utf8Decode(copy);
    let manifest;
    try { manifest = JSON.parse(text); } catch (_) { throw 'manifest JSON is invalid'; }
    const canonical = utf8Encode(canonicalJson(manifest));
    requireThat(canonical.length === copy.length, 'manifest wire is not canonical');
    for (let i = 0; i < copy.length; i++) {
      requireThat(canonical[i] === copy[i], 'manifest wire is not canonical');
    }
    return {manifest: manifest, digest: expectedDigest};
  }

  function validateBinding(role, binding, allowUnavailable) {
    if (allowUnavailable && isRecord(binding) && binding.status === 'unavailable') {
      exactKeys(binding, ['status', 'reasonCode', 'evidenceId'], 'layers binding');
      checkedString(binding.reasonCode, false, 'layers reasonCode');
      checkedString(binding.evidenceId, false, 'layers evidenceId');
      return;
    }
    const keys = allowUnavailable ? ['status', 'className', 'fields', 'selector'] :
      ['className', 'fields', 'selector'];
    exactKeys(binding, keys, role + ' binding');
    if (allowUnavailable) requireThat(binding.status === 'bound', 'layers status must be bound or unavailable');
    checkedString(binding.className, false, role + ' className');
    requireThat(/^[A-Za-z_$][A-Za-z0-9_$]*(\.[A-Za-z_$][A-Za-z0-9_$]*)+$/.test(binding.className),
      role + ' className is invalid');
    const fieldTypes = ROLE_FIELDS[role];
    exactKeys(binding.fields, Object.keys(fieldTypes), role + ' fields');
    Object.keys(fieldTypes).forEach(function (outputName) {
      const descriptor = binding.fields[outputName];
      exactKeys(descriptor, ['field', 'type'], role + '.' + outputName + ' descriptor');
      requireThat(descriptor.type === fieldTypes[outputName], role + '.' + outputName + ' type mismatch');
      checkedString(descriptor.field, false, role + '.' + outputName + ' field');
      requireThat(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(descriptor.field) &&
        descriptor.field !== '__proto__' && descriptor.field !== 'constructor' &&
        descriptor.field !== 'prototype', role + '.' + outputName + ' field is unsafe');
    });
    requireThat(isRecord(binding.selector), role + ' selector must be an object');
    const selectorKeys = Object.keys(binding.selector);
    requireThat(selectorKeys.length > 0 && selectorKeys.length <= Object.keys(fieldTypes).length,
      role + ' selector is empty or oversized');
    requireThat(selectorKeys.indexOf('identity') >= 0, role + ' selector must include identity');
    selectorKeys.forEach(function (name) {
      requireThat(Object.prototype.hasOwnProperty.call(fieldTypes, name), role + ' selector field is unknown');
      checkedValue(binding.selector[name], fieldTypes[name], role + ' selector ' + name);
    });
  }

  function validateFileDescriptor(descriptor, label, mustBePresent, isOriginalPdf) {
    const keys = ['present', 'path', 'size', 'sha256', 'stat'];
    if (isOriginalPdf) keys.push('documentUri', 'uriResolution');
    exactKeys(descriptor, keys, label);
    requireThat(typeof descriptor.present === 'boolean', label + ' present must be boolean');
    if (mustBePresent) requireThat(descriptor.present === true, label + ' must be present');
    if (!descriptor.present) {
      requireThat(descriptor.path === null && descriptor.size === null &&
        descriptor.sha256 === null && descriptor.stat === null,
      label + ' absent descriptor must contain explicit nulls');
      return;
    }
    checkedString(descriptor.path, false, label + ' path');
    checkedDecimal(descriptor.size, label + ' size', false);
    checkedSha256(descriptor.sha256, label + ' SHA-256');
    exactKeys(descriptor.stat, ['device', 'inode', 'mode', 'uid', 'gid',
      'mtimeNs', 'ctimeNs'], label + ' stat');
    checkedDecimal(descriptor.stat.device, label + ' device', true);
    checkedDecimal(descriptor.stat.inode, label + ' inode', false);
    checkedDecimal(descriptor.stat.mode, label + ' mode', false);
    checkedInteger(descriptor.stat.uid, label + ' uid');
    checkedInteger(descriptor.stat.gid, label + ' gid');
    requireThat(descriptor.stat.uid >= 0 && descriptor.stat.gid >= 0,
      label + ' owner is invalid');
    checkedDecimal(descriptor.stat.mtimeNs, label + ' mtimeNs', true);
    checkedDecimal(descriptor.stat.ctimeNs, label + ' ctimeNs', true);
    if (!isOriginalPdf) return;
    checkedString(descriptor.documentUri, false, 'original PDF documentUri');
    requireThat(isRecord(descriptor.uriResolution),
      'original PDF URI resolution must be an object');
    if (descriptor.documentUri.indexOf('file://') === 0) {
      exactKeys(descriptor.uriResolution, ['authority', 'documentUri', 'resolvedPath',
        'evidenceSha256'], 'file URI resolution');
      requireThat(descriptor.uriResolution.authority ===
        'rtl-reader-file-uri-resolution-v1', 'file URI resolution authority mismatch');
      requireThat(descriptor.uriResolution.documentUri === descriptor.documentUri,
        'file URI resolution documentUri mismatch');
      requireThat(descriptor.uriResolution.resolvedPath === descriptor.path,
        'file URI resolution path mismatch');
      checkedSha256(descriptor.uriResolution.evidenceSha256,
        'file URI resolution evidence SHA-256');
      return;
    }
    requireThat(descriptor.documentUri.indexOf('content://') === 0,
      'original PDF documentUri scheme is unsupported');
    exactKeys(descriptor.uriResolution, ['authority', 'documentUri', 'resolvedPath',
      'providerPackage', 'providerApkSha256', 'evidenceSha256'],
    'content URI resolution');
    requireThat(descriptor.uriResolution.authority ===
      'rtl-reader-content-uri-resolution-v1', 'content URI resolution authority mismatch');
    requireThat(descriptor.uriResolution.documentUri === descriptor.documentUri,
      'content URI resolution documentUri mismatch');
    requireThat(descriptor.uriResolution.resolvedPath === descriptor.path,
      'content URI resolution path mismatch');
    checkedString(descriptor.uriResolution.providerPackage, false,
      'content URI provider package');
    checkedSha256(descriptor.uriResolution.providerApkSha256,
      'content URI provider APK SHA-256');
    checkedSha256(descriptor.uriResolution.evidenceSha256,
      'content URI resolution evidence SHA-256');
  }

  function validateManifest(manifest) {
    exactKeys(manifest, ['schemaVersion', 'authority', 'attachment', 'files',
      'coordinator', 'expected', 'bindings'], 'manifest');
    requireThat(manifest.schemaVersion === SCHEMA_VERSION, 'manifest schema mismatch');
    requireThat(manifest.authority === MANIFEST_AUTHORITY, 'manifest authority mismatch');

    const attachment = manifest.attachment;
    exactKeys(attachment, ['packageName', 'processName', 'pid', 'startTimeTicks',
      'apk', 'module'], 'attachment');
    requireThat(attachment.packageName === PACKAGE_NAME, 'wrong package identity');
    requireThat(attachment.processName === PROCESS_NAME, 'wrong process identity');
    checkedInteger(attachment.pid, 'attachment pid');
    requireThat(attachment.pid > 0, 'attachment pid must be positive');
    checkedString(attachment.startTimeTicks, false, 'process start time');
    requireThat(/^[1-9][0-9]{0,19}$/.test(attachment.startTimeTicks), 'process start time is invalid');

    exactKeys(attachment.apk, ['path', 'size', 'sha256'], 'APK identity');
    checkedString(attachment.apk.path, false, 'APK path');
    checkedInteger(attachment.apk.size, 'APK size');
    requireThat(attachment.apk.size > 0 && attachment.apk.size <= MAX_MODULE_BYTES,
      'APK size is invalid');
    checkedSha256(attachment.apk.sha256, 'APK SHA-256');

    exactKeys(attachment.module, ['name', 'path', 'size', 'sha256'], 'module identity');
    checkedString(attachment.module.name, false, 'module name');
    checkedString(attachment.module.path, false, 'module path');
    checkedInteger(attachment.module.size, 'module size');
    requireThat(attachment.module.size > 0 && attachment.module.size <= MAX_MODULE_BYTES,
      'module size is invalid');
    checkedSha256(attachment.module.sha256, 'module SHA-256');

    exactKeys(manifest.files, ['authority', 'verification', 'originalPdf', 'mark'],
      'file authority');
    requireThat(manifest.files.authority === FILE_AUTHORITY, 'file authority mismatch');
    requireThat(manifest.files.verification === 'external-before-and-after-exact',
      'file verification mode mismatch');
    validateFileDescriptor(manifest.files.originalPdf, 'original PDF', true, true);
    validateFileDescriptor(manifest.files.mark, 'mark file', false, false);

    exactKeys(manifest.coordinator, ['authority', 'observerSessionId', 'hardDeadlineMs',
      'maxJavaChooseWalks', 'detachOnDeadline', 'abortOnAnyError',
      'verifyTargetLivenessAfter'], 'coordinator');
    requireThat(manifest.coordinator.authority === COORDINATOR_AUTHORITY,
      'coordinator authority mismatch');
    checkedString(manifest.coordinator.observerSessionId, false, 'observer session ID');
    requireThat(/^[A-Za-z0-9._:-]{16,128}$/.test(manifest.coordinator.observerSessionId),
      'observer session ID is invalid');
    checkedInteger(manifest.coordinator.hardDeadlineMs, 'hard deadline');
    requireThat(manifest.coordinator.hardDeadlineMs >= 250 &&
      manifest.coordinator.hardDeadlineMs <= 10000, 'hard deadline is invalid');
    requireThat(manifest.coordinator.maxJavaChooseWalks === 10,
      'Java.choose walk budget must be exactly 10');
    requireThat(manifest.coordinator.detachOnDeadline === true &&
      manifest.coordinator.abortOnAnyError === true &&
      manifest.coordinator.verifyTargetLivenessAfter === true,
      'coordinator safety postconditions are required');

    const expected = manifest.expected;
    exactKeys(expected, ['taskId', 'displayId', 'sessionGeneration', 'uri',
      'currentPageIndex', 'pageCount'], 'expected');
    checkedInteger(expected.taskId, 'expected taskId');
    checkedInteger(expected.displayId, 'expected displayId');
    checkedInteger(expected.sessionGeneration, 'expected sessionGeneration');
    checkedString(expected.uri, false, 'expected URI');
    checkedInteger(expected.currentPageIndex, 'expected current page');
    checkedInteger(expected.pageCount, 'expected page count');
    requireThat(expected.taskId >= 0 && expected.displayId >= 0 && expected.displayId <= 1024,
      'expected task/display is invalid');
    requireThat(expected.sessionGeneration >= 0, 'expected generation is invalid');
    requireThat(expected.pageCount > 0 && expected.pageCount <= MAX_PAGE_COUNT,
      'expected page count is invalid');
    requireThat(expected.currentPageIndex >= 0 && expected.currentPageIndex < expected.pageCount,
      'expected current page is invalid');
    requireThat(manifest.files.originalPdf.documentUri === expected.uri,
      'original PDF descriptor documentUri does not match expected URI');

    exactKeys(manifest.bindings, ['activity', 'viewModel', 'pageInfo', 'presenter',
      'layers'], 'bindings');
    validateBinding('activity', manifest.bindings.activity, false);
    validateBinding('viewModel', manifest.bindings.viewModel, false);
    validateBinding('pageInfo', manifest.bindings.pageInfo, false);
    validateBinding('presenter', manifest.bindings.presenter, false);
    validateBinding('layers', manifest.bindings.layers, true);
  }

  function checkLocalDeadline() {
    requireThat(localDeadlineMs > 0 && Date.now() <= localDeadlineMs,
      'local observation deadline exceeded');
  }

  function readField(instance, descriptor, type, label) {
    const slot = instance[descriptor.field];
    requireThat(slot !== null && typeof slot === 'object' && ('value' in slot),
      label + ' field is unavailable');
    return checkedValue(slot.value, type, label);
  }

  function recordMatches(record, selector) {
    const keys = Object.keys(selector);
    for (let i = 0; i < keys.length; i++) {
      const name = keys[i];
      if (!Object.is(record[name], selector[name])) return false;
    }
    return true;
  }

  function selectOne(role, binding, callback) {
    let completed = false;
    let seen = 0;
    const matches = [];
    let pendingError = null;
    function finish(error, value) {
      if (completed) return;
      completed = true;
      callback(error, value);
    }
    try {
      checkLocalDeadline();
      chooseWalks += 1;
      requireThat(chooseWalks <= 10, 'Java.choose walk budget exceeded');
      Java.choose(binding.className, {
        onMatch: function (instance) {
          if (pendingError !== null) return 'stop';
          try {
            seen += 1;
            requireThat(seen <= MAX_CANDIDATES, role + ' candidate bound exceeded');
            const record = {};
            Object.keys(ROLE_FIELDS[role]).forEach(function (name) {
              record[name] = readField(instance, binding.fields[name],
                ROLE_FIELDS[role][name], role + '.' + name);
            });
            if (recordMatches(record, binding.selector)) {
              matches.push(record);
              requireThat(matches.length === 1, role + ' selection is ambiguous');
            }
          } catch (error) {
            pendingError = error;
            return 'stop';
          }
          return undefined;
        },
        onComplete: function () {
          try {
            checkLocalDeadline();
            if (pendingError !== null) throw pendingError;
            requireThat(matches.length === 1, role + ' selection is missing');
            finish(null, matches[0]);
          } catch (error) {
            finish(error, null);
          }
        }
      });
    } catch (error) {
      finish(error, null);
    }
  }

  function runtimeIdentity(manifest) {
    requireThat(Process.arch === 'arm64' && Process.pointerSize === 8,
      'wrong runtime architecture');
    requireThat(Process.id === manifest.attachment.pid, 'process PID changed');
    const module = Process.getModuleByName(manifest.attachment.module.name);
    requireThat(module !== null && typeof module === 'object', 'pinned module is missing');
    requireThat(module.name === manifest.attachment.module.name &&
      module.path === manifest.attachment.module.path &&
      module.size === manifest.attachment.module.size, 'mapped module identity changed');
    return {
      architecture: Process.arch,
      pointerSize: Process.pointerSize,
      pid: Process.id,
      module: {
        name: module.name, path: module.path, size: module.size,
        externallyVerifiedSha256: manifest.attachment.module.sha256
      }
    };
  }

  function sample(manifest, callback) {
    let runtime;
    try {
      runtime = runtimeIdentity(manifest);
    } catch (error) {
      callback(error, null);
      return;
    }
    const roles = ['activity', 'viewModel', 'pageInfo', 'presenter'];
    if (manifest.bindings.layers.status === 'bound') roles.push('layers');
    const values = {};
    function next(index) {
      if (index === roles.length) {
        if (manifest.bindings.layers.status === 'unavailable') {
          values.layers = {
            status: 'unavailable',
            reasonCode: manifest.bindings.layers.reasonCode,
            evidenceId: manifest.bindings.layers.evidenceId
          };
        }
        callback(null, {runtime: runtime, values: values});
        return;
      }
      const role = roles[index];
      selectOne(role, manifest.bindings[role], function (error, record) {
        if (error !== null) {
          callback(error, null);
          return;
        }
        values[role] = record;
        next(index + 1);
      });
    }
    next(0);
  }

  function matrixFrom(page, prefix) {
    return [page[prefix + 'A'], page[prefix + 'B'], page[prefix + 'C'],
      page[prefix + 'D'], page[prefix + 'E'], page[prefix + 'F']];
  }

  function verifyInverse(forward, inverse) {
    const determinant = forward[0] * forward[3] - forward[1] * forward[2];
    const linearNorm = Math.max(Math.abs(forward[0]), Math.abs(forward[1]),
      Math.abs(forward[2]), Math.abs(forward[3]));
    requireThat(linearNorm > 0 && Math.abs(determinant) >
      Number.EPSILON * linearNorm * linearNorm * 64, 'CTM is singular or unstable');
    const expected = [
      forward[3] / determinant,
      -forward[1] / determinant,
      -forward[2] / determinant,
      forward[0] / determinant,
      (forward[2] * forward[5] - forward[3] * forward[4]) / determinant,
      (forward[1] * forward[4] - forward[0] * forward[5]) / determinant
    ];
    expected.forEach(function (value) {
      requireThat(Number.isFinite(value) && Math.abs(value) <= MAX_MATRIX_ABS,
        'derived CTM inverse exceeds numeric bound');
    });
    const inverseLinearNorm = Math.max(Math.abs(inverse[0]), Math.abs(inverse[1]),
      Math.abs(inverse[2]), Math.abs(inverse[3]));
    requireThat(linearNorm * inverseLinearNorm <= 1000000000000,
      'CTM linear condition bound exceeded');
    for (let i = 0; i < 4; i++) {
      const scale = Math.max(1, Math.abs(expected[i]), Math.abs(inverse[i]));
      requireThat(Math.abs(inverse[i] - expected[i]) <=
        Number.EPSILON * 256 * scale, 'CTM linear inverse mismatch');
    }
    for (let i = 4; i < 6; i++) {
      const scale = Math.max(1, Math.abs(expected[i]), Math.abs(inverse[i]));
      requireThat(Math.abs(inverse[i] - expected[i]) <=
        Number.EPSILON * 512 * scale, 'CTM translation inverse mismatch');
    }
  }

  function validateSample(manifest, snapshot) {
    const activity = snapshot.values.activity;
    const viewModel = snapshot.values.viewModel;
    const pageInfo = snapshot.values.pageInfo;
    const presenter = snapshot.values.presenter;
    const expected = manifest.expected;
    requireThat(activity.taskId === expected.taskId, 'wrong task');
    requireThat(activity.displayId === expected.displayId, 'wrong display');
    requireThat(activity.sessionGeneration === expected.sessionGeneration, 'wrong session generation');
    requireThat(viewModel.uri === expected.uri, 'wrong document URI');
    requireThat(viewModel.currentPageIndex === expected.currentPageIndex, 'wrong current page');
    requireThat(viewModel.pageCount === expected.pageCount, 'wrong page count');
    requireThat(pageInfo.pageIndex === viewModel.currentPageIndex, 'PageInfo page mismatch');
    requireThat(presenter.currentPageIndex === viewModel.currentPageIndex,
      'presenter page mismatch');
    requireThat(viewModel.pageCount > 0 && viewModel.pageCount <= MAX_PAGE_COUNT &&
      viewModel.currentPageIndex >= 0 && viewModel.currentPageIndex < viewModel.pageCount,
      'observed page range is invalid');
    requireThat(pageInfo.width > 0 && pageInfo.height > 0 &&
      pageInfo.width <= MAX_DIMENSION && pageInfo.height <= MAX_DIMENSION,
      'PageInfo dimensions are invalid');
    requireThat(pageInfo.cropRight > pageInfo.cropLeft &&
      pageInfo.cropBottom > pageInfo.cropTop, 'crop rectangle is invalid');
    requireThat(pageInfo.bitmapWidth > 0 && pageInfo.bitmapHeight > 0 &&
      pageInfo.bitmapWidth <= MAX_DIMENSION && pageInfo.bitmapHeight <= MAX_DIMENSION,
      'bitmap dimensions are invalid');
    requireThat(presenter.rotation >= -360 && presenter.rotation <= 360,
      'presenter rotation is outside the bounded raw-code range');
    if (manifest.files.mark.present) {
      requireThat(presenter.markPath === manifest.files.mark.path,
        'presenter mark path does not match file authority');
    } else {
      requireThat(presenter.markPath === null,
        'presenter mark path exists without file authority');
    }
    verifyInverse(matrixFrom(pageInfo, 'ctm'), matrixFrom(pageInfo, 'inverse'));
  }

  function binary64Hex(value) {
    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);
    view.setFloat64(0, value, false);
    let result = '0x';
    for (let i = 0; i < 8; i++) result += view.getUint8(i).toString(16).padStart(2, '0');
    return result;
  }

  function encodedFinite(value) {
    return {binary64: binary64Hex(value)};
  }

  function encodePageInfo(page) {
    return {
      identity: page.identity,
      pageIndex: page.pageIndex,
      size: [encodedFinite(page.width), encodedFinite(page.height)],
      crop: [encodedFinite(page.cropLeft), encodedFinite(page.cropTop),
        encodedFinite(page.cropRight), encodedFinite(page.cropBottom)],
      ctm: matrixFrom(page, 'ctm').map(encodedFinite),
      inverse: matrixFrom(page, 'inverse').map(encodedFinite),
      offset: [encodedFinite(page.offsetX), encodedFinite(page.offsetY)],
      bitmapDimensions: [page.bitmapWidth, page.bitmapHeight]
    };
  }

  function stableEncoding(snapshot) {
    const values = snapshot.values;
    return JSON.stringify({
      runtime: snapshot.runtime,
      activity: values.activity,
      viewModel: values.viewModel,
      pageInfo: encodePageInfo(values.pageInfo),
      presenter: values.presenter,
      layers: values.layers
    });
  }

  function emitFailure(error) {
    if (terminalSent) return;
    terminalSent = true;
    let message = typeof error === 'string' ? error : 'non-primitive observation failure';
    if (message.length > MAX_ERROR_CHARS) message = message.slice(0, MAX_ERROR_CHARS);
    send({event: 'native_page_snapshot_error', schemaVersion: SCHEMA_VERSION,
      code: 'SNAPSHOT_REJECTED', message: message});
    send({event: 'native_page_snapshot_complete', success: false});
  }

  function emitSuccess(manifest, manifestDigest, snapshot) {
    if (terminalSent) return;
    terminalSent = true;
    const values = snapshot.values;
    send({
      event: 'native_page_snapshot',
      schemaVersion: SCHEMA_VERSION,
      authority: RECORD_AUTHORITY,
      manifestSha256: manifestDigest,
      observationOnly: true,
      atomic: false,
      attachment: {
        packageName: manifest.attachment.packageName,
        processName: manifest.attachment.processName,
        pid: snapshot.runtime.pid,
        processStartTimeTicks: manifest.attachment.startTimeTicks,
        architecture: snapshot.runtime.architecture,
        pointerSize: snapshot.runtime.pointerSize,
        apk: {
          path: manifest.attachment.apk.path,
          size: manifest.attachment.apk.size,
          externallyVerifiedSha256: manifest.attachment.apk.sha256
        },
        module: snapshot.runtime.module
      },
      fileAuthority: manifest.files,
      coordinator: {
        authority: manifest.coordinator.authority,
        observerSessionId: manifest.coordinator.observerSessionId,
        hardDeadlineMs: manifest.coordinator.hardDeadlineMs,
        javaChooseWalks: chooseWalks,
        externalDetachOnDeadline: true,
        externalTargetLivenessPostconditionRequired: true
      },
      session: {
        activityIdentity: values.activity.identity,
        taskId: values.activity.taskId,
        displayId: values.activity.displayId,
        generation: values.activity.sessionGeneration
      },
      document: {
        viewModelIdentity: values.viewModel.identity,
        uri: values.viewModel.uri,
        currentPageIndex: values.viewModel.currentPageIndex,
        pageCount: values.viewModel.pageCount,
        pageInfo: encodePageInfo(values.pageInfo)
      },
      presenter: values.presenter,
      layers: values.layers,
      drawPathPrerequisite: {
        status: 'external-prerequisite',
        authority: 'rtl-reader-drawpath-scalar-snapshot-v1',
        required: true,
        requiredFields: ['pid', 'startTimeTicks', 'screenWidth', 'screenHeight',
          'documentImageWidth', 'documentImageHeight'],
        note: 'Capture independently from the pinned DrawPath process; no offsets are inferred here.'
      }
    });
    send({event: 'native_page_snapshot_complete', success: true});
  }

  try {
    const parsedWire = parseManifestWire();
    const manifest = parsedWire.manifest;
    validateManifest(manifest);
    chooseWalks = 0;
    const startedAt = Date.now();
    requireThat(Number.isFinite(startedAt), 'monotonic coordinator clock is unavailable');
    localDeadlineMs = startedAt + manifest.coordinator.hardDeadlineMs;
    Java.perform(function () {
      sample(manifest, function (firstError, first) {
        if (firstError !== null) {
          emitFailure(firstError);
          return;
        }
        try { validateSample(manifest, first); } catch (error) { emitFailure(error); return; }
        sample(manifest, function (secondError, second) {
          if (secondError !== null) {
            emitFailure(secondError);
            return;
          }
          try {
            validateSample(manifest, second);
            requireThat(stableEncoding(first) === stableEncoding(second),
              'snapshot changed during observation');
            const expectedWalks = manifest.bindings.layers.status === 'bound' ? 10 : 8;
            requireThat(chooseWalks === expectedWalks, 'Java.choose walk count mismatch');
            checkLocalDeadline();
            emitSuccess(manifest, parsedWire.digest, first);
          } catch (error) {
            emitFailure(error);
          }
        });
      });
    });
  } catch (error) {
    emitFailure(error);
  }
}());
