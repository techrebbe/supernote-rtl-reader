'use strict';

// Read-only, pinned-firmware graph observer. This script performs exactly one
// heap walk, retains one live DocumentActivity, reads only hard-coded direct
// fields, and uses JNI IsSameObject solely for retained-reference stability.
(function () {
  const SCHEMA_VERSION = 2;
  const MANIFEST_AUTHORITY = 'rtl-reader-native-page-graph-manifest-v2';
  const RECORD_AUTHORITY = 'rtl-reader-native-page-graph-snapshot-v2';
  const COORDINATOR_AUTHORITY = 'rtl-reader-native-page-graph-coordinator-v2';
  const EXTERNAL_SESSION_AUTHORITY = 'rtl-reader-native-page-external-session-v2';
  const CALIBRATION_AUTHORITY = 'rtl-reader-native-page-calibration-raw-v1';
  const FILE_AUTHORITY = 'rtl-reader-native-page-file-authority-v1';
  const PACKAGE_NAME = 'com.supernote.document';
  const PROCESS_NAME = 'Document';
  const AUTHORIZED_SERIAL = 'SN078C10015092';
  const FIRMWARE_FINGERPRINT =
    'Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys';
  const APK_SIZE = 138486560;
  const APK_SHA256 = 'f008c86ddc42008c36b431410cbc3b29057b4aad9bc26c3577ee13b39b230482';
  const FRAMEWORK_SIZE = 30186065;
  const FRAMEWORK_SHA256 =
    'c3a525a7ef16363a93412182cce693f46dfa1395a570e9620da0d4e27a59631d';
  const MAX_MANIFEST_BYTES = 131072;
  const MAX_OUTPUT_BYTES = 2097152;
  const MAX_STRING_BYTES = 4096;
  const MAX_MODULE_BYTES = 536870912;
  const MAX_PAGE_COUNT = 10000000;
  const MAX_DIMENSION = 10000000;
  const MAX_NUMERIC_ABS = 1000000000000;
  const MAX_HEAP_CANDIDATES = 64;
  const MIN_DEADLINE_MS = 250;
  const MAX_DEADLINE_MS = 10000;

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
    matrix: 'com.artifex.mupdf.fitz.Matrix',
    rect: 'android.graphics.RectF',
    bitmap: 'android.graphics.Bitmap',
    note: 'com.example.libsupernote.SuperNoteNote',
    client: 'com.supernote.document.handwrite.HandWriteClient',
    uri: 'android.net.Uri$StringUri',
    attachInfo: 'android.view.View$AttachInfo'
  });

  const FIELD = Object.freeze({
    activityViewModel: 'documentViewModel',
    activityPresenter: 'handWritePresenter',
    activityHandWriteView: 'handWriteView',
    activityImage: 'mImage',
    activityDigestImage: 'digestImage',
    activityContentView: 'mContentView',
    activityDocumentLayout: 'documentViewLayout',
    resumed: 'mResumed', finished: 'mFinished', destroyed: 'mDestroyed',
    currentPage: 'currentPage', pageCount: 'pageCount', pageInfo: 'pageInfo',
    uri: 'uri', uriString: 'uriString',
    scaleRect: 'scaleRect', portraitScaleRect: 'portraitScaleRect',
    landscapeScaleRect: 'landscapeScaleRect', showRect: 'showRect',
    trimmingRect: 'trimmingRect', landscapeTrimmingRect: 'landscapeTrimmingRect',
    page: 'page', ctm: 'ctm', revertCtm: 'revertCtm',
    originBitmap: 'originBitmap', displayBitmap: 'displayBitmap',
    digestBitmap: 'digestBitmap', offsetX: 'offsetX', offsetY: 'offsetY',
    scale: 'scale',
    presenterMarkPath: 'markPath', presenterRotation: 'screenRotation',
    presenterBitmap: 'bitmap', presenterNote: 'superNoteNote',
    presenterClient: 'handWriteClient',
    binder: 'iBinder', sfBinder: 'mSFBinder', notePointer: 'pointer',
    matrixA: 'a', matrixB: 'b', matrixC: 'c', matrixD: 'd',
    matrixE: 'e', matrixF: 'f',
    rectLeft: 'left', rectTop: 'top', rectRight: 'right', rectBottom: 'bottom',
    bitmapWidth: 'mWidth', bitmapHeight: 'mHeight', bitmapPointer: 'mNativePtr',
    viewLeft: 'mLeft', viewTop: 'mTop', viewRight: 'mRight',
    viewBottom: 'mBottom', viewScrollX: 'mScrollX', viewScrollY: 'mScrollY',
    viewAttachCount: 'mWindowAttachCount', viewAttachInfo: 'mAttachInfo'
  });

  let terminalSent = false;
  let heapWalks = 0;
  let manifest = null;
  let manifestDigest = null;

  function reject() { throw 'GRAPH_SNAPSHOT_REJECTED'; }
  function requireThat(condition) { if (!condition) reject(); }
  function isRecord(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }
  function exactKeys(value, expected) {
    requireThat(isRecord(value));
    const actual = Object.keys(value).sort();
    const wanted = expected.slice().sort();
    requireThat(actual.length === wanted.length);
    for (let index = 0; index < wanted.length; index++) {
      requireThat(actual[index] === wanted[index]);
    }
  }
  function checkedString(value, nullable) {
    if (nullable && value === null) return null;
    requireThat(typeof value === 'string' && value.length > 0);
    let bytes = 0;
    for (let index = 0; index < value.length; index++) {
      let point = value.charCodeAt(index);
      requireThat(point !== 0);
      if (point <= 0x7f) bytes += 1;
      else if (point <= 0x7ff) bytes += 2;
      else if (point >= 0xd800 && point <= 0xdbff) {
        requireThat(index + 1 < value.length);
        const low = value.charCodeAt(++index);
        requireThat(low >= 0xdc00 && low <= 0xdfff);
        bytes += 4;
      } else {
        requireThat(point < 0xdc00 || point > 0xdfff);
        bytes += 3;
      }
      requireThat(bytes <= MAX_STRING_BYTES);
    }
    return value;
  }
  function checkedInteger(value, minimum, maximum) {
    requireThat(typeof value === 'number' && Number.isSafeInteger(value) &&
      !Object.is(value, -0) && value >= minimum && value <= maximum);
    return value;
  }
  function checkedSha256(value) {
    requireThat(typeof value === 'string' && /^[0-9a-f]{64}$/.test(value));
    return value;
  }
  function checkedDecimal(value, allowZero, digits) {
    checkedString(value, false);
    const expression = allowZero ? /^(0|[1-9][0-9]*)$/ : /^[1-9][0-9]*$/;
    requireThat(expression.test(value) && value.length <= digits);
    return value;
  }
  function utf8Encode(value) {
    const result = [];
    for (let index = 0; index < value.length; index++) {
      let point = value.charCodeAt(index);
      requireThat(point !== 0);
      if (point >= 0xd800 && point <= 0xdbff) {
        requireThat(index + 1 < value.length);
        const low = value.charCodeAt(++index);
        requireThat(low >= 0xdc00 && low <= 0xdfff);
        point = 0x10000 + ((point - 0xd800) << 10) + (low - 0xdc00);
      } else {
        requireThat(point < 0xdc00 || point > 0xdfff);
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
    for (let index = 0; index < bytes.length;) {
      const first = bytes[index++];
      let point;
      if (first <= 0x7f) point = first;
      else if (first >= 0xc2 && first <= 0xdf) {
        requireThat(index < bytes.length);
        const second = bytes[index++];
        requireThat((second & 0xc0) === 0x80);
        point = ((first & 0x1f) << 6) | (second & 0x3f);
      } else if (first >= 0xe0 && first <= 0xef) {
        requireThat(index + 1 < bytes.length);
        const second = bytes[index++], third = bytes[index++];
        requireThat((second & 0xc0) === 0x80 && (third & 0xc0) === 0x80);
        requireThat(!(first === 0xe0 && second < 0xa0) &&
          !(first === 0xed && second >= 0xa0));
        point = ((first & 0x0f) << 12) | ((second & 0x3f) << 6) | (third & 0x3f);
      } else if (first >= 0xf0 && first <= 0xf4) {
        requireThat(index + 2 < bytes.length);
        const second = bytes[index++], third = bytes[index++], fourth = bytes[index++];
        requireThat((second & 0xc0) === 0x80 && (third & 0xc0) === 0x80 &&
          (fourth & 0xc0) === 0x80);
        requireThat(!(first === 0xf0 && second < 0x90) &&
          !(first === 0xf4 && second >= 0x90));
        point = ((first & 7) << 18) | ((second & 0x3f) << 12) |
          ((third & 0x3f) << 6) | (fourth & 0x3f);
      } else reject();
      requireThat(point !== 0);
      if (point <= 0xffff) result += String.fromCharCode(point);
      else {
        point -= 0x10000;
        result += String.fromCharCode(0xd800 | (point >>> 10),
          0xdc00 | (point & 0x3ff));
      }
    }
    return result;
  }
  function canonicalJson(value) {
    if (value === null) return 'null';
    if (typeof value === 'boolean') return value ? 'true' : 'false';
    if (typeof value === 'string') {
      checkedString(value, true);
      return JSON.stringify(value);
    }
    if (typeof value === 'number') {
      checkedInteger(value, -9007199254740991, 9007199254740991);
      return String(value);
    }
    if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
    requireThat(isRecord(value));
    const keys = Object.keys(value).sort();
    return '{' + keys.map(function (key) {
      checkedString(key, false);
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
    const rotate = function (value, count) {
      return (value >>> count) | (value << (32 - count));
    };
    for (let offset = 0; offset < data.length; offset += 64) {
      const words = new Array(64);
      for (let index = 0; index < 16; index++) {
        const at = offset + index * 4;
        words[index] = ((data[at] << 24) | (data[at + 1] << 16) |
          (data[at + 2] << 8) | data[at + 3]) >>> 0;
      }
      for (let index = 16; index < 64; index++) {
        const s0 = rotate(words[index - 15], 7) ^ rotate(words[index - 15], 18) ^
          (words[index - 15] >>> 3);
        const s1 = rotate(words[index - 2], 17) ^ rotate(words[index - 2], 19) ^
          (words[index - 2] >>> 10);
        words[index] = (words[index - 16] + s0 + words[index - 7] + s1) >>> 0;
      }
      let a = state[0], b = state[1], c = state[2], d = state[3];
      let e = state[4], f = state[5], g = state[6], h = state[7];
      for (let index = 0; index < 64; index++) {
        const upper1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25);
        const choice = (e & f) ^ (~e & g);
        const first = (h + upper1 + choice + constants[index] + words[index]) >>> 0;
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
    return state.map(function (word) {
      return word.toString(16).padStart(8, '0');
    }).join('');
  }

  function parseManifestWire() {
    const supplied = globalThis.NATIVE_PAGE_GRAPH_MANIFEST_UTF8;
    const expectedDigest = globalThis.NATIVE_PAGE_GRAPH_MANIFEST_SHA256;
    requireThat(Array.isArray(supplied) && supplied.length > 0 &&
      supplied.length <= MAX_MANIFEST_BYTES);
    const bytes = [];
    for (let index = 0; index < supplied.length; index++) {
      checkedInteger(supplied[index], 0, 255);
      bytes.push(supplied[index]);
    }
    checkedSha256(expectedDigest);
    requireThat(sha256(bytes) === expectedDigest);
    let value;
    try { value = JSON.parse(utf8Decode(bytes)); } catch (_) { reject(); }
    const canonical = utf8Encode(canonicalJson(value));
    requireThat(canonical.length === bytes.length);
    for (let index = 0; index < bytes.length; index++) {
      requireThat(canonical[index] === bytes[index]);
    }
    return {value: value, digest: expectedDigest};
  }

  function validateStat(value) {
    exactKeys(value, ['device', 'inode', 'mode', 'uid', 'gid', 'mtimeNs', 'ctimeNs']);
    checkedDecimal(value.device, true, 40);
    checkedDecimal(value.inode, false, 40);
    checkedDecimal(value.mode, false, 40);
    checkedInteger(value.uid, 0, 2147483647);
    checkedInteger(value.gid, 0, 2147483647);
    checkedDecimal(value.mtimeNs, true, 40);
    checkedDecimal(value.ctimeNs, true, 40);
  }
  function validateFile(value, original, required) {
    const keys = ['present', 'path', 'size', 'sha256', 'stat'];
    if (original) keys.push('documentUri', 'uriResolution');
    exactKeys(value, keys);
    requireThat(typeof value.present === 'boolean');
    if (required) requireThat(value.present === true);
    if (!value.present) {
      requireThat(value.path === null && value.size === null && value.sha256 === null &&
        value.stat === null);
      return;
    }
    checkedString(value.path, false);
    checkedDecimal(value.size, false, 40);
    checkedSha256(value.sha256);
    validateStat(value.stat);
    if (!original) return;
    checkedString(value.documentUri, false);
    if (value.documentUri.indexOf('file://') === 0) {
      exactKeys(value.uriResolution,
        ['authority', 'documentUri', 'resolvedPath', 'evidenceSha256']);
      requireThat(value.uriResolution.authority === 'rtl-reader-file-uri-resolution-v1' &&
        value.uriResolution.documentUri === value.documentUri &&
        value.uriResolution.resolvedPath === value.path);
      checkedSha256(value.uriResolution.evidenceSha256);
      return;
    }
    requireThat(value.documentUri.indexOf('content://') === 0);
    exactKeys(value.uriResolution, ['authority', 'documentUri', 'resolvedPath',
      'providerPackage', 'providerApkSha256', 'evidenceSha256']);
    requireThat(value.uriResolution.authority === 'rtl-reader-content-uri-resolution-v1' &&
      value.uriResolution.documentUri === value.documentUri &&
      value.uriResolution.resolvedPath === value.path);
    checkedString(value.uriResolution.providerPackage, false);
    checkedSha256(value.uriResolution.providerApkSha256);
    checkedSha256(value.uriResolution.evidenceSha256);
  }
  function validateBinaryFile(value, includeName) {
    exactKeys(value, includeName ? ['name', 'path', 'size', 'sha256'] :
      ['path', 'size', 'sha256']);
    if (includeName) checkedString(value.name, false);
    checkedString(value.path, false);
    checkedInteger(value.size, 1, MAX_MODULE_BYTES);
    checkedSha256(value.sha256);
  }
  function validateManifest(value) {
    exactKeys(value, ['schemaVersion', 'authority', 'attachment', 'externalSession',
      'files', 'coordinator', 'expected']);
    requireThat(value.schemaVersion === SCHEMA_VERSION &&
      value.authority === MANIFEST_AUTHORITY);
    const attachment = value.attachment;
    exactKeys(attachment, ['packageName', 'processName', 'pid', 'startTimeTicks',
      'firmwareFingerprint', 'apk', 'framework', 'module', 'observerSha256']);
    requireThat(attachment.packageName === PACKAGE_NAME &&
      attachment.processName === PROCESS_NAME &&
      attachment.firmwareFingerprint === FIRMWARE_FINGERPRINT);
    checkedInteger(attachment.pid, 1, 2147483647);
    checkedDecimal(attachment.startTimeTicks, false, 20);
    validateBinaryFile(attachment.apk, false);
    validateBinaryFile(attachment.framework, false);
    validateBinaryFile(attachment.module, true);
    requireThat(attachment.apk.size === APK_SIZE && attachment.apk.sha256 === APK_SHA256 &&
      attachment.framework.size === FRAMEWORK_SIZE &&
      attachment.framework.sha256 === FRAMEWORK_SHA256);
    checkedSha256(attachment.observerSha256);

    const external = value.externalSession;
    exactKeys(external, ['authority', 'authorizedSerial', 'taskId', 'displayId',
      'hostSessionId', 'displayGeneration']);
    requireThat(external.authority === EXTERNAL_SESSION_AUTHORITY &&
      external.authorizedSerial === AUTHORIZED_SERIAL);
    checkedInteger(external.taskId, 0, 2147483647);
    checkedInteger(external.displayId, 0, 1024);
    checkedString(external.hostSessionId, false);
    requireThat(/^[A-Za-z0-9._:-]{16,128}$/.test(external.hostSessionId));
    checkedInteger(external.displayGeneration, 0, 9007199254740991);

    exactKeys(value.files, ['authority', 'verification', 'originalPdf', 'mark']);
    requireThat(value.files.authority === FILE_AUTHORITY &&
      value.files.verification === 'external-before-and-after-exact');
    validateFile(value.files.originalPdf, true, true);
    validateFile(value.files.mark, false, false);

    const coordinator = value.coordinator;
    exactKeys(coordinator, ['authority', 'observerSessionId',
      'absoluteMonotonicDeadlineNs', 'hardDeadlineMs', 'maxJavaChooseWalks',
      'retainedRootSamples', 'detachOnDeadline', 'abortOnAnyError',
      'verifyTargetLivenessAfter', 'noRetry']);
    requireThat(coordinator.authority === COORDINATOR_AUTHORITY);
    checkedString(coordinator.observerSessionId, false);
    requireThat(/^[A-Za-z0-9._:-]{16,128}$/.test(coordinator.observerSessionId));
    checkedDecimal(coordinator.absoluteMonotonicDeadlineNs, false, 30);
    checkedInteger(coordinator.hardDeadlineMs, MIN_DEADLINE_MS, MAX_DEADLINE_MS);
    requireThat(coordinator.maxJavaChooseWalks === 1 &&
      coordinator.retainedRootSamples === 2 && coordinator.detachOnDeadline === true &&
      coordinator.abortOnAnyError === true &&
      coordinator.verifyTargetLivenessAfter === true && coordinator.noRetry === true);

    exactKeys(value.expected, ['documentUri', 'calibrationProfile']);
    checkedString(value.expected.documentUri, false);
    exactKeys(value.expected.calibrationProfile,
      ['authority', 'status', 'pageIndexSemantics', 'matrixSemantics']);
    requireThat(value.expected.calibrationProfile.authority === CALIBRATION_AUTHORITY &&
      value.expected.calibrationProfile.status === 'calibration-only' &&
      value.expected.calibrationProfile.pageIndexSemantics === 'independent-raw' &&
      value.expected.calibrationProfile.matrixSemantics === 'independent-raw');
    requireThat(value.files.originalPdf.documentUri === value.expected.documentUri);
  }

  function direct(parent, field) {
    requireThat(parent !== null && typeof parent === 'object');
    const slot = parent[field];
    requireThat(slot !== null && typeof slot === 'object' && ('value' in slot));
    return slot.value;
  }
  function exactClass(value, expected) {
    requireThat(value !== null && typeof value === 'object' &&
      value.$className === expected && value.$h !== null &&
      typeof value.$h === 'object');
  }
  function retained(value, state) {
    let copy = null;
    try {
      copy = Java.retain(value);
      requireThat(copy !== null && typeof copy === 'object' && copy.$h !== null &&
        typeof copy.$h === 'object' && typeof copy.$dispose === 'function');
      state.retained.push(copy);
      return copy;
    } catch (_) {
      if (copy !== null && typeof copy === 'object' &&
          typeof copy.$dispose === 'function') {
        try { copy.$dispose(); } catch (_) { /* cleanup failure remains rejection */ }
      }
      reject();
    }
  }
  function sameObject(left, right, state) {
    requireThat(left !== null && right !== null && left.$h !== null && right.$h !== null);
    state.sameObjectCalls++;
    requireThat(state.env.isSameObject(left.$h, right.$h) === true);
  }
  function reference(parent, field, expectedClass, nullable, state, prior, second) {
    const value = direct(parent, field);
    if (value === null) {
      requireThat(nullable);
      if (second) requireThat(prior === null);
      return null;
    }
    if (expectedClass !== null) exactClass(value, expectedClass);
    else requireThat(typeof value === 'object' && value.$h !== null &&
      typeof value.$h === 'object');
    if (second) {
      requireThat(prior !== null);
      sameObject(prior, value, state);
      return value;
    }
    return retained(value, state);
  }
  function readBoolean(parent, field) {
    const value = direct(parent, field);
    requireThat(typeof value === 'boolean');
    return value;
  }
  function readInt(parent, field, minimum, maximum) {
    return checkedInteger(direct(parent, field), minimum, maximum);
  }
  function finite(value) {
    requireThat(typeof value === 'number' && Number.isFinite(value) &&
      Math.abs(value) <= MAX_NUMERIC_ABS);
    return value;
  }
  function binary64(value) {
    finite(value);
    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);
    view.setFloat64(0, value, false);
    let output = '0x';
    for (let index = 0; index < 8; index++) {
      output += view.getUint8(index).toString(16).padStart(2, '0');
    }
    return {binary64: output};
  }
  function readFloat(parent, field) { return binary64(finite(direct(parent, field))); }
  function longHex(value) {
    let text;
    if (typeof value === 'number') {
      checkedInteger(value, 0, 9007199254740991);
      text = value.toString(16);
    } else if (typeof value === 'bigint') {
      requireThat(value >= 0n && value <= 0xffffffffffffffffn);
      text = value.toString(16);
    } else {
      requireThat(value !== null && typeof value === 'object' &&
        typeof value.toString === 'function');
      text = value.toString(16);
    }
    requireThat(typeof text === 'string' && /^[0-9a-f]{1,16}$/.test(text));
    return '0x' + text.padStart(16, '0');
  }
  function pointerRecord(value) {
    const wire = longHex(value);
    const present = wire !== '0x0000000000000000';
    return {present: present, value: present ? wire : null};
  }
  function rectRecord(rect) {
    const raw = [direct(rect, FIELD.rectLeft), direct(rect, FIELD.rectTop),
      direct(rect, FIELD.rectRight), direct(rect, FIELD.rectBottom)].map(finite);
    requireThat(raw[2] > raw[0] && raw[3] > raw[1]);
    return raw.map(binary64);
  }
  function matrixRecord(matrix) {
    const names = [FIELD.matrixA, FIELD.matrixB, FIELD.matrixC,
      FIELD.matrixD, FIELD.matrixE, FIELD.matrixF];
    const raw = names.map(function (name) { return finite(direct(matrix, name)); });
    const determinant = raw[0] * raw[3] - raw[1] * raw[2];
    const norm = Math.max(Math.abs(raw[0]), Math.abs(raw[1]),
      Math.abs(raw[2]), Math.abs(raw[3]));
    requireThat(norm > 0 && Math.abs(determinant) >
      Number.EPSILON * norm * norm * 64 &&
      (norm * norm) / Math.abs(determinant) <= MAX_NUMERIC_ABS);
    return raw.map(binary64);
  }
  function bitmapRecord(bitmap) {
    if (bitmap === null) return {present: false, width: null, height: null,
      nativePointer: null};
    const width = readInt(bitmap, FIELD.bitmapWidth, 1, MAX_DIMENSION);
    const height = readInt(bitmap, FIELD.bitmapHeight, 1, MAX_DIMENSION);
    return {present: true, width: width, height: height,
      nativePointer: pointerRecord(direct(bitmap, FIELD.bitmapPointer))};
  }
  function viewRecord(view, className, attachInfo) {
    const left = readInt(view, FIELD.viewLeft, -2147483648, 2147483647);
    const top = readInt(view, FIELD.viewTop, -2147483648, 2147483647);
    const right = readInt(view, FIELD.viewRight, -2147483648, 2147483647);
    const bottom = readInt(view, FIELD.viewBottom, -2147483648, 2147483647);
    requireThat(right > left && bottom > top);
    return {className: className, bounds: [left, top, right, bottom],
      scroll: [readInt(view, FIELD.viewScrollX, -2147483648, 2147483647),
        readInt(view, FIELD.viewScrollY, -2147483648, 2147483647)],
      windowAttachCount: readInt(view, FIELD.viewAttachCount, 0, 2147483647),
      attached: attachInfo !== null, referenceStable: true, attachInfoStable: true};
  }
  function uriString(uri) {
    exactClass(uri, CLASS.uri);
    return checkedString(direct(uri, FIELD.uriString), false);
  }

  function captureSample(root, state, prior, second) {
    exactClass(root, CLASS.activity);
    const lifecycle = {
      resumed: readBoolean(root, FIELD.resumed),
      finished: readBoolean(root, FIELD.finished),
      destroyed: readBoolean(root, FIELD.destroyed)
    };
    requireThat(lifecycle.resumed === true && lifecycle.finished === false &&
      lifecycle.destroyed === false);
    const previous = prior === null ? {} : prior.objects;
    const objects = {};
    function edge(name, parent, field, expectedClass, nullable) {
      const value = reference(parent, field, expectedClass, nullable, state,
        second ? previous[name] : undefined, second);
      objects[name] = second ? previous[name] : value;
      return value;
    }

    const viewModel = edge('viewModel', root, FIELD.activityViewModel,
      CLASS.viewModel, false);
    const presenter = edge('presenter', root, FIELD.activityPresenter,
      CLASS.presenter, false);
    const handWriteView = edge('handWriteView', root, FIELD.activityHandWriteView,
      CLASS.handWriteView, false);
    const image = edge('image', root, FIELD.activityImage, CLASS.imageView, false);
    const digestImage = edge('digestImage', root, FIELD.activityDigestImage,
      CLASS.digestImageView, false);
    const contentView = edge('contentView', root, FIELD.activityContentView,
      CLASS.contentView, false);
    const documentLayout = edge('documentLayout', root, FIELD.activityDocumentLayout,
      CLASS.documentLayout, false);

    const pageInfo = edge('pageInfo', viewModel, FIELD.pageInfo, CLASS.pageInfo, false);
    const viewModelUri = edge('viewModelUri', viewModel, FIELD.uri, CLASS.uri, false);
    const scaleRect = edge('scaleRect', viewModel, FIELD.scaleRect, CLASS.rect, false);
    const portraitScaleRect = edge('portraitScaleRect', viewModel,
      FIELD.portraitScaleRect, CLASS.rect, false);
    const landscapeScaleRect = edge('landscapeScaleRect', viewModel,
      FIELD.landscapeScaleRect, CLASS.rect, false);
    const showRect = edge('showRect', viewModel, FIELD.showRect, CLASS.rect, false);
    const viewModelTrimmingRect = edge('viewModelTrimmingRect', viewModel,
      FIELD.trimmingRect, CLASS.rect, false);
    const landscapeTrimmingRect = edge('landscapeTrimmingRect', viewModel,
      FIELD.landscapeTrimmingRect, CLASS.rect, false);

    const ctm = edge('ctm', pageInfo, FIELD.ctm, CLASS.matrix, false);
    const revertCtm = edge('revertCtm', pageInfo, FIELD.revertCtm, CLASS.matrix, false);
    const pageTrimmingRect = edge('pageTrimmingRect', pageInfo,
      FIELD.trimmingRect, CLASS.rect, false);
    const originBitmap = edge('originBitmap', pageInfo, FIELD.originBitmap,
      CLASS.bitmap, true);
    const displayBitmap = edge('displayBitmap', pageInfo, FIELD.displayBitmap,
      CLASS.bitmap, true);
    const digestBitmap = edge('digestBitmap', pageInfo, FIELD.digestBitmap,
      CLASS.bitmap, true);

    const presenterUri = edge('presenterUri', presenter, FIELD.uri, CLASS.uri, false);
    const presenterBitmap = edge('presenterBitmap', presenter, FIELD.presenterBitmap,
      CLASS.bitmap, true);
    const note = edge('note', presenter, FIELD.presenterNote, CLASS.note, false);
    const client = edge('client', presenter, FIELD.presenterClient, CLASS.client, false);
    const binder = edge('binder', client, FIELD.binder, null, true);
    const sfBinder = edge('sfBinder', client, FIELD.sfBinder, null, true);

    const views = [
      ['handWriteViewAttachInfo', handWriteView, CLASS.handWriteView],
      ['imageAttachInfo', image, CLASS.imageView],
      ['digestImageAttachInfo', digestImage, CLASS.digestImageView],
      ['contentViewAttachInfo', contentView, CLASS.contentView],
      ['documentLayoutAttachInfo', documentLayout, CLASS.documentLayout]
    ];
    const viewObjects = [handWriteView, image, digestImage, contentView, documentLayout];
    const attachInfos = views.map(function (entry, index) {
      return edge(entry[0], viewObjects[index], FIELD.viewAttachInfo,
        CLASS.attachInfo, false);
    });

    const rawCurrentPage = readInt(viewModel, FIELD.currentPage, 0, MAX_PAGE_COUNT);
    const pageCount = readInt(viewModel, FIELD.pageCount, 1, MAX_PAGE_COUNT);
    const rawPageInfoPage = readInt(pageInfo, FIELD.page, 0, pageCount);
    const rawPresenterPage = readInt(presenter, FIELD.currentPage, 0, pageCount);
    requireThat(rawCurrentPage <= pageCount);
    const vmUri = uriString(viewModelUri);
    const writerUri = uriString(presenterUri);
    requireThat(vmUri === writerUri && vmUri === manifest.expected.documentUri);
    const markPath = checkedString(direct(presenter, FIELD.presenterMarkPath), true);
    requireThat(markPath === (manifest.files.mark.present ? manifest.files.mark.path : null));

    const record = {
      lifecycle: lifecycle,
      document: {
        uri: vmUri,
        rawCurrentPage: rawCurrentPage,
        pageCount: pageCount,
        rawPageInfoPage: rawPageInfoPage,
        rectangles: {
          scaleRect: rectRecord(scaleRect),
          portraitScaleRect: rectRecord(portraitScaleRect),
          landscapeScaleRect: rectRecord(landscapeScaleRect),
          showRect: rectRecord(showRect),
          trimmingRect: rectRecord(viewModelTrimmingRect),
          landscapeTrimmingRect: rectRecord(landscapeTrimmingRect)
        }
      },
      pageInfo: {
        ctm: matrixRecord(ctm), revertCtm: matrixRecord(revertCtm),
        offset: [readInt(pageInfo, FIELD.offsetX, -2147483648, 2147483647),
          readInt(pageInfo, FIELD.offsetY, -2147483648, 2147483647)],
        scale: readFloat(pageInfo, FIELD.scale),
        trimmingRect: rectRecord(pageTrimmingRect),
        bitmaps: {
          originBitmap: bitmapRecord(originBitmap),
          displayBitmap: bitmapRecord(displayBitmap),
          digestBitmap: bitmapRecord(digestBitmap)
        }
      },
      presenter: {
        uri: writerUri, rawPresenterPage: rawPresenterPage, markPath: markPath,
        rawRotationCode: readInt(presenter, FIELD.presenterRotation,
          -2147483648, 2147483647),
        bitmap: bitmapRecord(presenterBitmap),
        notePointer: pointerRecord(direct(note, FIELD.notePointer)),
        binders: {
          iBinder: {present: binder !== null, referenceStable: true},
          mSFBinder: {present: sfBinder !== null, referenceStable: true}
        }
      },
      views: {
        handWriteView: viewRecord(handWriteView, CLASS.handWriteView, attachInfos[0]),
        documentImage: viewRecord(image, CLASS.imageView, attachInfos[1]),
        digestImage: viewRecord(digestImage, CLASS.digestImageView, attachInfos[2]),
        contentView: viewRecord(contentView, CLASS.contentView, attachInfos[3]),
        documentLayout: viewRecord(documentLayout, CLASS.documentLayout, attachInfos[4])
      }
    };
    return {objects: objects, record: record};
  }

  function releaseAll(state) {
    let clean = true;
    for (let index = state.retained.length - 1; index >= 0; index--) {
      try { state.retained[index].$dispose(); } catch (_) { clean = false; }
    }
    state.retained.length = 0;
    return clean;
  }
  function runtimeAttachment() {
    requireThat(Process.arch === 'arm64' && Process.pointerSize === 8 &&
      Process.id === manifest.attachment.pid);
    const module = Process.getModuleByName(manifest.attachment.module.name);
    requireThat(module !== null && typeof module === 'object' &&
      module.name === manifest.attachment.module.name &&
      module.path === manifest.attachment.module.path &&
      module.size === manifest.attachment.module.size);
    return {
      packageName: manifest.attachment.packageName,
      processName: manifest.attachment.processName,
      pid: Process.id,
      processStartTimeTicks: manifest.attachment.startTimeTicks,
      architecture: Process.arch,
      pointerSize: Process.pointerSize,
      firmwareFingerprint: manifest.attachment.firmwareFingerprint,
      apk: {path: manifest.attachment.apk.path, size: manifest.attachment.apk.size,
        externallyVerifiedSha256: manifest.attachment.apk.sha256},
      framework: {path: manifest.attachment.framework.path,
        size: manifest.attachment.framework.size,
        externallyVerifiedSha256: manifest.attachment.framework.sha256},
      module: {name: module.name, path: module.path, size: module.size,
        externallyVerifiedSha256: manifest.attachment.module.sha256},
      observerExternallyVerifiedSha256: manifest.attachment.observerSha256
    };
  }
  function externalSessionRecord() {
    return {
      authority: manifest.externalSession.authority,
      source: 'external-coordinator',
      authorizedSerial: manifest.externalSession.authorizedSerial,
      taskId: manifest.externalSession.taskId,
      displayId: manifest.externalSession.displayId,
      hostSessionId: manifest.externalSession.hostSessionId,
      displayGeneration: manifest.externalSession.displayGeneration
    };
  }
  function emitFrames(record, success) {
    if (terminalSent) return;
    terminalSent = true;
    try { send(record); } catch (_) { /* external runner rejects partial framing */ }
    try { send({event: 'native_page_graph_snapshot_complete', success: success}); }
    catch (_) { /* external runner rejects partial framing */ }
  }
  function emitFailure() {
    emitFrames({event: 'native_page_graph_snapshot_error', schemaVersion: SCHEMA_VERSION,
      code: 'GRAPH_SNAPSHOT_REJECTED'}, false);
  }
  function emitSuccess(sample, attachment, state) {
    requireThat(heapWalks === 1 && state.sameObjectCalls > 0);
    const payload = {
      event: 'native_page_graph_snapshot', schemaVersion: SCHEMA_VERSION,
      authority: RECORD_AUTHORITY, manifestSha256: manifestDigest,
      observationOnly: true, atomic: false,
      attachment: attachment,
      externalSession: externalSessionRecord(),
      fileAuthority: manifest.files,
      coordinator: {
        authority: manifest.coordinator.authority,
        observerSessionId: manifest.coordinator.observerSessionId,
        absoluteMonotonicDeadlineNs: manifest.coordinator.absoluteMonotonicDeadlineNs,
        hardDeadlineMs: manifest.coordinator.hardDeadlineMs,
        heapWalks: heapWalks, retainedRootSamples: 2,
        externalDetachOnDeadline: true,
        externalTargetLivenessPostconditionRequired: true,
        noRetry: true
      },
      calibrationProfile: manifest.expected.calibrationProfile,
      lifecycle: {resumed: sample.lifecycle.resumed,
        finished: sample.lifecycle.finished, destroyed: sample.lifecycle.destroyed,
        graphStable: true},
      document: sample.document,
      pageInfo: sample.pageInfo,
      presenter: sample.presenter,
      views: sample.views,
      layers: {status: 'unavailable',
        reasonCode: 'DIRECT_LAYER_PROVENANCE_NOT_PINNED',
        evidenceId: 'native-page-graph-v2-static-map'}
    };
    requireThat(utf8Encode(canonicalJson(payload)).length <= MAX_OUTPUT_BYTES);
    emitFrames(payload, true);
  }

  function observe() {
    const state = {retained: [], sameObjectCalls: 0, env: null};
    let root = null;
    let liveCount = 0;
    let candidateCount = 0;
    let selectionFailed = false;
    let completed = false;
    let attachment = null;
    try {
      attachment = runtimeAttachment();
      state.env = Java.vm.getEnv();
      requireThat(state.env !== null && typeof state.env === 'object' &&
        typeof state.env.isSameObject === 'function');
      heapWalks++;
      requireThat(heapWalks === 1);
      Java.choose(CLASS.activity, {
        onMatch: function (candidate) {
          if (terminalSent || completed || selectionFailed) return 'stop';
          try {
            candidateCount++;
            requireThat(candidateCount <= MAX_HEAP_CANDIDATES);
            exactClass(candidate, CLASS.activity);
            const live = readBoolean(candidate, FIELD.resumed) === true &&
              readBoolean(candidate, FIELD.finished) === false &&
              readBoolean(candidate, FIELD.destroyed) === false;
            if (!live) return undefined;
            liveCount++;
            if (liveCount > 1) return 'stop';
            root = retained(candidate, state);
            return undefined;
          } catch (_) {
            selectionFailed = true;
            return 'stop';
          }
        },
        onComplete: function () {
          if (completed || terminalSent) return;
          completed = true;
          let result = null;
          let failed = selectionFailed;
          try {
            requireThat(!failed && liveCount === 1 && root !== null);
            const first = captureSample(root, state, null, false);
            const second = captureSample(root, state, first, true);
            requireThat(canonicalJson(first.record) === canonicalJson(second.record));
            result = second.record;
          } catch (_) { failed = true; }
          if (!releaseAll(state)) failed = true;
          if (failed || result === null) emitFailure();
          else {
            try { emitSuccess(result, attachment, state); } catch (_) { emitFailure(); }
          }
        }
      });
    } catch (_) {
      releaseAll(state);
      emitFailure();
    }
  }

  try {
    const parsed = parseManifestWire();
    manifest = parsed.value;
    manifestDigest = parsed.digest;
    validateManifest(manifest);
    Java.perform(observe);
  } catch (_) { emitFailure(); }
})();
