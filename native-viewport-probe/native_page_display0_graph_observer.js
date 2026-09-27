'use strict';

// Disposable stock-reader graph calibration. No hooks, setters, target methods,
// input synthesis, pen ownership, or hardware-admission claim. The host owns
// PID/start-time, file, task/display, deadline, and post-detach authority.
(function () {
  const SCHEMA = 1;
  const MANIFEST_AUTHORITY = 'rtl-reader-display0-graph-manifest-v1';
  const RECORD_AUTHORITY = 'rtl-reader-display0-graph-observation-v1';
  const FINGERPRINT =
    'Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys';
  const URI = 'file:///storage/emulated/0/Document/RTL_DISPLAY0_CAPTURE_20260927.pdf';
  const MARK = '/storage/emulated/0/Document/RTL_DISPLAY0_CAPTURE_20260927.pdf.mark';
  const CLASS = Object.freeze({
    activity: 'com.supernote.document.document.DocumentActivity',
    vm: 'com.supernote.document.document.DocumentViewModel',
    presenter: 'com.supernote.document.handwrite.HandWritePresenter',
    pageInfo: 'com.supernote.document.document.PageInfo',
    matrix: 'com.artifex.mupdf.fitz.Matrix', rect: 'android.graphics.RectF',
    bitmap: 'android.graphics.Bitmap',
    handWriteView: 'com.supernote.document.handwrite.HandWriteView',
    documentImage: 'com.supernote.document.utils.view.DocumentImageView',
    digestImage: 'com.supernote.document.utils.view.DigestImageView',
    contentView: 'android.widget.FrameLayout', documentLayout: 'android.widget.RelativeLayout',
    attachInfo: 'android.view.View$AttachInfo',
    stringUri: 'android.net.Uri$StringUri',
    hierarchicalUri: 'android.net.Uri$HierarchicalUri'
  });
  const VIEW_FIELDS = Object.freeze([
    ['handWriteView', 'handWriteView', CLASS.handWriteView],
    ['documentImage', 'mImage', CLASS.documentImage],
    ['digestImage', 'digestImage', CLASS.digestImage],
    ['contentView', 'mContentView', CLASS.contentView],
    ['documentLayout', 'documentViewLayout', CLASS.documentLayout]
  ]);
  const MAX_MANIFEST_BYTES = 4096;
  const MAX_CANDIDATES = 64;
  const MAX_DIMENSION = 32768;
  const MAX_NUMBER = 1000000000;
  let terminal = false, timer = null, activeState = null, walks = 0;
  let phase = 'MANIFEST', reason = 'INVALID';
  const concreteUriClasses = Object.create(null);

  function reject() { throw 'DISPLAY0_GRAPH_REJECTED'; }
  function need(ok) { if (!ok) reject(); }
  function point(p, r) { phase = p; reason = r; }
  function record(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }
  function keys(value, expected) {
    need(record(value));
    const actual = Object.keys(value).sort(), wanted = expected.slice().sort();
    need(actual.length === wanted.length);
    for (let i = 0; i < actual.length; i++) need(actual[i] === wanted[i]);
  }
  function integer(value, min, max) {
    need(typeof value === 'number' && Number.isSafeInteger(value) &&
      !Object.is(value, -0) && value >= min && value <= max);
    return value;
  }
  function ascii(value, max) {
    need(typeof value === 'string' && value.length > 0 && value.length <= max &&
      /^[\x20-\x7e]+$/.test(value));
    return value;
  }
  function shaText(value) {
    need(typeof value === 'string' && /^[0-9a-f]{64}$/.test(value));
    return value;
  }
  function canonical(value) {
    if (value === null) return 'null';
    if (typeof value === 'boolean') return value ? 'true' : 'false';
    if (typeof value === 'number') return String(integer(value, 0, 9007199254740991));
    if (typeof value === 'string') return JSON.stringify(ascii(value, 1024));
    if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
    need(record(value));
    return '{' + Object.keys(value).sort().map(function (key) {
      ascii(key, 128);
      return JSON.stringify(key) + ':' + canonical(value[key]);
    }).join(',') + '}';
  }
  // Local SHA-256 avoids invoking any target Java method during admission.
  function sha256(bytes) {
    const k = [
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
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
    const padded = bytes.slice(), bits = padded.length * 8;
    padded.push(0x80);
    while (padded.length % 64 !== 56) padded.push(0);
    for (let shift = 56; shift >= 0; shift -= 8)
      padded.push(shift >= 32 ? 0 : (bits / Math.pow(2, shift)) & 255);
    const h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const rot = (v, n) => (v >>> n) | (v << (32 - n));
    for (let offset = 0; offset < padded.length; offset += 64) {
      const w = new Array(64);
      for (let i = 0; i < 16; i++) {
        const j = offset + i * 4;
        w[i] = ((padded[j] << 24) | (padded[j + 1] << 16) |
          (padded[j + 2] << 8) | padded[j + 3]) >>> 0;
      }
      for (let i = 16; i < 64; i++) {
        const a = rot(w[i - 15], 7) ^ rot(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const b = rot(w[i - 2], 17) ^ rot(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + a + w[i - 7] + b) >>> 0;
      }
      let [a, b, c, d, e, f, g, q] = h;
      for (let i = 0; i < 64; i++) {
        const x = (q + (rot(e, 6) ^ rot(e, 11) ^ rot(e, 25)) +
          ((e & f) ^ (~e & g)) + k[i] + w[i]) >>> 0;
        const y = ((rot(a, 2) ^ rot(a, 13) ^ rot(a, 22)) +
          ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
        q = g; g = f; f = e; e = (d + x) >>> 0;
        d = c; c = b; b = a; a = (x + y) >>> 0;
      }
      const next = [a, b, c, d, e, f, g, q];
      for (let i = 0; i < h.length; i++) h[i] = (h[i] + next[i]) >>> 0;
    }
    return h.map(v => v.toString(16).padStart(8, '0')).join('');
  }
  function parseManifest() {
    const input = globalThis.NATIVE_PAGE_DISPLAY0_GRAPH_MANIFEST_UTF8;
    const digest = shaText(globalThis.NATIVE_PAGE_DISPLAY0_GRAPH_MANIFEST_SHA256);
    need(Array.isArray(input) && input.length > 0 && input.length <= MAX_MANIFEST_BYTES);
    const bytes = input.map(v => integer(v, 0, 255));
    need(sha256(bytes) === digest && bytes.every(v => v >= 0x20 && v <= 0x7e));
    const wire = String.fromCharCode.apply(null, bytes);
    let value;
    try { value = JSON.parse(wire); } catch (_) { reject(); }
    need(canonical(value) === wire);
    keys(value, ['schemaVersion', 'authority', 'attachment', 'expected', 'coordinator']);
    need(value.schemaVersion === SCHEMA && value.authority === MANIFEST_AUTHORITY);
    const a = value.attachment;
    keys(a, ['packageName', 'processName', 'pid', 'startTimeTicks',
      'firmwareFingerprint', 'observerSha256']);
    need(a.packageName === 'com.supernote.document' &&
      a.processName === 'com.supernote.document' &&
      a.firmwareFingerprint === FINGERPRINT);
    integer(a.pid, 1, 2147483647);
    need(/^[1-9][0-9]{0,19}$/.test(a.startTimeTicks));
    shaText(a.observerSha256);
    keys(value.expected, ['documentUri', 'markPath']);
    need(value.expected.documentUri === URI);
    need(value.expected.markPath === null || value.expected.markPath === MARK);
    const c = value.coordinator;
    keys(c, ['maxJavaChooseWalks', 'retainedRootSamples', 'hardDeadlineMs',
      'detachOnDeadline', 'abortOnAnyError', 'noRetry']);
    need(c.maxJavaChooseWalks === 1 && c.retainedRootSamples === 2 &&
      c.detachOnDeadline === true && c.abortOnAnyError === true && c.noRetry === true);
    integer(c.hardDeadlineMs, 250, 10000);
    return {value, digest};
  }
  function direct(parent, field) {
    need(parent !== null && typeof parent === 'object');
    const slot = parent[field];
    need(slot !== null && typeof slot === 'object' && ('value' in slot));
    return slot.value;
  }
  function exactClass(value, name) {
    need(value !== null && typeof value === 'object' &&
      value.$className === name && value.$h !== null && typeof value.$h === 'object');
  }
  function retain(value, state) {
    let copy = null;
    try {
      copy = Java.retain(value);
      need(copy !== null && typeof copy === 'object' &&
        copy.$h !== null && typeof copy.$h === 'object' &&
        typeof copy.$dispose === 'function');
      state.refs.push(copy);
      return copy;
    } catch (_) {
      let clean = copy === null;
      if (copy !== null && typeof copy === 'object' &&
          typeof copy.$dispose === 'function') {
        try { copy.$dispose(); clean = true; } catch (_) { /* fail below */ }
      }
      if (!clean) point('CLEANUP', 'FAILED');
      reject();
    }
  }
  function release(state) {
    if (state.released) return !state.cleanupFailed;
    state.released = true;
    let clean = true;
    for (let i = state.refs.length - 1; i >= 0; i--) {
      try { state.refs[i].$dispose(); } catch (_) { clean = false; }
    }
    state.refs.length = 0;
    state.cleanupFailed = !clean;
    return clean;
  }
  function edge(parent, field, name, state, prior, nullable) {
    const value = direct(parent, field);
    if (value === null) {
      need(nullable && (prior === undefined || prior === null));
      return null;
    }
    exactClass(value, name);
    if (prior !== undefined) {
      need(prior !== null && state.env.isSameObject(prior.$h, value.$h) === true);
      return prior;
    }
    return retain(value, state);
  }
  function finite(value) {
    need(typeof value === 'number' && Number.isFinite(value) &&
      Math.abs(value) <= MAX_NUMBER);
    return value;
  }
  function f64(value) {
    const bytes = new DataView(new ArrayBuffer(8));
    bytes.setFloat64(0, finite(value), false);
    let out = '0x';
    for (let i = 0; i < 8; i++) out += bytes.getUint8(i).toString(16).padStart(2, '0');
    return out;
  }
  function floatFields(value, names) {
    if (value === null) return null;
    return names.map(name => f64(direct(value, name)));
  }
  function bitmap(value) {
    if (value === null) return {present: false, dimensions: null};
    return {present: true, dimensions: [
      integer(direct(value, 'mWidth'), 1, MAX_DIMENSION),
      integer(direct(value, 'mHeight'), 1, MAX_DIMENSION)]};
  }
  function view(value, attach) {
    if (value === null) return {present: false, bounds: null,
      windowAttachCount: null, attached: null};
    const bounds = [
      integer(direct(value, 'mLeft'), -2147483648, 2147483647),
      integer(direct(value, 'mTop'), -2147483648, 2147483647),
      integer(direct(value, 'mRight'), -2147483648, 2147483647),
      integer(direct(value, 'mBottom'), -2147483648, 2147483647)];
    need(bounds[2] > bounds[0] && bounds[3] > bounds[1]);
    return {present: true, bounds,
      windowAttachCount: integer(direct(value, 'mWindowAttachCount'), 0, 2147483647),
      attached: attach !== null};
  }
  function subtype(value) {
    point('URI', 'SUBTYPE');
    need(value !== null && typeof value === 'object');
    const name = value.$className;
    need(name === CLASS.stringUri || name === CLASS.hierarchicalUri);
    exactClass(value, name);
    return name;
  }
  function cachedUri(value, name) {
    point('URI', 'WRAPPER');
    exactClass(value, name);
    if (concreteUriClasses[name] === undefined) concreteUriClasses[name] = Java.use(name);
    const concrete = Java.cast(value, concreteUriClasses[name]);
    exactClass(concrete, name);
    const cached = ascii(direct(concrete, 'uriString'), 1024);
    need(cached !== 'NOT CACHED');
    return cached;
  }
  function bool(value, field) {
    const result = direct(value, field);
    need(typeof result === 'boolean');
    return result;
  }
  function sample(root, manifest, state, previous) {
    point('GRAPH', 'MISMATCH');
    exactClass(root, CLASS.activity);
    const lifecycle = {resumed: bool(root, 'mResumed'),
      finished: bool(root, 'mFinished'), destroyed: bool(root, 'mDestroyed')};
    need(lifecycle.resumed && !lifecycle.finished && !lifecycle.destroyed);
    const refs = {}, prior = previous === null ? {} : previous.refs;
    function read(name, parent, field, className, nullable) {
      const value = edge(parent, field, className, state,
        previous === null ? undefined : prior[name], nullable);
      refs[name] = value;
      return value;
    }
    const vm = read('vm', root, 'documentViewModel', CLASS.vm, false);
    const presenter = read('presenter', root, 'handWritePresenter', CLASS.presenter, false);
    const page = read('page', vm, 'pageInfo', CLASS.pageInfo, false);
    const vmUri = direct(vm, 'uri'), presenterUri = direct(presenter, 'uri');
    const vmSubtype = subtype(vmUri), presenterSubtype = subtype(presenterUri);
    if (previous !== null) need(vmSubtype === previous.vmSubtype &&
      presenterSubtype === previous.presenterSubtype);
    const vmUriRef = read('vmUri', vm, 'uri', vmSubtype, false);
    const presenterUriRef = read('presenterUri', presenter, 'uri', presenterSubtype, false);
    const vmCached = cachedUri(vmUriRef, vmSubtype);
    const presenterCached = cachedUri(presenterUriRef, presenterSubtype);
    point('URI', 'MISMATCH');
    need(vmCached === presenterCached && vmCached === manifest.expected.documentUri);
    point('GRAPH', 'MISMATCH');
    const mark = direct(presenter, 'markPath');
    need(mark === null || (typeof mark === 'string' && mark === MARK));
    if (manifest.expected.markPath !== null) need(mark === manifest.expected.markPath);
    const ctm = read('ctm', page, 'ctm', CLASS.matrix, true);
    const inverse = read('revertCtm', page, 'revertCtm', CLASS.matrix, true);
    const crop = read('trimmingRect', page, 'trimmingRect', CLASS.rect, true);
    const origin = read('originBitmap', page, 'originBitmap', CLASS.bitmap, true);
    const display = read('displayBitmap', page, 'displayBitmap', CLASS.bitmap, true);
    const digest = read('digestBitmap', page, 'digestBitmap', CLASS.bitmap, true);
    const penBitmap = read('presenterBitmap', presenter, 'bitmap', CLASS.bitmap, true);
    const views = {};
    for (const [name, field, className] of VIEW_FIELDS) {
      const value = read(name, root, field, className, true);
      const attach = value === null ? null :
        read(name + 'Attach', value, 'mAttachInfo', CLASS.attachInfo, true);
      if (value === null) {
        need(previous === null || prior[name + 'Attach'] === undefined);
      }
      views[name] = view(value, attach);
    }
    const output = {lifecycle, uriAgreementAndExpectedMatch: true,
      markPathPresent: mark !== null,
      markPathMatchedExpected: manifest.expected.markPath === null ? null : true,
      rawPageTuple: [integer(direct(vm, 'currentPage'), 0, 10000000),
        integer(direct(vm, 'pageCount'), 1, 10000000),
        integer(direct(page, 'page'), 0, 10000000),
        integer(direct(presenter, 'currentPage'), 0, 10000000)],
      pageInfo: {ctm: floatFields(ctm, ['a', 'b', 'c', 'd', 'e', 'f']),
        revertCtm: floatFields(inverse, ['a', 'b', 'c', 'd', 'e', 'f']),
        offset: [integer(direct(page, 'offsetX'), -2147483648, 2147483647),
          integer(direct(page, 'offsetY'), -2147483648, 2147483647)],
        scale: f64(direct(page, 'scale')),
        trimmingRect: floatFields(crop, ['left', 'top', 'right', 'bottom']),
        bitmaps: {origin: bitmap(origin), display: bitmap(display), digest: bitmap(digest)}},
      presenter: {rawRotationCode: integer(direct(presenter, 'screenRotation'),
        -2147483648, 2147483647), bitmap: bitmap(penBitmap)}, views};
    if (previous !== null) need(JSON.stringify(output) === JSON.stringify(previous.output));
    return {refs, output, vmSubtype, presenterSubtype};
  }
  function frames(payload, success) {
    if (terminal) return;
    terminal = true;
    if (timer !== null) { clearTimeout(timer); timer = null; }
    try { send(payload); } catch (_) { /* host rejects partial framing */ }
    try { send({event: 'native_page_display0_graph_complete', success}); }
    catch (_) { /* host rejects partial framing */ }
  }
  function fail() {
    frames({event: 'native_page_display0_graph_error', schemaVersion: SCHEMA,
      code: 'DISPLAY0_GRAPH_REJECTED', phase, reason}, false);
  }
  function observe(manifest, digest) {
    if (terminal) return;
    const state = {refs: [], released: false, cleanupFailed: false, env: null};
    activeState = state;
    let root = null, candidates = 0, live = 0, failed = false;
    let completed = false, chooseReturned = false, enteredChoose = false, staged = null;
    function flush() {
      if (!chooseReturned || staged === null || terminal) return;
      const outcome = staged;
      staged = null;
      if (outcome === false) fail(); else frames(outcome, true);
    }
    try {
      point('RUNTIME', 'MISMATCH');
      need(Process.arch === 'arm64' && Process.pointerSize === 8 &&
        Process.id === manifest.attachment.pid);
      point('BRIDGE', 'UNAVAILABLE');
      state.env = Java.vm.getEnv();
      need(state.env !== null && typeof state.env.isSameObject === 'function');
      point('JAVA_CHOOSE', 'FAILED');
      need(++walks === 1);
      enteredChoose = true;
      Java.choose(CLASS.activity, {
        onMatch(candidate) {
          if (terminal || completed || failed) return 'stop';
          try {
            point('ACTIVITY', 'LIMIT');
            need(++candidates <= MAX_CANDIDATES);
            point('GRAPH', 'MISMATCH');
            exactClass(candidate, CLASS.activity);
            if (!bool(candidate, 'mResumed') || bool(candidate, 'mFinished') ||
                bool(candidate, 'mDestroyed')) return undefined;
            if (++live > 1) { point('ACTIVITY', 'MULTIPLE'); return 'stop'; }
            point('BRIDGE', 'UNAVAILABLE');
            root = retain(candidate, state);
          } catch (_) { failed = true; return 'stop'; }
          return undefined;
        },
        onComplete() {
          if (terminal || completed) return;
          completed = true;
          let output = null;
          try {
            if (!failed && live === 0) point('ACTIVITY', 'NONE');
            if (!failed && live > 1) point('ACTIVITY', 'MULTIPLE');
            need(!failed && live === 1 && root !== null);
            const first = sample(root, manifest, state, null);
            output = sample(root, manifest, state, first).output;
          } catch (_) { failed = true; }
          if (!release(state)) { point('CLEANUP', 'FAILED'); failed = true; }
          if (failed || output === null) staged = false;
          else {
            staged = {event: 'native_page_display0_graph', schemaVersion: SCHEMA,
              authority: RECORD_AUTHORITY, manifestSha256: digest,
              observationOnly: true, hardwareAdmission: false,
              semanticCalibration: false, hostAssertionsOnly: true,
              runtimePidMatched: true,
              heapWalks: walks, retainedRootSamples: 2, graphStable: true,
              ...output};
            // The emitted record contains only fixed ASCII keys, booleans,
            // bounded integers and binary64 hex, so length is UTF-8 size.
            if (JSON.stringify(staged).length > 8192) {
              point('OUTPUT', 'OVERSIZE'); staged = false;
            }
          }
          flush();
        }
      });
      chooseReturned = true;
      flush();
    } catch (_) {
      staged = null;
      if (enteredChoose && phase !== 'CLEANUP') point('JAVA_CHOOSE', 'FAILED');
      if (!release(state)) point('CLEANUP', 'FAILED');
      fail();
    }
  }
  try {
    point('MANIFEST', 'INVALID');
    const parsed = parseManifest();
    timer = setTimeout(function () {
      point('DEADLINE', 'EXPIRED');
      if (activeState !== null && !release(activeState)) point('CLEANUP', 'FAILED');
      fail();
    }, parsed.value.coordinator.hardDeadlineMs);
    point('BRIDGE', 'UNAVAILABLE');
    Java.perform(function () { observe(parsed.value, parsed.digest); });
  } catch (_) {
    if (activeState !== null && !release(activeState)) point('CLEANUP', 'FAILED');
    fail();
  }
})();
