'use strict';

// Stock display-0 identity observation only. This is deliberately not a variant
// of the virtual-display graph probe: it neither admits a hardware experiment
// nor changes native document, pen, task, or window state.
(function () {
  const SCHEMA = 1;
  const MANIFEST_AUTHORITY = 'rtl-reader-display0-identity-manifest-v1';
  const RECORD_AUTHORITY = 'rtl-reader-display0-identity-observation-v1';
  const FINGERPRINT =
    'Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys';
  const URI = 'file:///storage/emulated/0/Document/RTL_DISPLAY0_CAPTURE_20260927.pdf';
  const MARK = '/storage/emulated/0/Document/RTL_DISPLAY0_CAPTURE_20260927.pdf.mark';
  const CLASS = Object.freeze({
    activity: 'com.supernote.document.document.DocumentActivity',
    viewModel: 'com.supernote.document.document.DocumentViewModel',
    presenter: 'com.supernote.document.handwrite.HandWritePresenter',
    uri: 'android.net.Uri$StringUri',
    hierarchicalUri: 'android.net.Uri$HierarchicalUri'
  });
  const MAX_MANIFEST_BYTES = 4096;
  const MAX_CANDIDATES = 64;
  let terminal = false;
  let heapWalks = 0;
  let timer = null;
  let activeState = null;
  let failurePhase = 'MANIFEST';
  let failureReason = 'INVALID';
  const concreteUriClasses = Object.create(null);

  function reject() { throw 'DISPLAY0_IDENTITY_REJECTED'; }
  function need(condition) { if (!condition) reject(); }
  function point(phase, reason) {
    failurePhase = phase;
    failureReason = reason;
  }
  function record(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
  }
  function keys(value, expected) {
    need(record(value));
    const actual = Object.keys(value).sort();
    const wanted = expected.slice().sort();
    need(actual.length === wanted.length);
    for (let i = 0; i < actual.length; i++) need(actual[i] === wanted[i]);
  }
  function integer(value, min, max) {
    need(typeof value === 'number' && Number.isSafeInteger(value) &&
      !Object.is(value, -0) && value >= min && value <= max);
    return value;
  }
  function string(value, max) {
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
    if (typeof value === 'string') return JSON.stringify(string(value, 1024));
    if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
    need(record(value));
    const sorted = Object.keys(value).sort();
    return '{' + sorted.map(function (key) {
      string(key, 128);
      return JSON.stringify(key) + ':' + canonical(value[key]);
    }).join(',') + '}';
  }
  // SHA-256 is local so the observer does not call another Java API or trust a
  // host-supplied digest without checking the exact bytes loaded into Frida.
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
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
    const padded = bytes.slice();
    const bitLength = padded.length * 8;
    padded.push(0x80);
    while ((padded.length % 64) !== 56) padded.push(0);
    for (let shift = 56; shift >= 0; shift -= 8) {
      padded.push(shift >= 32 ? 0 : (bitLength / Math.pow(2, shift)) & 0xff);
    }
    const h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const rotate = (v, n) => (v >>> n) | (v << (32 - n));
    for (let offset = 0; offset < padded.length; offset += 64) {
      const w = new Array(64);
      for (let i = 0; i < 16; i++) {
        const j = offset + i * 4;
        w[i] = ((padded[j] << 24) | (padded[j + 1] << 16) |
          (padded[j + 2] << 8) | padded[j + 3]) >>> 0;
      }
      for (let i = 16; i < 64; i++) {
        const a = rotate(w[i - 15], 7) ^ rotate(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const b = rotate(w[i - 2], 17) ^ rotate(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + a + w[i - 7] + b) >>> 0;
      }
      let [a, b, c, d, e, f, g, q] = h;
      for (let i = 0; i < 64; i++) {
        const x = (q + (rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25)) +
          ((e & f) ^ (~e & g)) + constants[i] + w[i]) >>> 0;
        const y = ((rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22)) +
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
    const input = globalThis.NATIVE_PAGE_DISPLAY0_IDENTITY_MANIFEST_UTF8;
    const digest = shaText(globalThis.NATIVE_PAGE_DISPLAY0_IDENTITY_MANIFEST_SHA256);
    need(Array.isArray(input) && input.length > 0 && input.length <= MAX_MANIFEST_BYTES);
    const bytes = input.map(v => integer(v, 0, 255));
    need(sha256(bytes) === digest);
    // This manifest is deliberately ASCII-only. Duplicate JSON keys, escapes,
    // extraneous fields, and noncanonical byte encodings fail the round trip.
    need(bytes.every(v => v >= 0x20 && v <= 0x7e));
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
    return {value: value, digest: digest};
  }
  function direct(parent, field) {
    need(parent !== null && typeof parent === 'object');
    const slot = parent[field];
    need(slot !== null && typeof slot === 'object' && ('value' in slot));
    return slot.value;
  }
  function exactClass(value, name) {
    need(value !== null && typeof value === 'object' && value.$className === name &&
      value.$h !== null && typeof value.$h === 'object');
  }
  function keep(value, state) {
    let copy = null;
    try {
      copy = Java.retain(value);
      need(copy !== null && typeof copy === 'object' && copy.$h !== null &&
        typeof copy.$h === 'object' && typeof copy.$dispose === 'function');
      state.refs.push(copy);
      return copy;
    } catch (_) {
      let cleaned = copy === null;
      if (copy !== null && typeof copy === 'object' && typeof copy.$dispose === 'function') {
        try { copy.$dispose(); cleaned = true; } catch (_) { /* fixed cleanup phase below */ }
      }
      if (!cleaned) point('CLEANUP', 'FAILED');
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
  function compareRef(value, previous, className, state) {
    exactClass(value, className);
    need(state.env.isSameObject(previous.$h, value.$h) === true);
    return value;
  }
  function boolean(parent, field) {
    const value = direct(parent, field);
    need(typeof value === 'boolean');
    return value;
  }
  function uriSubtype(value) {
    point('URI', 'SUBTYPE');
    need(value !== null && typeof value === 'object');
    const subtype = value.$className;
    need(subtype === CLASS.uri || subtype === CLASS.hierarchicalUri);
    exactClass(value, subtype);
    return subtype;
  }
  function uri(value, subtype) {
    point('URI', 'WRAPPER');
    exactClass(value, subtype);
    // Field access on a declared android.net.Uri wrapper does not expose the
    // concrete StringUri or HierarchicalUri member. This exact-class cast
    // performs only a JNI read-only type check; it invokes no target Java
    // method or setter. The subtype was checked against the two-class allowlist.
    if (concreteUriClasses[subtype] === undefined) {
      concreteUriClasses[subtype] = Java.use(subtype);
    }
    const concrete = Java.cast(value, concreteUriClasses[subtype]);
    exactClass(concrete, subtype);
    const cached = string(direct(concrete, 'uriString'), 1024);
    need(cached !== 'NOT CACHED');
    return cached;
  }
  function sample(root, manifest, state, previous) {
    point('IDENTITY', 'MISMATCH');
    exactClass(root, CLASS.activity);
    const lifecycle = [boolean(root, 'mResumed'), boolean(root, 'mFinished'),
      boolean(root, 'mDestroyed')];
    need(lifecycle[0] === true && lifecycle[1] === false && lifecycle[2] === false);
    const vmValue = direct(root, 'documentViewModel');
    const presenterValue = direct(root, 'handWritePresenter');
    exactClass(vmValue, CLASS.viewModel);
    exactClass(presenterValue, CLASS.presenter);
    const vm = previous ? compareRef(vmValue, previous.vm, CLASS.viewModel, state) :
      keep(vmValue, state);
    const presenter = previous ? compareRef(presenterValue, previous.presenter,
      CLASS.presenter, state) : keep(presenterValue, state);
    exactClass(vm, CLASS.viewModel);
    exactClass(presenter, CLASS.presenter);
    const vmUriValue = direct(vm, 'uri');
    const presenterUriValue = direct(presenter, 'uri');
    const vmUriSubtype = uriSubtype(vmUriValue);
    const presenterUriSubtype = uriSubtype(presenterUriValue);
    if (previous) {
      need(vmUriSubtype === previous.vmUriSubtype &&
        presenterUriSubtype === previous.presenterUriSubtype);
    }
    point('URI', 'WRAPPER');
    const vmUri = previous ? compareRef(vmUriValue, previous.vmUri, vmUriSubtype, state) :
      keep(vmUriValue, state);
    const presenterUri = previous ? compareRef(presenterUriValue, previous.presenterUri,
      presenterUriSubtype, state) : keep(presenterUriValue, state);
    const observedVmUri = uri(vmUri, vmUriSubtype);
    const observedPresenterUri = uri(presenterUri, presenterUriSubtype);
    point('URI', 'MISMATCH');
    need(observedVmUri === observedPresenterUri &&
      observedVmUri === manifest.expected.documentUri);
    point('IDENTITY', 'MISMATCH');
    const rawMark = direct(presenter, 'markPath');
    need(rawMark === null || typeof rawMark === 'string');
    if (rawMark !== null) need(string(rawMark, 1024) === MARK);
    if (previous) need(rawMark === previous.privateMarkPath);
    if (manifest.expected.markPath !== null) need(rawMark === manifest.expected.markPath);
    const diagnostic = {markPathPresent: rawMark !== null,
      markPathMatchedExpected: manifest.expected.markPath === null ? null : true};
    const result = {lifecycle: lifecycle, diagnostic: diagnostic};
    if (previous) need(JSON.stringify(result) === JSON.stringify(previous.result));
    return {vm: vm, presenter: presenter, vmUri: vmUri, vmUriSubtype: vmUriSubtype,
      presenterUri: presenterUri, presenterUriSubtype: presenterUriSubtype,
      privateMarkPath: rawMark, result: result};
  }
  function frames(payload, success) {
    if (terminal) return;
    terminal = true;
    if (timer !== null) { clearTimeout(timer); timer = null; }
    try { send(payload); } catch (_) { /* host rejects partial framing */ }
    try { send({event: 'native_page_display0_identity_complete', success: success}); }
    catch (_) { /* host rejects partial framing */ }
  }
  function fail() {
    frames({event: 'native_page_display0_identity_error', schemaVersion: SCHEMA,
      code: 'DISPLAY0_IDENTITY_REJECTED', phase: failurePhase,
      reason: failureReason}, false);
  }
  function observe(manifest, digest) {
    if (terminal) return;
    const state = {refs: [], released: false, cleanupFailed: false, env: null};
    activeState = state;
    let root = null;
    let candidates = 0;
    let live = 0;
    let failed = false;
    let completed = false;
    let chooseReturned = false;
    let enteredChoose = false;
    let staged = null;
    function flush() {
      if (!chooseReturned || staged === null || terminal) return;
      const outcome = staged;
      staged = null;
      if (outcome === false) fail();
      else frames(outcome, true);
    }
    try {
      point('RUNTIME', 'MISMATCH');
      need(Process.arch === 'arm64' && Process.pointerSize === 8 &&
        Process.id === manifest.attachment.pid);
      point('BRIDGE', 'UNAVAILABLE');
      state.env = Java.vm.getEnv();
      need(state.env !== null && typeof state.env.isSameObject === 'function');
      point('JAVA_CHOOSE', 'FAILED');
      heapWalks++;
      need(heapWalks === 1);
      enteredChoose = true;
      Java.choose(CLASS.activity, {
        onMatch: function (candidate) {
          if (terminal || completed || failed) return 'stop';
          try {
            point('ACTIVITY', 'LIMIT');
            candidates++;
            need(candidates <= MAX_CANDIDATES);
            point('IDENTITY', 'MISMATCH');
            exactClass(candidate, CLASS.activity);
            if (!boolean(candidate, 'mResumed') ||
                boolean(candidate, 'mFinished') || boolean(candidate, 'mDestroyed')) {
              return undefined;
            }
            live++;
            if (live > 1) {
              point('ACTIVITY', 'MULTIPLE');
              return 'stop';
            }
            point('BRIDGE', 'UNAVAILABLE');
            root = keep(candidate, state);
          } catch (_) { failed = true; return 'stop'; }
          return undefined;
        },
        onComplete: function () {
          if (terminal || completed) return;
          completed = true;
          let result = null;
          try {
            if (!failed && live === 0) point('ACTIVITY', 'NONE');
            if (!failed && live > 1) point('ACTIVITY', 'MULTIPLE');
            need(!failed && live === 1 && root !== null);
            const first = sample(root, manifest, state, null);
            const second = sample(root, manifest, state, first);
            result = second.result;
          } catch (_) { failed = true; }
          if (!release(state)) {
            point('CLEANUP', 'FAILED');
            failed = true;
          }
          if (failed || result === null) staged = false;
          else staged = {event: 'native_page_display0_identity', schemaVersion: SCHEMA,
            authority: RECORD_AUTHORITY, manifestSha256: digest,
            observationOnly: true, hardwareAdmission: false,
            hostAssertionsOnly: true, runtimePidMatched: true,
            heapWalks: heapWalks, retainedRootSamples: 2,
            lifecycle: {resumed: true, finished: false, destroyed: false},
            uriAgreementAndExpectedMatch: true,
            markPathPresent: result.diagnostic.markPathPresent,
            markPathMatchedExpected: result.diagnostic.markPathMatchedExpected};
          flush();
        }
      });
      chooseReturned = true;
      flush();
    } catch (_) {
      // A synchronous onComplete may have staged success just before choose
      // throws. Only a normal choose return is allowed to publish it.
      staged = null;
      if (enteredChoose && failurePhase !== 'CLEANUP') point('JAVA_CHOOSE', 'FAILED');
      if (!release(state)) point('CLEANUP', 'FAILED');
      fail();
    }
  }
  try {
    point('MANIFEST', 'INVALID');
    const parsed = parseManifest();
    // This JavaScript timer is advisory: a blocked Frida event loop cannot run
    // it. The host must enforce its own monotonic timeout and detach on expiry.
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
