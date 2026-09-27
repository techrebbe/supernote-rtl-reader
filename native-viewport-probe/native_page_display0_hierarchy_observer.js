'use strict';

// One-shot, observation-only stock-reader hierarchy snapshot. This script
// neither hooks target methods nor modifies a View. The host authenticates the
// device, foreground task, process start, PDF and missing .mark on both sides.
(function () {
  const VERSION = 1;
  const MANIFEST_AUTHORITY = 'rtl-reader-display0-hierarchy-manifest-v1';
  const RECORD_AUTHORITY = 'rtl-reader-display0-hierarchy-observation-v1';
  const FINGERPRINT =
    'Supernote/Supernote/Supernote:11/RQ2A.210505.003/eng.supern.20260616.100032:user/release-keys';
  const URI = 'file:///storage/emulated/0/Document/RTL_DISPLAY0_CAPTURE_20260927.pdf';
  const CLASSES = Object.freeze({
    activity: 'com.supernote.document.document.DocumentActivity',
    vm: 'com.supernote.document.document.DocumentViewModel',
    root: 'android.widget.FrameLayout',
    pdf: 'com.supernote.document.utils.view.DocumentImageView',
    digest: 'com.supernote.document.utils.view.DigestImageView',
    pen: 'com.supernote.document.handwrite.HandWriteView',
    stringUri: 'android.net.Uri$StringUri',
    hierarchicalUri: 'android.net.Uri$HierarchicalUri'
  });
  const MAX_CHILDREN = 32;
  let done = false, timer = null, state = null, phase = 'MANIFEST', reason = 'INVALID';
  let stage = 'NONE', childIndex = -1, sampleOrdinal = 0;
  function reject() { throw 'HIERARCHY_REJECTED'; }
  function need(ok) { if (!ok) reject(); }
  function point(p, r) {
    phase = p; reason = r;
    stage = 'NONE'; childIndex = -1; sampleOrdinal = 0;
  }
  // Error diagnostics carry only fixed checkpoints and bounded ordinals. They
  // never publish a partial hierarchy, exception text, target URI, or geometry.
  function checkpoint(name, index = -1) { stage = name; childIndex = index; }
  function object(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
  function keys(value, names) {
    need(object(value));
    const a = Object.keys(value).sort(), b = names.slice().sort();
    need(a.length === b.length && a.every((name, i) => name === b[i]));
  }
  function integer(v, lo, hi) {
    need(typeof v === 'number' && Number.isSafeInteger(v) &&
      !Object.is(v, -0) && v >= lo && v <= hi);
    return v;
  }
  function ascii(v, max) {
    need(typeof v === 'string' && v.length > 0 && v.length <= max &&
      /^[\x20-\x7e]+$/.test(v));
    return v;
  }
  function shaText(v) { need(typeof v === 'string' && /^[0-9a-f]{64}$/.test(v)); return v; }
  function canonical(value) {
    if (value === null) return 'null';
    if (typeof value === 'boolean') return value ? 'true' : 'false';
    if (typeof value === 'number') return String(integer(value, 0, 9007199254740991));
    if (typeof value === 'string') return JSON.stringify(ascii(value, 1024));
    if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
    need(object(value));
    return '{' + Object.keys(value).sort().map(key => {
      ascii(key, 128);
      return JSON.stringify(key) + ':' + canonical(value[key]);
    }).join(',') + '}';
  }
  // Local SHA-256 keeps manifest admission independent of target Java calls.
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
        const j = offset + 4 * i;
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
  function manifest() {
    const bytes = globalThis.NATIVE_PAGE_HIERARCHY_MANIFEST_UTF8;
    const digest = shaText(globalThis.NATIVE_PAGE_HIERARCHY_MANIFEST_SHA256);
    need(Array.isArray(bytes) && bytes.length > 0 && bytes.length <= 4096);
    bytes.forEach(v => integer(v, 0, 255));
    need(bytes.every(v => v >= 0x20 && v <= 0x7e) && sha256(bytes) === digest);
    const wire = String.fromCharCode.apply(null, bytes);
    let value;
    try { value = JSON.parse(wire); } catch (_) { reject(); }
    need(canonical(value) === wire);
    keys(value, ['schemaVersion', 'authority', 'attachment', 'expected', 'coordinator']);
    need(value.schemaVersion === VERSION && value.authority === MANIFEST_AUTHORITY);
    const a = value.attachment;
    keys(a, ['packageName', 'processName', 'pid', 'startTimeTicks',
      'firmwareFingerprint', 'observerSha256']);
    need(a.packageName === 'com.supernote.document' &&
      a.processName === 'com.supernote.document' && a.firmwareFingerprint === FINGERPRINT);
    integer(a.pid, 1, 2147483647);
    need(typeof a.startTimeTicks === 'string' && /^[1-9][0-9]{0,19}$/.test(a.startTimeTicks));
    shaText(a.observerSha256);
    keys(value.expected, ['documentUri', 'markPath']);
    need(value.expected.documentUri === URI && value.expected.markPath === null);
    const c = value.coordinator;
    keys(c, ['maxJavaChooseWalks', 'retainedRootSamples', 'hardDeadlineMs',
      'detachOnDeadline', 'abortOnAnyError', 'noRetry']);
    need(c.maxJavaChooseWalks === 1 && c.retainedRootSamples === 2 &&
      c.detachOnDeadline === true && c.abortOnAnyError === true && c.noRetry === true);
    integer(c.hardDeadlineMs, 250, 10000);
    return {value, digest};
  }
  function direct(owner, field) {
    need(object(owner));
    const slot = owner[field];
    need(object(slot) && 'value' in slot);
    return slot.value;
  }
  function exact(value, className) {
    need(object(value) && value.$className === className && object(value.$h));
  }
  function retain(value, s) {
    let copy = null;
    try {
      copy = Java.retain(value);
      need(object(copy) && object(copy.$h) && typeof copy.$dispose === 'function');
      s.refs.push(copy);
      return copy;
    } catch (_) {
      if (copy !== null && object(copy) && typeof copy.$dispose === 'function') {
        try { copy.$dispose(); } catch (_) { point('CLEANUP', 'FAILED'); }
      }
      reject();
    }
  }
  function release(s) {
    if (s.released) return !s.cleanupFailed;
    s.released = true;
    let clean = true;
    for (let i = s.refs.length - 1; i >= 0; i--) {
      try { s.refs[i].$dispose(); } catch (_) { clean = false; }
    }
    s.refs.length = 0;
    s.cleanupFailed = !clean;
    return clean;
  }
  function same(s, a, b) {
    need(object(a) && object(b) && s.env.isSameObject(a.$h, b.$h) === true);
  }
  function f64(v) {
    need(typeof v === 'number' && Number.isFinite(v) && Math.abs(v) <= 1000000000);
    const buffer = new DataView(new ArrayBuffer(8));
    buffer.setFloat64(0, v, false);
    let result = '0x';
    for (let i = 0; i < 8; i++) result += buffer.getUint8(i).toString(16).padStart(2, '0');
    return result;
  }
  function bounds(v, requirePositive) {
    const box = ['mLeft', 'mTop', 'mRight', 'mBottom'].map(field =>
      integer(direct(v, field), -2147483648, 2147483647));
    // A stock GONE/INVISIBLE child can legitimately have 0×0 bounds.
    need(requirePositive ? box[2] > box[0] && box[3] > box[1] :
      box[2] >= box[0] && box[3] >= box[1]);
    return box;
  }
  function childSnapshot(v, index, s, root) {
    checkpoint('CHILD_CLASS', index);
    const name = ascii(v.$className, 160);
    need(object(v.$h));
    checkpoint('CHILD_PARENT', index);
    same(s, v.getParent(), root);
    checkpoint('CHILD_ID', index);
    const id = integer(v.getId(), -1, 2147483647);
    checkpoint('CHILD_VISIBILITY', index);
    const visibility = integer(v.getVisibility(), 0, 8);
    need([0, 4, 8].includes(visibility));
    checkpoint('CHILD_BOUNDS', index);
    const box = bounds(v, visibility === 0);
    checkpoint('CHILD_Z', index);
    const z = f64(v.getZ());
    return {index, id, className: name, bounds: box,
      visibility, z, parentIsRoot: true};
  }
  function sample(activity, s, previous) {
    point('HIERARCHY', 'MISMATCH');
    sampleOrdinal = previous === null ? 1 : 2;
    checkpoint('ACTIVITY_CLASS');
    exact(activity, CLASSES.activity);
    checkpoint('ACTIVITY_LIFECYCLE');
    need(direct(activity, 'mResumed') === true &&
      direct(activity, 'mFinished') === false &&
      direct(activity, 'mDestroyed') === false);
    checkpoint('VM_CLASS');
    const vm = direct(activity, 'documentViewModel');
    exact(vm, CLASSES.vm);
    checkpoint('URI_CLASS');
    const uri = direct(vm, 'uri');
    need(object(uri) && [CLASSES.stringUri, CLASSES.hierarchicalUri].includes(uri.$className));
    checkpoint('URI_VALUE');
    const concrete = Java.cast(uri, Java.use(uri.$className));
    need(ascii(direct(concrete, 'uriString'), 1024) === URI);
    checkpoint('ROOT_CLASS');
    const root = direct(activity, 'mContentView');
    exact(root, CLASSES.root);
    const fields = [
      ['pdf', 'mImage', CLASSES.pdf],
      ['digest', 'digestImage', CLASSES.digest],
      ['pen', 'handWriteView', CLASSES.pen]
    ];
    const refs = {activity, vm, uri, root}, fieldIndex = {};
    for (const [key, name, className] of fields) {
      checkpoint('FIELD_' + key.toUpperCase());
      const view = direct(activity, name);
      exact(view, className);
      refs[key] = view;
    }
    checkpoint('ROOT_CHILD_COUNT');
    const count = integer(root.getChildCount(), 4, MAX_CHILDREN);
    checkpoint('DRAW_ORDER');
    const customDrawingOrder = root.isChildrenDrawingOrderEnabled();
    need(typeof customDrawingOrder === 'boolean');
    const children = [];
    for (let i = 0; i < count; i++) {
      checkpoint('CHILD_HANDLE', i);
      const child = root.getChildAt(i);
      need(object(child) && object(child.$h));
      refs['child' + i] = child;
      children.push(childSnapshot(child, i, s, root));
      checkpoint('CHILD_FIELD_IDENTITY', i);
      for (const [key] of fields) {
        if (s.env.isSameObject(child.$h, refs[key].$h) === true) {
          need(fieldIndex[key] === undefined);
          fieldIndex[key] = i;
        }
      }
    }
    checkpoint('FIELD_ORDER');
    need(Object.keys(fieldIndex).length === 3 &&
      fieldIndex.pdf < fieldIndex.digest && fieldIndex.digest < fieldIndex.pen);
    // These are raw child indices and Z values. A custom draw order or future
    // framework behavior can invalidate any inferred effective compositing.
    checkpoint('ROOT_ID');
    const rootId = integer(root.getId(), -1, 2147483647);
    checkpoint('ROOT_BOUNDS');
    const rootBounds = bounds(root, true);
    const output = {rootClass: CLASSES.root, rootId,
      rootBounds, childCount: count, children,
      fieldIndex, customDrawingOrder,
      effectiveCompositingAdmitted: false,
      uriMatchedExpected: true, lifecycleStable: true};
    if (previous !== null) {
      checkpoint('SECOND_SAMPLE_REFS');
      for (const key of Object.keys(refs)) same(s, refs[key], previous.refs[key]);
      checkpoint('SECOND_SAMPLE_VALUES');
      need(JSON.stringify(output) === JSON.stringify(previous.output));
    }
    return {refs, output};
  }
  function frames(payload, success) {
    if (done) return;
    done = true;
    if (timer !== null) clearTimeout(timer);
    try { send(payload); } catch (_) { /* host rejects incomplete framing */ }
    try { send({event: 'native_page_hierarchy_complete', success}); }
    catch (_) { /* host rejects incomplete framing */ }
  }
  function fail() {
    frames({event: 'native_page_hierarchy_error', schemaVersion: VERSION,
      code: 'HIERARCHY_REJECTED', phase, reason, stage, childIndex,
      sampleOrdinal}, false);
  }
  function observe(parsed) {
    if (done) return;
    const s = {refs: [], released: false, cleanupFailed: false, env: null};
    state = s;
    let selected = null, candidates = 0, live = 0, failed = false;
    let completed = false, chooseReturned = false, staged = null;
    function flush() {
      if (!chooseReturned || staged === null || done) return;
      if (staged === false) fail(); else frames(staged, true);
    }
    try {
      point('RUNTIME', 'MISMATCH');
      need(Process.arch === 'arm64' && Process.pointerSize === 8 &&
        Process.id === parsed.value.attachment.pid);
      point('BRIDGE', 'UNAVAILABLE');
      point('JAVA_CHOOSE', 'FAILED');
      Java.choose(CLASSES.activity, {
        onMatch(candidate) {
          if (done || completed || failed) return 'stop';
          try {
            point('ACTIVITY', 'LIMIT');
            need(++candidates <= 64);
            if (direct(candidate, 'mResumed') !== true ||
                direct(candidate, 'mFinished') !== false ||
                direct(candidate, 'mDestroyed') !== false) return undefined;
            if (++live > 1) { point('ACTIVITY', 'MULTIPLE'); return 'stop'; }
            selected = retain(candidate, s);
          } catch (_) { failed = true; return 'stop'; }
          return undefined;
        },
        onComplete() {
          if (done || completed) return;
          completed = true;
          try {
            if (!failed && live === 0) point('ACTIVITY', 'NONE');
            need(!failed && live === 1 && selected !== null);
            point('BRIDGE', 'UNAVAILABLE');
            Java.scheduleOnMainThread(function () {
              if (done) return;
              let output = null;
              try {
                // JNIEnv is thread-local; never carry one from the choose
                // callback onto the UI thread.
                point('BRIDGE', 'UNAVAILABLE');
                s.env = Java.vm.getEnv();
                need(object(s.env) && typeof s.env.isSameObject === 'function');
                const first = sample(selected, s, null);
                output = sample(selected, s, first).output;
              } catch (_) { failed = true; }
              if (!release(s)) { point('CLEANUP', 'FAILED'); failed = true; }
              if (failed || output === null) staged = false;
              else {
                staged = {event: 'native_page_hierarchy', schemaVersion: VERSION,
                  authority: RECORD_AUTHORITY, manifestSha256: parsed.digest,
                  observationOnly: true, hardwareAdmission: false,
                  uiThreadSamples: true, heapWalks: 1,
                  retainedRootSamples: 2, hierarchyStable: true, ...output};
                if (JSON.stringify(staged).length > 12288) {
                  point('OUTPUT', 'OVERSIZE'); staged = false;
                }
              }
              flush();
            });
          } catch (_) {
            if (!release(s)) point('CLEANUP', 'FAILED');
            staged = false;
            flush();
          }
        }
      });
      chooseReturned = true;
      flush();
    } catch (_) {
      if (!release(s)) point('CLEANUP', 'FAILED');
      fail();
    }
  }
  try {
    point('MANIFEST', 'INVALID');
    const parsed = manifest();
    timer = setTimeout(function () {
      point('DEADLINE', 'EXPIRED');
      if (state !== null && !release(state)) point('CLEANUP', 'FAILED');
      fail();
    }, parsed.value.coordinator.hardDeadlineMs);
    Java.perform(function () { observe(parsed); });
  } catch (_) {
    if (state !== null && !release(state)) point('CLEANUP', 'FAILED');
    fail();
  }
})();
