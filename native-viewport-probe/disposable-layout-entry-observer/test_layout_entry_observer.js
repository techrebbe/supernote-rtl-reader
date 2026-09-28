'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SOURCE = fs.readFileSync(path.join(__dirname, 'layout_entry_observer.js'), 'utf8');
const ACTIVITY = 'com.techrebbe.supernote.layoutfencetrial.TrialActivity';
const ROOT = 'com.techrebbe.supernote.layoutfencetrial.TrialRoot';
const VIEW_GROUP = 'android.view.ViewGroup';
const config = () => ({schemaVersion: 1, pid: 2468, incarnation: 'fresh-1',
  activityToken: 'activity-1', rootToken: 'root-1'});

function scenario(options = {}) {
  let thread = 7, implementation = null, originals = 0, sends = 0;
  let identityCalls = 0, inFlightDisarm = null, pendingPerform = null;
  const disposed = [], order = [];
  const root = {$className: ROOT, $h: {id: 'root'}, bounds: [0, 0, 100, 200],
    revision: '4', ordinal: '4', layoutCalls: '3', paintCount: '8',
    getRootToken() { return 'root-1'; },
    isAttachedToWindow() { return true; },
    getLeft() { if (options.getterThrows) throw Error('private path'); return this.bounds[0]; },
    getTop() { return this.bounds[1]; },
    getRight() { return this.bounds[2]; },
    getBottom() { return this.bounds[3]; },
    getParentPreCallRevision() { return this.revision; },
    getObservedWriteOrdinal() { return this.ordinal; },
    getLayoutCallCount() { return this.layoutCalls; },
    getCompletedPaintCount() { return this.paintCount; }};
  const other = {$className: VIEW_GROUP, $h: {id: 'other'},
    getLeft() { throw Error('non-target getter called'); }};
  const activity = {$className: ACTIVITY, $h: {id: 'activity'},
    getActivityToken() { return options.wrongActivityToken ? 'other-activity' : 'activity-1'; },
    getTrialRoot() { return root; }};
  const method = {
    get implementation() { return implementation; },
    set implementation(fn) {
      if (fn === null && options.revertThrows) throw Error('private revert');
      if (fn === null && options.revertCallback && implementation !== null) {
        const old = implementation;
        implementation = null;
        old.call(other, 1, 2, 3, 4);
        return;
      }
      implementation = fn;
    },
    call(receiver, left, top, right, bottom) {
      originals++;
      order.push('original');
      if (pendingPerform !== null) {
        const callback = pendingPerform;
        pendingPerform = null;
        callback();
      }
      if (options.disarmInsideOriginal) {
        inFlightDisarm = sandbox.rpc.exports.disarm();
      }
      if (options.originalThrows) throw Error('original Java failure');
      if (receiver === root) {
        root.bounds = [left, top, right, bottom];
        root.layoutCalls = String(Number(root.layoutCalls) + 1);
      }
      return undefined;
    }
  };
  const sandbox = {
    rpc: {exports: {}},
    Process: {id: 2468, getCurrentThreadId() { return thread; }},
    Java: {
      available: true,
      perform(fn) {
        if (options.disarmPerformReentry && implementation !== null) {
          pendingPerform = fn;
          implementation.call(root, 0, 0, 100, 200);
        } else fn();
      },
      choose(name, callbacks) {
        assert.strictEqual(name, ACTIVITY);
        callbacks.onMatch(activity);
        if (options.multipleActivities) callbacks.onMatch(activity);
        callbacks.onComplete();
        if (options.chooseThrowsAfterComplete) throw Error('choose late failure');
      },
      scheduleOnMainThread(fn) {
        const prior = thread; thread = 1;
        try { fn(); } finally { thread = prior; }
      },
      retain(value) {
        const copy = Object.create(value);
        copy.$dispose = () => disposed.push(value.$h.id);
        return copy;
      },
      vm: {getEnv() { return {isSameObject(a, b) {
        identityCalls++;
        if (options.identityThrows ||
            (options.identityThrowsOnEntry && identityCalls > 1)) {
          throw Error('private identity');
        }
        return a && b && a.id === b.id;
      }}; }},
      use(name) {
        assert.strictEqual(name, VIEW_GROUP);
        return {layout: {overload(...types) {
          assert.deepStrictEqual(types, ['int', 'int', 'int', 'int']);
          return method;
        }}};
      }
    },
    send() { sends++; throw Error('send forbidden in callback'); }
  };
  vm.runInNewContext(SOURCE, sandbox);
  return {rpc: sandbox.rpc.exports, root, other, method, disposed, order,
    originals: () => originals, sends: () => sends,
    inFlightDisarm: () => inFlightDisarm,
    invoke(receiver, ...rect) {
      const prior = thread; thread = 1;
      try {
        order.push('hook');
        return implementation === null ? method.call(receiver, ...rect) :
          implementation.call(receiver, ...rect);
      } finally { thread = prior; }
    }};
}

async function tests() {
  {
    const s = scenario();
    assert.strictEqual((await s.rpc.arm(config())).ok, true);
    s.invoke(s.other, 1, 2, 3, 4);
    assert.strictEqual(s.rpc.snapshot().events.length, 0);
    s.invoke(s.root, 0, 0, 101, 200);
    const captured = s.rpc.snapshot();
    assert.strictEqual(captured.fault, null);
    assert.strictEqual(captured.callbacks, 2);
    assert.strictEqual(captured.forwardAttempts, 2);
    assert.strictEqual(captured.targetEntries, 1);
    assert.strictEqual(captured.events.length, 1);
    assert.deepStrictEqual(Array.from(captured.events[0].oldBounds), [0, 0, 100, 200]);
    assert.deepStrictEqual(Array.from(captured.events[0].proposedBounds), [0, 0, 101, 200]);
    assert.strictEqual(captured.events[0].parentRevision, '4');
    assert.strictEqual(captured.events[0].layoutCallsBefore, '3');
    assert.strictEqual(captured.events[0].originalReturned, true);
    assert.strictEqual(s.originals(), 2);
    assert.strictEqual(s.sends(), 0);
    const before = s.rpc.snapshot().callbacks;
    assert.strictEqual((await s.rpc.disarm()).ok, true);
    assert.strictEqual(s.method.implementation, null);
    s.invoke(s.root, 0, 0, 101, 200);
    assert.strictEqual(s.rpc.snapshot().callbacks, before);
    assert.deepStrictEqual(s.disposed.sort(), ['activity', 'root']);
    assert.strictEqual(s.originals(), 3);
  }
  {
    const s = scenario({getterThrows: true});
    assert.strictEqual((await s.rpc.arm(config())).ok, true);
    s.invoke(s.root, 0, 0, 101, 200);
    assert.strictEqual(s.originals(), 1);
    assert.strictEqual(s.rpc.snapshot().fault, 'ENTRY_CAPTURE_FAILED');
    assert.strictEqual(s.rpc.snapshot().events.length, 0);
    assert.strictEqual((await s.rpc.disarm()).ok, true);
  }
  {
    const s = scenario({identityThrows: true});
    assert.strictEqual((await s.rpc.arm(config())).ok, false);
    assert.strictEqual(s.method.implementation, null);
    assert.strictEqual(s.originals(), 0);
  }
  {
    const s = scenario({identityThrowsOnEntry: true});
    assert.strictEqual((await s.rpc.arm(config())).ok, true);
    s.invoke(s.root, 0, 0, 101, 200);
    assert.strictEqual(s.originals(), 1);
    assert.strictEqual(s.rpc.snapshot().fault, 'ENTRY_CAPTURE_FAILED');
    assert.strictEqual((await s.rpc.disarm()).ok, true);
  }
  {
    const s = scenario({originalThrows: true});
    assert.strictEqual((await s.rpc.arm(config())).ok, true);
    assert.throws(() => s.invoke(s.root, 0, 0, 101, 200), /original Java failure/);
    assert.strictEqual(s.originals(), 1);
    assert.strictEqual(s.rpc.snapshot().fault, 'ORIGINAL_THROWN');
    assert.strictEqual(s.rpc.snapshot().events[0].originalReturned, false);
    assert.strictEqual((await s.rpc.disarm()).ok, true);
  }
  {
    const s = scenario({multipleActivities: true});
    assert.strictEqual((await s.rpc.arm(config())).code,
      'ACTIVITY_SELECTION_FAILED');
    assert.strictEqual(s.method.implementation, null);
    assert.strictEqual((await s.rpc.arm(config())).code, 'ALREADY_USED');
  }
  {
    const s = scenario({wrongActivityToken: true});
    const result = await s.rpc.arm(config());
    assert.strictEqual(result.code, 'ARM_FAILED');
    assert.strictEqual(s.method.implementation, null);
    assert.deepStrictEqual(s.disposed, ['activity']);
  }
  {
    const s = scenario({chooseThrowsAfterComplete: true});
    const result = await s.rpc.arm(config());
    assert.strictEqual(result.code, 'CHOOSE_FAILED');
    assert.strictEqual(s.method.implementation, null);
    assert.deepStrictEqual(s.disposed, ['activity']);
  }
  {
    const s = scenario({disarmInsideOriginal: true});
    assert.strictEqual((await s.rpc.arm(config())).ok, true);
    s.invoke(s.root, 0, 0, 101, 200);
    assert.strictEqual((await s.inFlightDisarm()).code, 'DISARM_UNSAFE');
    assert.notStrictEqual(s.method.implementation, null);
    assert.strictEqual((await s.rpc.disarm()).ok, true);
  }
  {
    const s = scenario({revertThrows: true});
    assert.strictEqual((await s.rpc.arm(config())).ok, true);
    const disarm = await s.rpc.disarm();
    assert.strictEqual(disarm.ok, false);
    assert.strictEqual(disarm.cleanupCertain, false);
    assert.strictEqual(s.rpc.snapshot().phase, 'UNCERTAIN');
  }
  {
    const s = scenario({disarmPerformReentry: true});
    assert.strictEqual((await s.rpc.arm(config())).ok, true);
    const disarm = await s.rpc.disarm();
    assert.strictEqual(disarm.code, 'DISARM_IN_FLIGHT');
    assert.strictEqual(s.originals(), 1);
    assert.notStrictEqual(s.method.implementation, null);
  }
  {
    const s = scenario({revertCallback: true});
    assert.strictEqual((await s.rpc.arm(config())).ok, true);
    const disarm = await s.rpc.disarm();
    assert.strictEqual(disarm.ok, false);
    assert.strictEqual(s.rpc.snapshot().fault, 'DISARM_RACE');
    assert.strictEqual(s.originals(), 1);
    assert.strictEqual(s.rpc.snapshot().phase, 'UNCERTAIN');
  }
  {
    const s = scenario();
    const invalid = config(); invalid.pid = 0;
    assert.strictEqual((await s.rpc.arm(invalid)).code, 'ADMISSION_FAILED');
    assert.strictEqual(s.method.implementation, null);
  }
  console.log('layout_entry_observer: 13 deterministic cases PASS');
}

tests().catch(error => { console.error(error); process.exitCode = 1; });
