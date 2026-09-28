'use strict';

// Synthetic emulator trial only. This replaces ViewGroup.layout process-wide
// while armed. The disposable app, never this script, owns restoration.
(function () {
  const ACTIVITY = 'com.techrebbe.supernote.layoutfencetrial.TrialActivity';
  const ROOT = 'com.techrebbe.supernote.layoutfencetrial.TrialRoot';
  const VIEW_GROUP = 'android.view.ViewGroup';
  const MAX_EVENTS = 16;
  const MAX_CALLBACKS = 4096;
  const state = {
    phase: 'NEW', fault: null, activity: null, root: null, layout: null,
    mainTid: null, callbacks: 0, activeCallbacks: 0, targetDepth: 0,
    forwardAttempts: 0, targetEntries: 0, events: [], hookRemoved: false
  };

  function fault(code) { if (state.fault === null) state.fault = code; }
  function integer(value) {
    return typeof value === 'number' && Number.isSafeInteger(value) &&
      value >= -2147483648 && value <= 2147483647 && !Object.is(value, -0);
  }
  function decimal(value) {
    const text = String(value);
    if (!/^(0|[1-9][0-9]{0,18})$/.test(text)) throw new Error('COUNTER_INVALID');
    return text;
  }
  function token(value) {
    return typeof value === 'string' && value.length > 0 && value.length <= 128 &&
      /^[A-Za-z0-9._:-]+$/.test(value);
  }
  function configValid(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value) &&
      Object.keys(value).sort().join(',') ===
        'activityToken,incarnation,pid,rootToken,schemaVersion' &&
      value.schemaVersion === 1 && integer(value.pid) && value.pid > 0 &&
      token(value.incarnation) && token(value.activityToken) && token(value.rootToken);
  }
  function dispose(ref) {
    if (ref === null) return true;
    try { ref.$dispose(); return true; } catch (_) { return false; }
  }
  function releaseRefs() {
    const root = state.root, activity = state.activity;
    state.root = null; state.activity = null;
    const rootOk = dispose(root), activityOk = dispose(activity);
    if (!rootOk || !activityOk) fault('REF_DISPOSE_FAILED');
    return rootOk && activityOk;
  }
  function snapshot() {
    return {
      phase: state.phase, fault: state.fault,
      hookRemoved: state.hookRemoved,
      callbacks: state.callbacks, activeCallbacks: state.activeCallbacks,
      forwardAttempts: state.forwardAttempts, targetEntries: state.targetEntries,
      events: state.events.map(event => ({...event,
        oldBounds: event.oldBounds.slice(), proposedBounds: event.proposedBounds.slice()}))
    };
  }
  function capture(receiver, left, top, right, bottom) {
    const env = globalThis.Java.vm.getEnv();
    if (!env || typeof env.isSameObject !== 'function') throw new Error('NO_JNI');
    const same = env.isSameObject(receiver.$h, state.root.$h);
    if (typeof same !== 'boolean') throw new Error('IDENTITY_INVALID');
    if (!same) return null;
    if (Process.getCurrentThreadId() !== state.mainTid) {
      fault('TARGET_NOT_MAIN');
    }
    if (state.targetDepth !== 0) fault('TARGET_REENTRY');
    state.targetEntries++;
    if (state.targetEntries > MAX_EVENTS) {
      fault('TARGET_LIMIT');
      return null;
    }
    const oldBounds = [receiver.getLeft(), receiver.getTop(),
      receiver.getRight(), receiver.getBottom()];
    const proposedBounds = [left, top, right, bottom];
    if (!oldBounds.every(integer) || !proposedBounds.every(integer)) {
      throw new Error('BOUNDS_INVALID');
    }
    const event = {
      ordinal: state.targetEntries,
      oldBounds, proposedBounds,
      parentRevision: decimal(state.root.getParentPreCallRevision()),
      observedWriteOrdinal: decimal(state.root.getObservedWriteOrdinal()),
      layoutCallsBefore: decimal(state.root.getLayoutCallCount()),
      paintCountBefore: decimal(state.root.getCompletedPaintCount()),
      mainThread: Process.getCurrentThreadId() === state.mainTid,
      originalReturned: false
    };
    return event;
  }
  function hookedLayout(left, top, right, bottom) {
    // Observation is entirely best-effort; neither a failed predicate nor a
    // failed getter may prevent the single original call below.
    state.callbacks++;
    state.activeCallbacks++;
    if (state.callbacks > MAX_CALLBACKS) fault('CALLBACK_LIMIT');
    let event = null, target = false, returned = false;
    try {
      event = capture(this, left, top, right, bottom);
      target = event !== null;
      if (target) state.targetDepth++;
    } catch (_) { fault('ENTRY_CAPTURE_FAILED'); }
    try {
      state.forwardAttempts++;
      const result = state.layout.call(this, left, top, right, bottom);
      returned = true;
      return result;
    } finally {
      // No send(), logging, Java getter, or view mutation in this callback.
      try {
        if (target) {
          event.originalReturned = returned;
          if (state.events.length < MAX_EVENTS) state.events.push(event);
          else fault('EVENT_LIMIT');
          state.targetDepth--;
        }
        if (!returned) fault('ORIGINAL_THROWN');
      } catch (_) { fault('POST_FORWARD_FAILED'); }
      state.activeCallbacks--;
    }
  }
  function armOnMain(config, resolve) {
    if (state.phase !== 'ARMING') return;
    let hookMayBeInstalled = false;
    try {
      state.mainTid = Process.getCurrentThreadId();
      if (state.activity.$className !== ACTIVITY ||
          state.activity.getActivityToken() !== config.activityToken) {
        throw new Error('ACTIVITY_TOKEN_MISMATCH');
      }
      const root = state.activity.getTrialRoot();
      if (!root || root.$className !== ROOT || !root.$h ||
          root.getRootToken() !== config.rootToken ||
          root.isAttachedToWindow() !== true) throw new Error('ROOT_MISMATCH');
      state.root = globalThis.Java.retain(root);
      if (!state.root || !state.root.$h ||
          typeof state.root.$dispose !== 'function' ||
          globalThis.Java.vm.getEnv().isSameObject(root.$h, state.root.$h) !== true) {
        throw new Error('ROOT_RETAIN_FAILED');
      }
      const ViewGroup = globalThis.Java.use(VIEW_GROUP);
      state.layout = ViewGroup.layout.overload('int', 'int', 'int', 'int');
      if (state.layout.implementation !== null) throw new Error('HOOK_OCCUPIED');
      hookMayBeInstalled = true;
      state.layout.implementation = hookedLayout;
      if (state.layout.implementation === null) throw new Error('HOOK_NOT_INSTALLED');
      state.phase = 'ARMED';
      resolve({ok: true, phase: 'ARMED', hookInstalled: true,
        pid: config.pid, rootToken: config.rootToken});
    } catch (_) {
      fault('ARM_FAILED');
      let removed = !hookMayBeInstalled;
      if (hookMayBeInstalled && state.layout !== null) {
        try {
          state.layout.implementation = null;
          removed = state.layout.implementation === null;
        } catch (_) { removed = false; }
      }
      state.hookRemoved = removed;
      if (!releaseRefs()) removed = false;
      state.phase = removed ? 'FAILED' : 'UNCERTAIN';
      resolve({ok: false, phase: state.phase, code: 'ARM_FAILED',
        cleanupCertain: removed});
    }
  }
  rpc.exports = {
    arm(config) {
      if (state.phase !== 'NEW') return Promise.resolve({ok: false,
        phase: state.phase, code: 'ALREADY_USED', cleanupCertain: state.hookRemoved});
      state.phase = 'ARMING';
      if (!configValid(config) || Process.id !== config.pid ||
          !globalThis.Java || globalThis.Java.available !== true) {
        state.phase = 'FAILED'; state.hookRemoved = true;
        return Promise.resolve({ok: false, phase: state.phase,
          code: 'ADMISSION_FAILED', cleanupCertain: true});
      }
      return new Promise(resolve => {
        let performReturned = false, chooseReturned = false;
        let completed = false, scheduled = false, cancelled = false;
        let candidates = 0, chooseFailed = false;
        function rejectArm(code, uncertain) {
          if (cancelled) return;
          cancelled = true;
          fault(code);
          const clean = releaseRefs();
          state.hookRemoved = !uncertain;
          state.phase = clean && !uncertain ? 'FAILED' : 'UNCERTAIN';
          resolve({ok: false, phase: state.phase, code,
            cleanupCertain: clean && !uncertain});
        }
        function finishChoose() {
          if (!performReturned || !chooseReturned || !completed ||
              cancelled || scheduled) return;
          scheduled = true;
          if (chooseFailed || candidates !== 1 || !state.activity) {
            rejectArm('ACTIVITY_SELECTION_FAILED', false);
            return;
          }
          try {
            globalThis.Java.scheduleOnMainThread(() => armOnMain(config, resolve));
          } catch (_) { rejectArm('MAIN_SCHEDULE_FAILED', false); }
        }
        try {
          globalThis.Java.perform(function () {
            try {
              globalThis.Java.choose(ACTIVITY, {
                onMatch(candidate) {
                  if (completed || chooseFailed || cancelled) return 'stop';
                  candidates++;
                  if (candidates !== 1) return 'stop';
                  try { state.activity = globalThis.Java.retain(candidate); }
                  catch (_) { chooseFailed = true; return 'stop'; }
                  return undefined;
                },
                onComplete() {
                  if (completed) return;
                  completed = true;
                  finishChoose();
                }
              });
              chooseReturned = true;
              finishChoose();
            } catch (_) {
              rejectArm('CHOOSE_FAILED', false);
            }
          });
          performReturned = true;
          finishChoose();
        } catch (_) {
          rejectArm('JAVA_PERFORM_FAILED', true);
        }
      });
    },
    snapshot() { return snapshot(); },
    disarm() {
      if (state.phase !== 'ARMED' || state.activeCallbacks !== 0 ||
          state.layout === null) return Promise.resolve({ok: false,
            phase: state.phase, code: 'DISARM_UNSAFE', cleanupCertain: false});
      return new Promise(resolve => {
        try {
          globalThis.Java.perform(function () {
            if (state.activeCallbacks !== 0) {
              fault('DISARM_IN_FLIGHT');
              state.phase = 'UNCERTAIN';
              resolve({ok: false, phase: state.phase,
                code: 'DISARM_IN_FLIGHT', cleanupCertain: false,
                callbacks: state.callbacks, forwardAttempts: state.forwardAttempts});
              return;
            }
            const callbacksBefore = state.callbacks;
            const forwardsBefore = state.forwardAttempts;
            state.phase = 'DISARMING';
            let removed = false;
            try {
              state.layout.implementation = null;
              removed = state.layout.implementation === null;
            } catch (_) { removed = false; }
            state.hookRemoved = removed;
            const quiescent = state.activeCallbacks === 0 &&
              state.callbacks === callbacksBefore &&
              state.forwardAttempts === forwardsBefore;
            if (!quiescent) fault('DISARM_RACE');
            const refsGone = removed && quiescent && releaseRefs();
            state.phase = removed && quiescent && refsGone ? 'DISARMED' : 'UNCERTAIN';
            resolve({ok: state.phase === 'DISARMED', phase: state.phase,
              code: state.phase === 'DISARMED' ? 'DISARMED' : 'REVERT_UNCERTAIN',
              cleanupCertain: state.phase === 'DISARMED',
              callbacks: state.callbacks, forwardAttempts: state.forwardAttempts});
          });
        } catch (_) {
          state.phase = 'UNCERTAIN';
          resolve({ok: false, phase: state.phase,
            code: 'DISARM_FAILED', cleanupCertain: false});
        }
      });
    }
  };
})();
