'use strict';
// Offline T014 groundwork only: no native listener, pairing, timers or IO.
// A future view-scoped bridge must stamp events with its owning activation ID
// AND document ID; change activation before any routing-eligibility transition.
// This controller calls the existing logical navigation operation synchronously;
// it never queues a turn for later or owns page/annotation state.
// Vertical arrows are logical: Up = Previous, Down = Next, in RTL and LTR.
// Android DPAD codes are not Linux/HID scan codes; do not translate raw input here.
const DEFAULT_BINDINGS = Object.freeze({19: 'previous', 20: 'next', 21: 'left', 22: 'right', 92: 'previous', 93: 'next'});
const ALLOWED_KEYS = new Set([19, 20, 21, 22, 24, 25, 62, 66, 92, 93]);
const ACTIONS = new Set(['left', 'right', 'next', 'previous']);
const MAX_RECORDS = 32;

function bindingsCopy(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError('Invalid key bindings');
  // Keep the existing native atomic configuration's eight-key bound.
  if (Object.keys(value).length > 8) throw new TypeError('Too many page-turner bindings');
  const copied = Object.create(null);
  for (const [key, action] of Object.entries(value)) {
    if (!/^[1-9][0-9]*$/.test(key) || !ALLOWED_KEYS.has(Number(key)) || !ACTIONS.has(action)) {
      throw new TypeError('Unsupported page-turner binding');
    }
    copied[key] = action;
  }
  return Object.freeze(copied);
}

function identity(context) {
  return context && typeof context.activationId === 'string' && context.activationId.length > 0 &&
    typeof context.documentId === 'string' && context.documentId.length > 0;
}

function validEvent(event) {
  return event && typeof event === 'object' && !Array.isArray(event) &&
    typeof event.activationId === 'string' && typeof event.documentId === 'string' &&
    Number.isInteger(event.keyCode) && Number.isInteger(event.deviceId) &&
    event.deviceId >= -1 && event.deviceId <= 2147483647 &&
    Number.isSafeInteger(event.downTime) && event.downTime >= 0 &&
    Number.isInteger(event.repeatCount) && event.repeatCount >= 0 && event.repeatCount <= 2147483647 &&
    (event.action === 0 || event.action === 1);
}

function createPageTurnerKeys({currentContext, turn, bindings = DEFAULT_BINDINGS}) {
  if (typeof currentContext !== 'function' || typeof turn !== 'function') throw new TypeError('Missing key dependencies');
  const mapping = bindingsCopy(bindings);
  const records = new Map();
  let activation = null;
  let document = null;
  let retiredThrough = -1;
  let disposed = false;
  const ignored = reason => ({handled: false, reason});
  const consumed = reason => ({handled: true, reason});

  function handle(event) {
    if (disposed) return ignored('disposed');
    const context = currentContext();
    // Losing context is not permission to forget an already classified contact.
    // The bridge must publish a fresh activation when eligibility is restored.
    if (!identity(context)) return ignored('context_unavailable');
    if (activation !== context.activationId || document !== context.documentId) {
      records.clear(); retiredThrough = -1; activation = context.activationId; document = context.documentId;
    }
    if (!validEvent(event) || event.activationId !== activation || event.documentId !== document) {
      return ignored('event_unavailable');
    }
    const binding = mapping[event.keyCode];
    if (!binding) return ignored('unmapped');
    const key = `${event.deviceId}:${event.keyCode}`;
    const prior = records.get(key);
    if (event.action === 1) {
      if (!prior?.held || event.downTime !== prior.downTime) return ignored('unowned_up');
      prior.held = false;
      return consumed('released'); // Finish an owned press even if a modal/transition has since locked navigation.
    }
    if (prior && event.downTime <= prior.downTime) {
      return prior.accepted ? consumed('duplicate_or_stale') : ignored('rejected_duplicate_or_stale');
    }
    if (event.downTime <= retiredThrough) return ignored('retired_contact');
    const eligible = context.enabled === true && context.focused === true && context.blocked === false &&
      ['rtl', 'ltr'].includes(context.direction);
    const accepted = eligible && event.repeatCount === 0;
    if (!prior && records.size >= MAX_RECORDS) {
      // Evict only finished/rejected contacts. The monotonic Android uptime
      // watermark rejects their delayed duplicates without unbounded history.
      const retired = [...records].find(([, record]) => !record.held);
      if (retired) {
        retiredThrough = Math.max(retiredThrough, retired[1].downTime);
        records.delete(retired[0]);
        if (event.downTime <= retiredThrough) return ignored('retired_contact');
      } else {
        retiredThrough = Math.max(retiredThrough, event.downTime);
        return ignored('capacity');
      }
    }
    // Classify every valid mapped DOWN exactly once, including rejection while
    // a modal/focus/transition fence is closed. Rejection never owns the event.
    records.set(key, {downTime: event.downTime, held: accepted, accepted});
    if (!eligible) return ignored('inactive');
    if (!accepted) return ignored('unowned_repeat');
    // A strictly newer Android downTime also recovers a missing UP for this key,
    // without timeout-based replay. The bridge, not Bluetooth, supplies downTime.
    const action = binding === 'left' ? (context.direction === 'rtl' ? 'next' : 'previous')
      : binding === 'right' ? (context.direction === 'rtl' ? 'previous' : 'next') : binding;
    try {
      turn(action); // App must retain its existing transition guards and Single/Spread page step.
      return {handled: true, reason: 'turned', action};
    } catch (_) {
      // Never retry a callback that may already have moved the page.
      return consumed('turn_failed');
    }
  }

  return {
    handle,
    cancelContacts() { for (const record of records.values()) record.held = false; },
    dispose() { disposed = true; records.clear(); retiredThrough = -1; },
    getState() { return {disposed, records: records.size, held: [...records.values()].filter(record => record.held).length}; },
  };
}

module.exports = {DEFAULT_BINDINGS, MAX_RECORDS, createPageTurnerKeys};
