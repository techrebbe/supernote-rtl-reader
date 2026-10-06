'use strict';
const {DEFAULT_BINDINGS, createPageTurnerKeys} = require('./pageTurnerKeys');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const STATE_FIELDS = ['schemaVersion', 'kind', 'requestId', 'sequence', 'activationId',
  'documentId', 'generation', 'eligible', 'disposed'];
const KEY_FIELDS = [...STATE_FIELDS, 'action', 'keyCode', 'deviceId', 'downTime', 'repeatCount'];

function contextCopy(value, bindings) {
  if (!value || typeof value.documentId !== 'string' || !value.documentId.length || value.documentId.length > 4096 ||
      typeof value.presentationId !== 'string' || !value.presentationId.length ||
      !['rtl', 'ltr'].includes(value.direction) || typeof value.enabled !== 'boolean' || typeof value.blocked !== 'boolean') {
    throw new TypeError('Invalid reader key context');
  }
  // Reuse the reviewed controller's strict mapping validator, without routing.
  createPageTurnerKeys({currentContext: () => null, turn() {}, bindings}).dispose();
  const pairs = Object.entries(bindings).sort(([a], [b]) => Number(a) - Number(b));
  return Object.freeze({...value, bindings: Object.freeze(Object.fromEntries(pairs)),
    signature: JSON.stringify([value.documentId, value.presentationId, value.direction, value.enabled,
      value.blocked, pairs])});
}

function validEnvelope(packet) {
  if (!packet || typeof packet !== 'object' || Array.isArray(packet)) return false;
  const fields = packet.kind === 'state' ? STATE_FIELDS : packet.kind === 'key' ? KEY_FIELDS : null;
  if (!fields || Object.keys(packet).length !== fields.length || !fields.every(field => Object.hasOwn(packet, field))) return false;
  const colon = typeof packet.activationId === 'string' ? packet.activationId.lastIndexOf(':') : -1;
  return packet.schemaVersion === 1 && typeof packet.requestId === 'string' &&
    typeof packet.documentId === 'string' && Number.isSafeInteger(packet.sequence) && packet.sequence > 0 &&
    Number.isSafeInteger(packet.generation) && packet.generation > 0 && typeof packet.activationId === 'string' &&
    UUID.test(packet.activationId.slice(0, colon)) &&
    packet.activationId.slice(colon + 1) === String(packet.generation) &&
    typeof packet.eligible === 'boolean' && typeof packet.disposed === 'boolean' && !(packet.disposed && packet.eligible) &&
    (packet.kind === 'state' || (packet.eligible && !packet.disposed &&
      (packet.action === 0 || packet.action === 1) && Number.isInteger(packet.keyCode) &&
      Number.isInteger(packet.deviceId) && packet.deviceId >= -1 && packet.deviceId <= 2147483647 &&
      Number.isSafeInteger(packet.downTime) && packet.downTime >= 0 && Number.isInteger(packet.repeatCount) &&
      packet.repeatCount >= 0 && packet.repeatCount <= 2147483647));
}

/** Unwired T014 RN consumer. One native-minted namespace per mounted JS owner.
 * A complete routeSpec is committed atomically in native after the prop batch.
 * Keys NEVER receive current JS/native stamps in place of their queued stamps.
 */
function createPageTurnerTransport({namespace, currentContext, turn}) {
  if (!UUID.test(namespace) || typeof currentContext !== 'function' || typeof turn !== 'function') {
    throw new TypeError('Missing reader key transport dependencies');
  }
  let counter = 0, config = null, spec = null, state = null, controller = null;
  let instance = null, sequence = 0, generation = 0, faulted = false, disposed = false;
  const ignored = reason => ({handled: false, reason});

  function currentMatches() {
    if (!config || !spec || faulted || disposed) return false;
    const expectedConfig = config, expectedSpec = spec, expectedState = state;
    try {
      const signature = contextCopy(currentContext(), expectedConfig.bindings).signature;
      // The callback is synchronous but can reenter this owner. A fence,
      // disposal, config replacement or native state update during the read
      // must revoke the in-progress key/focus check, not merely later checks.
      return !faulted && !disposed && config === expectedConfig && spec === expectedSpec &&
        state === expectedState && signature === expectedConfig.signature;
    }
    catch (_) { return false; }
  }

  function revoke(reason) {
    faulted = true; state = null; controller?.dispose(); controller = null;
    return ignored(reason);
  }

  function configure(context, bindings = DEFAULT_BINDINGS, force = false) {
    if (disposed) throw new Error('Disposed key transport');
    const next = contextCopy(context, bindings);
    if (!force && !faulted && config?.signature === next.signature) return spec;
    if (counter === Number.MAX_SAFE_INTEGER) throw new Error('Request identity exhausted');
    controller?.dispose(); controller = null; state = null; faulted = false;
    config = next;
    spec = Object.freeze({requestId: `${namespace}:${++counter}`, documentId: next.documentId,
      enabled: next.enabled && !next.blocked, keyCodes: Object.freeze(Object.keys(next.bindings).map(Number))});
    controller = createPageTurnerKeys({bindings: next.bindings,
      currentContext: () => ({activationId: state?.activationId, documentId: spec.documentId,
        direction: config.direction, enabled: spec.enabled, focused: state?.eligible === true,
        blocked: !currentMatches()}), turn});
    return spec;
  }

  function handle(packet) {
    if (disposed || !spec || faulted) return ignored('transport_unavailable');
    // Stale packets do not replace state, clear a fence, or consume sequence.
    if (packet?.requestId !== spec.requestId) return ignored('stale_request');
    if (!validEnvelope(packet) || packet.documentId !== spec.documentId || packet.eligible && !spec.enabled) {
      return revoke('malformed_envelope');
    }
    const nativeInstance = packet.activationId.slice(0, packet.activationId.lastIndexOf(':'));
    if (instance !== null && nativeInstance !== instance) return revoke('native_instance_changed');
    if (packet.sequence <= sequence) return revoke('stream_replay');
    if (state === null) {
      // The first state for a NEW configuration anchors the continuing native
      // stream after ignored old-request packets. A key cannot establish it.
      if (packet.kind !== 'state' || packet.generation <= generation) return revoke('missing_configuration_state');
    } else if (packet.sequence !== sequence + 1) return revoke('stream_gap');
    if (packet.kind === 'state') {
      if (packet.generation <= generation) return revoke('generation_replay');
      instance = nativeInstance; sequence = packet.sequence; generation = packet.generation; state = Object.freeze({...packet});
      controller.cancelContacts();
      if (packet.disposed) return revoke('native_disposed');
      return ignored(packet.eligible ? 'native_ready' : 'native_inactive');
    }
    if (!state.eligible || packet.activationId !== state.activationId || packet.generation !== generation) {
      return revoke('key_without_current_state');
    }
    sequence = packet.sequence;
    return controller.handle(packet);
  }

  return {configure, handle,
    // Used for synchronous UI fences BEFORE effects/native prop commits. A new
    // configure is required; an old queued state can never rearm this owner.
    fence() { state = null; controller?.dispose(); controller = null; faulted = true; },
    focusRequest() { return currentMatches() && spec.enabled ? spec.requestId : null; },
    dispose() { disposed = true; state = null; controller?.dispose(); controller = null; },
    getState() { return {requestId: spec?.requestId, activationId: state?.activationId,
      sequence, generation, faulted, disposed, eligible: state?.eligible === true}; },
  };
}

module.exports = {createPageTurnerTransport};
