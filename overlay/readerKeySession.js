'use strict';
const {createPageTurnerTransport} = require('./pageTurnerTransport');
const {DEFAULT_BINDINGS} = require('./pageTurnerKeys');

const KEY_PROFILES = Object.freeze({
  navigation: DEFAULT_BINDINGS,
  volume: Object.freeze({24: 'next', 25: 'previous'}),
  volume_reversed: Object.freeze({24: 'previous', 25: 'next'}),
});

// One mounted pageArea owner. No document/page authority or native-reader hook.
// Transport failures latch until this owner is unmounted; ordinary UI fences
// require a new configuration but do not silently revive a failed transport.
function createReaderKeySession({namespace, currentContext, turn, publishSpec, focus, status}) {
  let disposed = false, failed = false, fenced = false, signature = null, fenceRevision = 0;
  let activeContext = null, activeBindings = null;
  const transport = createPageTurnerTransport({namespace, currentContext, turn});
  const report = value => { if (!disposed) status(value); };
  function fail(reason) {
    if (failed || disposed) return;
    failed = true;
    // Retire native focus/consumption as well as JS authority. This is a new
    // complete OFF configuration, not retrying a failed key or resetting IDs.
    if (activeContext) {
      try { publishSpec(transport.configure({...activeContext, enabled: false, blocked: true}, activeBindings, true)); }
      catch (_) { /* Native dispatch failures already terminally drop Host. */ }
    }
    transport.fence();
    report(`Unavailable: ${reason}. Close and reopen RTL Reader to retry.`);
  }
  function synchronize() {
    if (disposed || failed) return;
    try {
      const context = currentContext();
      const bindings = KEY_PROFILES[context.profile];
      if (!bindings) throw new Error('invalid key profile');
      const next = JSON.stringify([context, bindings]);
      if (signature === next && !transport.getState().faulted) return;
      const spec = transport.configure(context, bindings);
      activeContext = {...context}; activeBindings = bindings; fenced = false;
      signature = next;
      publishSpec(spec);
      report(!context.enabled ? 'Off' : context.blocked ? 'Paused' : 'Waiting for reader focus');
    } catch (error) { fail(error?.message ?? 'configuration failed'); }
  }
  function requestFocus() {
    if (disposed || failed) return;
    const requestId = transport.focusRequest();
    if (requestId) {
      try { focus(requestId); } catch (_) { fail('native focus command failed'); }
    }
  }
  function handle(packet) {
    if (disposed || failed) return {handled: false, reason: 'session_unavailable'};
    if (fenced) return {handled: false, reason: 'ui_fenced'};
    const beforeFence = fenceRevision;
    const result = transport.handle(packet);
    // The sole page owner fences synchronously inside an accepted turn. That
    // expected fence is not a transport failure and cannot be rearmed here.
    if (beforeFence !== fenceRevision) return result;
    if (transport.getState().faulted) fail(result.reason);
    else if (result.reason === 'native_ready') report('Ready');
    else if (result.reason === 'native_inactive') {
      report(activeContext?.enabled && !activeContext.blocked ? 'Waiting for reader focus' : activeContext?.enabled ? 'Paused' : 'Off');
      requestFocus();
    }
    return result;
  }
  return {synchronize, handle, requestFocus,
    fence() { if (!disposed && !failed) { fenceRevision++; fenced = true; transport.fence(); report('Paused'); } },
    dispose() { disposed = true; transport.dispose(); },
    getState() { return {...transport.getState(), failed, disposed}; },
  };
}

module.exports = {KEY_PROFILES, createReaderKeySession};
