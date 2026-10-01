'use strict';
// Read-only T006 saved-handwriting orchestration. No writer/save/handoff calls.
// The native module owns source SHA, .mark snapshots, immutable PNG decoding and
// token-only bitmap publication. This alpha is deliberately ONLY T004 PAGE 3.
// Unsupported pages are unavailable, never asserted to contain no annotations.

const FIXTURE_NAME = 'RTL_RAPID_TOOLS_T004_20261001.pdf';
const PAGE_INDEX = 2;
const TOTAL_PAGES = 8;
const WIDTH = 1404;
const HEIGHT = 1872;
const MAX_PNG_BYTES = 16 * 1024 * 1024;
const MISSING_MARK_CODE = 1302;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;

// Ownership outlives React components. Old pending work or failed cleanup must
// not overlap a remount's renderer call. App cleanup awaits dispose() before a
// replacement run; a forgotten/failed cleanup remains visibly unavailable.
const sharedOwnership = {owner: null};

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function validAbsolutePath(value) {
  return typeof value === 'string' && value.length > 1 && value.length <= 4096 &&
    value.startsWith('/') && !/[\\\u0000-\u001f]/.test(value) &&
    !value.includes('//') && !value.split('/').some(part => part === '.' || part === '..');
}

function validPluginDir(value) {
  return validAbsolutePath(value) && !value.endsWith('/') &&
    /^\/data\/(?:data\/|user\/\d+\/)/.test(value);
}

function supportedContext(value) {
  return isRecord(value) && validAbsolutePath(value.filePath) &&
    value.filePath.endsWith(`/${FIXTURE_NAME}`) && value.pageIndex === PAGE_INDEX &&
    value.totalPages === TOTAL_PAGES && validPluginDir(value.pluginDir);
}

function sameContext(actual, expected) {
  return supportedContext(actual) && actual.filePath === expected.filePath &&
    actual.pageIndex === expected.pageIndex && actual.totalPages === expected.totalPages &&
    actual.pluginDir === expected.pluginDir;
}

function isToken(value) {
  return typeof value === 'string' && UUID.test(value);
}

function validOutputPath(value, token, pluginDir) {
  return validAbsolutePath(value) && value.startsWith(`${pluginDir}/`) &&
    value.endsWith(`/${token}/ink.png`);
}

function fault(reason) {
  const error = new Error(reason);
  error.savedInkReason = reason;
  return error;
}

function createSavedInkController(deps) {
  for (const name of ['prepare', 'finish', 'discard', 'generateThumbnail', 'currentContext']) {
    if (typeof deps?.[name] !== 'function') throw new TypeError(`Missing saved ink dependency: ${name}`);
  }
  const state = {busy: false, disposed: false, retained: null};
  let epoch = 0;
  let pending = null;
  let disposePromise = null;

  function releaseOwnership() {
    if (!state.busy && !state.retained && sharedOwnership.owner === state) sharedOwnership.owner = null;
  }

  function blocked() {
    if (state.disposed) return {status: 'unavailable', reason: 'disposed'};
    if (state.busy) return {status: 'unavailable', reason: 'busy'};
    if (state.retained) return {status: 'unavailable', reason: 'ink_retained'};
    if (sharedOwnership.owner && sharedOwnership.owner !== state) {
      return {status: 'unavailable', reason: 'ownership_pending'};
    }
    return null;
  }

  function start(work) {
    state.busy = true;
    sharedOwnership.owner = state;
    const result = Promise.resolve().then(work).finally(() => {
      state.busy = false;
      pending = null;
      releaseOwnership();
    });
    pending = result;
    return result;
  }

  async function requireCurrent(context, requestEpoch) {
    const current = await deps.currentContext();
    if (requestEpoch !== epoch || state.disposed) throw fault('cancelled');
    if (!sameContext(current, context)) throw fault('context_changed');
  }

  async function discardToken(token) {
    const result = await deps.discard({token});
    if (!isRecord(result) || result.token !== token || result.discarded !== true) {
      throw fault('cleanup_failed');
    }
  }

  function retain(token) {
    state.retained = Object.freeze({token});
    return state.retained;
  }

  async function execute(context, requestEpoch) {
    let token = null;
    let cleanupAttempted = false;
    let stage = 'context';
    try {
      await requireCurrent(context, requestEpoch);
      stage = 'prepare';
      const prepared = await deps.prepare({
        filePath: context.filePath, pageIndex: context.pageIndex,
        width: WIDTH, height: HEIGHT, pluginDir: context.pluginDir,
      });
      // A valid issued token stays cleanup-owned even if other fields are invalid.
      if (isRecord(prepared) && isToken(prepared.token)) token = prepared.token;
      if (!token || !isRecord(prepared) || prepared.sourceVerified !== true ||
          prepared.filePath !== context.filePath || prepared.pageIndex !== PAGE_INDEX ||
          prepared.width !== WIDTH || prepared.height !== HEIGHT ||
          !validOutputPath(prepared.pngPath, token, context.pluginDir)) {
        throw fault('prepare_invalid');
      }
      const pngPath = prepared.pngPath;
      await requireCurrent(context, requestEpoch);
      stage = 'generate';
      // Never timeout and remove an output while the API could still write it.
      // Cancellation suppresses publication; cleanup waits for real settlement.
      const api = await deps.generateThumbnail(context.filePath, PAGE_INDEX, pngPath, {width: WIDTH, height: HEIGHT});
      await requireCurrent(context, requestEpoch);
      const generated = isRecord(api) && api.success === true && api.result === true;
      const missingMark = isRecord(api) && api.success === false &&
        isRecord(api.error) && api.error.code === MISSING_MARK_CODE;
      if (!generated && !missingMark) throw fault('generation_failed');
      stage = 'finish';
      const checked = await deps.finish({token, missingMark});
      await requireCurrent(context, requestEpoch);
      if (!isRecord(checked) || checked.token !== token ||
          checked.filePath !== context.filePath || checked.pageIndex !== PAGE_INDEX ||
          checked.sourceUnchanged !== true || checked.markUnchanged !== true) {
        throw fault('finish_invalid');
      }
      if (missingMark) {
        if (checked.missingMark !== true) throw fault('finish_invalid');
        stage = 'cleanup';
        cleanupAttempted = true;
        await discardToken(token);
        token = null;
        await requireCurrent(context, requestEpoch);
        return {status: 'no_page', reason: 'missing_mark_page', evidence: Object.freeze({...checked})};
      }
      if (checked.missingMark === true || checked.pngPath !== pngPath ||
          checked.width !== WIDTH || checked.height !== HEIGHT || checked.decoded !== true ||
          !isToken(checked.savedInkToken) || checked.savedInkToken !== token ||
          typeof checked.sha256 !== 'string' || !SHA256.test(checked.sha256) ||
          !Number.isInteger(checked.byteLength) || checked.byteLength <= 0 || checked.byteLength > MAX_PNG_BYTES ||
          !Number.isInteger(checked.alphaMin) || !Number.isInteger(checked.alphaMax) ||
          checked.alphaMin < 0 || checked.alphaMax > 255 || checked.alphaMin > checked.alphaMax) {
        throw fault('finish_invalid');
      }
      const handle = retain(token);
      token = null;
      return {status: 'ready', savedInkToken: handle.token, handle, evidence: Object.freeze({...checked})};
    } catch (error) {
      const reason = typeof error?.savedInkReason === 'string' ? error.savedInkReason : `${stage}_failed`;
      if (token) {
        if (cleanupAttempted) return {status: 'error', reason: 'cleanup_failed', causeReason: reason, handle: retain(token)};
        try {
          await discardToken(token);
        } catch (_) {
          return {status: 'error', reason: 'cleanup_failed', causeReason: reason, handle: retain(token)};
        }
      }
      return {status: ['cancelled', 'context_changed'].includes(reason) ? 'unavailable' : 'error', reason};
    }
  }

  function run(context) {
    const obstruction = blocked();
    if (obstruction) return Promise.resolve(obstruction);
    if (!supportedContext(context)) return Promise.resolve({status: 'unavailable', reason: 'unsupported_context'});
    // Caller/dependencies cannot mutate the authority snapshot while awaiting.
    const expected = Object.freeze({
      filePath: context.filePath, pageIndex: context.pageIndex,
      totalPages: context.totalPages, pluginDir: context.pluginDir,
    });
    const requestEpoch = ++epoch;
    return start(() => execute(expected, requestEpoch));
  }

  function release(handle = state.retained) {
    if (state.busy) return Promise.resolve({status: 'unavailable', reason: 'busy'});
    if (!state.retained) return Promise.resolve({status: 'released'});
    if (handle !== state.retained) return Promise.resolve({status: 'error', reason: 'unknown_handle'});
    return start(async () => {
      try {
        await discardToken(state.retained.token);
        state.retained = null;
        return {status: 'released'};
      } catch (_) {
        return {status: 'error', reason: 'cleanup_failed', handle: state.retained};
      }
    });
  }

  function dispose() {
    if (disposePromise) return disposePromise;
    state.disposed = true;
    epoch += 1;
    // Waiting, not racing, is essential: the SDK may still own the PNG writer.
    disposePromise = (async () => {
      if (pending) await pending;
      const result = await release();
      return result.status === 'released' ? {status: 'disposed'} : result;
    })();
    return disposePromise;
  }

  return {
    run, release, dispose,
    // Call on EVERY visible-document/page transition, including away/back ABA.
    // The caller must hide a published token immediately, before async disposal.
    cancel() { epoch += 1; },
    getState() { return {busy: state.busy, disposed: state.disposed, retained: state.retained !== null}; },
  };
}

module.exports = {
  FIXTURE_NAME, PAGE_INDEX, TOTAL_PAGES, WIDTH, HEIGHT, MAX_PNG_BYTES,
  supportedContext, createSavedInkController,
};
