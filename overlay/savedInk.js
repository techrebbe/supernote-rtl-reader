'use strict';
// Read-only T006 saved-handwriting orchestration. No writer/save/handoff calls.
// The native module owns source SHA, .mark snapshots, immutable PNG decoding and
// token-only bitmap publication. This alpha is limited to two vetted fixtures.
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
const PROFILES = Object.freeze([
  Object.freeze({
    id: 't004-page3-canvas-v1',
    filePath: `/storage/emulated/0/Document/${FIXTURE_NAME}`,
    sourceSha256: 'ffb6c3b889ed455841d3c4f50a0813d844109c3c97255b4bbb5e4b949c9592c9',
    pageIndex: PAGE_INDEX, totalPages: TOTAL_PAGES, needsCanvasWitness: false,
  }),
  Object.freeze({
    id: 't008-page1-stock-portrait-fit-v1',
    filePath: '/storage/emulated/0/Document/RTL_INK_GEOMETRY_T008_20261002.pdf',
    sourceSha256: 'bd0fd00b4879cedb1b768a19deb2901a6d50dc7373decc8ef60e445613d83e64',
    pageIndex: 0, totalPages: 2, needsCanvasWitness: true,
  }),
  Object.freeze({
    id: 't008-page2-stock-portrait-fit-v1',
    filePath: '/storage/emulated/0/Document/RTL_INK_GEOMETRY_T008_20261002.pdf',
    sourceSha256: 'bd0fd00b4879cedb1b768a19deb2901a6d50dc7373decc8ef60e445613d83e64',
    pageIndex: 1, totalPages: 2, needsCanvasWitness: true,
  }),
]);

// UI eligibility, not native source/geometry authority. Native verifies bytes.
function selectSavedInkProfile(filePath, totalPages, pageIndex) {
  return PROFILES.find(profile => profile.filePath === filePath && profile.totalPages === totalPages &&
    (pageIndex === undefined || pageIndex === profile.pageIndex)) ?? null;
}

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
  if (!isRecord(value) || !validPluginDir(value.pluginDir)) return false;
  const profile = selectSavedInkProfile(value.filePath, value.totalPages, value.pageIndex);
  return profile !== null && value.pageIndex === profile.pageIndex;
}

function sameContext(actual, expected) {
  return supportedContext(actual) && actual.filePath === expected.filePath &&
    actual.pageIndex === expected.pageIndex && actual.totalPages === expected.totalPages &&
    actual.pluginDir === expected.pluginDir;
}

function supportedBatchContext(value) {
  return isRecord(value) && validPluginDir(value.pluginDir) && Array.isArray(value.pageIndices) &&
    value.pageIndices.length >= 1 && value.pageIndices.length <= 2 &&
    new Set(value.pageIndices).size === value.pageIndices.length && value.pageIndices.every(pageIndex => {
      if (!Number.isInteger(pageIndex)) return false;
      const profile = selectSavedInkProfile(value.filePath, value.totalPages, pageIndex);
      return profile?.needsCanvasWitness === true;
    });
}

function sameBatchContext(actual, expected) {
  return supportedBatchContext(actual) && actual.filePath === expected.filePath &&
    actual.totalPages === expected.totalPages && actual.pluginDir === expected.pluginDir &&
    actual.pageIndices.length === expected.pageIndices.length &&
    actual.pageIndices.every((page, index) => page === expected.pageIndices[index]);
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
  const state = {busy: false, disposed: false, retained: new Map()};
  let epoch = 0;
  let pending = null;
  let disposePromise = null;

  function releaseOwnership() {
    if (!state.busy && state.retained.size === 0 && sharedOwnership.owner === state) sharedOwnership.owner = null;
  }

  function blocked() {
    if (state.disposed) return {status: 'unavailable', reason: 'disposed'};
    if (state.busy) return {status: 'unavailable', reason: 'busy'};
    if (state.retained.size) return {status: 'unavailable', reason: 'ink_retained'};
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

  async function requireBatchCurrent(context, requestEpoch) {
    const current = await deps.currentContext();
    if (requestEpoch !== epoch || state.disposed) throw fault('cancelled');
    if (!sameBatchContext(current, context)) throw fault('context_changed');
  }

  async function discardToken(token) {
    const result = await deps.discard({token});
    if (!isRecord(result) || result.token !== token || result.discarded !== true) {
      throw fault('cleanup_failed');
    }
  }

  function retain(token) {
    if (!state.retained.has(token)) state.retained.set(token, Object.freeze({token}));
    return state.retained.get(token);
  }

  async function execute(context, requestEpoch, batch = null, siblingToken = null) {
    let token = null;
    let cleanupAttempted = false;
    let stage = 'context';
    try {
      const profile = selectSavedInkProfile(context.filePath, context.totalPages, context.pageIndex);
      const requireLive = () => batch ? requireBatchCurrent(batch, requestEpoch) : requireCurrent(context, requestEpoch);
      await requireLive();
      const requireCanvas = async () => {
        if (!profile.needsCanvasWitness) return;
        stage = 'canvas';
        if (typeof deps.getPageSize !== 'function') throw fault('canvas_unavailable');
        const size = await deps.getPageSize(context.filePath, context.pageIndex);
        await requireLive();
        if (!isRecord(size) || size.success !== true || !isRecord(size.result) ||
            size.result.width !== WIDTH || size.result.height !== HEIGHT) {
          throw fault('canvas_mismatch');
        }
      };
      await requireCanvas();
      stage = 'prepare';
      const prepared = await deps.prepare({
        profileId: profile.id,
        filePath: context.filePath, pageIndex: context.pageIndex,
        width: WIDTH, height: HEIGHT, pluginDir: context.pluginDir,
        ...(siblingToken === null ? {} : {siblingToken}),
      });
      // A valid issued token stays cleanup-owned even if other fields are invalid.
      if (isRecord(prepared) && isToken(prepared.token)) {
        if (state.retained.has(prepared.token)) throw fault('duplicate_token');
        token = prepared.token;
      }
      if (!token || !isRecord(prepared) || prepared.sourceVerified !== true ||
          prepared.filePath !== context.filePath || prepared.pageIndex !== context.pageIndex ||
          prepared.profileId !== profile.id || prepared.geometryId !== profile.id ||
          prepared.sourceSha256 !== profile.sourceSha256 || prepared.pageCount !== context.totalPages ||
          prepared.width !== WIDTH || prepared.height !== HEIGHT ||
          !validOutputPath(prepared.pngPath, token, context.pluginDir)) {
        throw fault('prepare_invalid');
      }
      const pngPath = prepared.pngPath;
      await requireLive();
      stage = 'generate';
      // Never timeout and remove an output while the API could still write it.
      // Cancellation suppresses publication; cleanup waits for real settlement.
      const api = await deps.generateThumbnail(context.filePath, context.pageIndex, pngPath, {width: WIDTH, height: HEIGHT});
      await requireLive();
      await requireCanvas();
      const generated = isRecord(api) && api.success === true && api.result === true;
      const missingMark = isRecord(api) && api.success === false &&
        isRecord(api.error) && api.error.code === MISSING_MARK_CODE;
      if (!generated && !missingMark) throw fault('generation_failed');
      stage = 'finish';
      const checked = await deps.finish({token, missingMark});
      await requireLive();
      if (!isRecord(checked) || checked.token !== token ||
          checked.filePath !== context.filePath || checked.pageIndex !== context.pageIndex ||
          checked.profileId !== profile.id || checked.geometryId !== profile.id ||
          checked.sourceSha256 !== profile.sourceSha256 || checked.pageCount !== context.totalPages ||
          checked.sourceUnchanged !== true || checked.markUnchanged !== true) {
        throw fault('finish_invalid');
      }
      if (missingMark) {
        if (checked.missingMark !== true) throw fault('finish_invalid');
        if (batch) {
          const handle = retain(token);
          token = null;
          return {status: 'no_page', reason: 'missing_mark_page', handle, evidence: Object.freeze({...checked})};
        }
        stage = 'cleanup';
        cleanupAttempted = true;
        await discardToken(token);
        token = null;
        await requireLive();
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

  async function discardRetained(handles, skip = null) {
    let failed = null;
    for (const handle of handles) {
      if (handle === skip || state.retained.get(handle.token) !== handle) continue;
      try {
        await discardToken(handle.token);
        state.retained.delete(handle.token);
      } catch (_) { failed = failed ?? handle; }
    }
    return failed ? {status: 'error', reason: 'cleanup_failed', handle: failed,
      handles: Object.freeze([...state.retained.values()])} : {status: 'released'};
  }

  function runBatch(context) {
    const obstruction = blocked();
    if (obstruction) return Promise.resolve(obstruction);
    if (!supportedBatchContext(context)) return Promise.resolve({status: 'unavailable', reason: 'unsupported_context'});
    if (typeof deps.validateBatch !== 'function') return Promise.resolve({status: 'error', reason: 'batch_validation_unavailable'});
    const expected = Object.freeze({filePath: context.filePath, totalPages: context.totalPages,
      pluginDir: context.pluginDir, pageIndices: Object.freeze([...context.pageIndices])});
    const requestEpoch = ++epoch;
    return start(async () => {
      const pages = [];
      let skipCleanup = null;
      try {
        for (const pageIndex of expected.pageIndices) {
          const siblingToken = pages.length ? pages[0].handle.token : null;
          const result = await execute({...expected, pageIndex}, requestEpoch, expected, siblingToken);
          if (!['ready', 'no_page'].includes(result.status)) {
            if (result.reason === 'cleanup_failed') skipCleanup = result.handle;
            throw fault(result.reason ?? 'page_failed');
          }
          if (pages.some(page => page.handle.token === result.handle.token)) throw fault('duplicate_token');
          pages.push(Object.freeze({...result, pageIndex}));
        }
        await requireBatchCurrent(expected, requestEpoch);
        const tokens = pages.map(page => page.handle.token);
        const checked = await deps.validateBatch({tokens: Object.freeze([...tokens])});
        await requireBatchCurrent(expected, requestEpoch);
        if (!isRecord(checked) || checked.batchUnchanged !== true ||
            checked.firstToken !== tokens[0] || checked.secondToken !== (tokens[1] ?? '')) throw fault('batch_invalid');
        return {status: pages.some(page => page.status === 'ready') ? 'ready' : 'no_page',
          pages: Object.freeze(pages)};
      } catch (error) {
        const reason = error.savedInkReason ?? 'batch_failed';
        const cleanup = await discardRetained([...state.retained.values()], skipCleanup);
        if (state.retained.size) return {status: 'error', reason: 'cleanup_failed', causeReason: reason,
          handle: cleanup.handle ?? skipCleanup, handles: Object.freeze([...state.retained.values()])};
        return {status: ['cancelled', 'context_changed'].includes(reason) ? 'unavailable' : 'error', reason};
      }
    });
  }

  function release(handle) {
    if (state.busy) return Promise.resolve({status: 'unavailable', reason: 'busy'});
    if (!state.retained.size) return Promise.resolve({status: 'released'});
    if (handle !== undefined && state.retained.get(handle?.token) !== handle) return Promise.resolve({status: 'error', reason: 'unknown_handle'});
    return start(() => discardRetained(handle === undefined ? [...state.retained.values()] : [handle]));
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
    run, runBatch, release, dispose,
    // Call on EVERY visible-document/page transition, including away/back ABA.
    // The caller must hide a published token immediately, before async disposal.
    cancel() { epoch += 1; },
    getState() { return {busy: state.busy, disposed: state.disposed, retained: state.retained.size > 0}; },
  };
}

module.exports = {
  FIXTURE_NAME, PAGE_INDEX, TOTAL_PAGES, WIDTH, HEIGHT, MAX_PNG_BYTES,
  PROFILES, selectSavedInkProfile, supportedContext, supportedBatchContext, createSavedInkController,
};
