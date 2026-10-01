'use strict';
// Pure orchestration for the DISABLED, MANUAL T004 annotation PNG probe.
// No React Native, device, filesystem, timers, or production composition.
// Native prepare owns exact fixture SHA validation and issues an opaque token.
// Native finish owns stable source/mark checks and bounded PNG decoding.
// This module cannot establish pixel alignment, annotation completeness, or save
// durability. A preview is evidence to inspect, not a rendered reader overlay.

const FIXTURE_NAME = 'RTL_RAPID_TOOLS_T004_20261001.pdf';
const PAGE_INDEX = 2;
const TOTAL_PAGES = 8;
const WIDTH = 1404;
const HEIGHT = 1872;
const MAX_PNG_BYTES = 16 * 1024 * 1024;
const MISSING_MARK_CODE = 1302;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isToken(value) {
  return typeof value === 'string' && UUID.test(value);
}

function validContext(value) {
  return isRecord(value) &&
    typeof value.filePath === 'string' &&
    value.filePath.startsWith('/') &&
    !/[\\\u0000-\u001f]/.test(value.filePath) &&
    !value.filePath.includes('//') &&
    !value.filePath.split('/').some(part => part === '.' || part === '..') &&
    value.filePath.endsWith(`/${FIXTURE_NAME}`) &&
    value.pageIndex === PAGE_INDEX && value.totalPages === TOTAL_PAGES;
}

function validOutputPath(value, token) {
  return typeof value === 'string' && value.length <= 4096 &&
    /^\/data\/(?:data\/|user\/\d+\/)/.test(value) &&
    !/[\\\u0000-\u001f]/.test(value) && !value.includes('//') &&
    !value.split('/').some(part => part === '.' || part === '..') &&
    value.endsWith(`/${token}/ink.png`);
}

function fault(reason) {
  const error = new Error(reason);
  error.probeReason = reason;
  return error;
}

function reasonOf(error, fallback) {
  return typeof error?.probeReason === 'string' ? error.probeReason : fallback;
}

function createAnnotationPreviewProbe(deps, options = {}) {
  for (const name of ['prepare', 'finish', 'discard', 'generateThumbnail', 'currentContext']) {
    if (typeof deps?.[name] !== 'function') throw new TypeError(`Missing probe dependency: ${name}`);
  }
  const enabled = options.enabled === true;
  let epoch = 0;
  let active = false;
  let retainedHandle = null;

  async function requireCurrent(expected, requestEpoch) {
    const context = await deps.currentContext();
    if (requestEpoch !== epoch) throw fault('cancelled');
    if (!validContext(context) || context.filePath !== expected.filePath ||
        context.pageIndex !== expected.pageIndex || context.totalPages !== expected.totalPages) {
      throw fault('context_changed');
    }
  }

  async function discardToken(token) {
    const result = await deps.discard({token});
    if (!isRecord(result) || result.token !== token || result.discarded !== true) {
      throw fault('cleanup_failed');
    }
  }

  async function release(handle) {
    // Object identity prevents callers from supplying arbitrary token/path data.
    if (active) return {status: 'blocked', reason: 'busy'};
    if (!retainedHandle || handle !== retainedHandle) {
      return {status: 'error', reason: 'unknown_handle'};
    }
    active = true;
    try {
      await discardToken(handle.token);
      retainedHandle = null;
      return {status: 'released'};
    } catch (_) {
      // Preserve the handle for a bounded, explicit cleanup retry; no next run.
      return {status: 'error', reason: 'cleanup_failed', handle};
    } finally {
      active = false;
    }
  }

  async function run(request = {}) {
    if (!enabled) return {status: 'blocked', reason: 'disabled'};
    if (request.manual !== true) return {status: 'blocked', reason: 'manual_required'};
    if (active) return {status: 'blocked', reason: 'busy'};
    if (retainedHandle) return {status: 'blocked', reason: 'preview_retained'};
    active = true;
    const requestEpoch = ++epoch;
    let token = null;
    let cleanupAttempted = false;
    let stage = 'context';
    try {
      const initial = await deps.currentContext();
      if (requestEpoch !== epoch) throw fault('cancelled');
      if (!validContext(initial)) throw fault('fixture_context_required');
      // Copy identity: a dependency cannot mutate our expected snapshot in place.
      const context = {filePath: initial.filePath, pageIndex: initial.pageIndex, totalPages: initial.totalPages};
      stage = 'prepare';
      const prepared = await deps.prepare({
        filePath: context.filePath, pageIndex: context.pageIndex, width: WIDTH, height: HEIGHT,
      });
      // Even a rejected preparation may have issued a valid native cleanup token.
      if (isRecord(prepared) && isToken(prepared.token)) token = prepared.token;
      if (!token || !isRecord(prepared) || prepared.sourceVerified !== true ||
          prepared.filePath !== context.filePath || prepared.pageIndex !== context.pageIndex ||
          prepared.width !== WIDTH || prepared.height !== HEIGHT ||
          !validOutputPath(prepared.pngPath, token)) {
        throw fault('prepare_invalid');
      }
      const pngPath = prepared.pngPath;
      await requireCurrent(context, requestEpoch);
      stage = 'generate';
      // NO JS timeout: a timed-out promise can still be writing its output. Keep
      // single-flight locked until the native-controlled call actually settles.
      // cancel() suppresses delivery but never discards an in-flight API output.
      const api = await deps.generateThumbnail(
        context.filePath, context.pageIndex, pngPath, {width: WIDTH, height: HEIGHT},
      );
      await requireCurrent(context, requestEpoch);
      const generated = isRecord(api) && api.success === true && api.result === true;
      const missingMark = isRecord(api) && api.success === false &&
        isRecord(api.error) && api.error.code === MISSING_MARK_CODE;
      if (!generated && !missingMark) throw fault('generation_failed');
      stage = 'finish';
      const checked = await deps.finish({token, missingMark});
      await requireCurrent(context, requestEpoch);
      if (!isRecord(checked) || checked.token !== token || checked.filePath !== context.filePath ||
          checked.pageIndex !== context.pageIndex || checked.sourceUnchanged !== true ||
          checked.markUnchanged !== true) {
        throw fault('finish_invalid');
      }
      if (missingMark) {
        if (checked.missingMark !== true) throw fault('finish_invalid');
        // A blank denotes the API-reported absent page OR absent sidecar. Only
        // native unchanged-source checks authorize this non-image result.
        stage = 'cleanup';
        cleanupAttempted = true;
        await discardToken(token);
        token = null;
        await requireCurrent(context, requestEpoch);
        return {status: 'blank', reason: 'missing_mark_page', evidence: {...checked}, geometryVerified: false};
      }
      if (checked.missingMark === true || checked.pngPath !== pngPath || checked.width !== WIDTH || checked.height !== HEIGHT ||
          checked.decoded !== true || typeof checked.sha256 !== 'string' || !SHA256.test(checked.sha256) ||
          !Number.isInteger(checked.byteLength) || checked.byteLength <= 0 || checked.byteLength > MAX_PNG_BYTES ||
          !Number.isInteger(checked.alphaMin) || !Number.isInteger(checked.alphaMax) ||
          checked.alphaMin < 0 || checked.alphaMax > 255 || checked.alphaMin > checked.alphaMax) {
        throw fault('finish_invalid');
      }
      retainedHandle = Object.freeze({token});
      token = null;
      return {
        status: 'preview', handle: retainedHandle, imageUri: `file://${pngPath}`,
        evidence: {...checked}, geometryVerified: false, annotationCompleteness: 'unknown',
      };
    } catch (error) {
      const reason = reasonOf(error, `${stage}_failed`);
      if (token) {
        if (cleanupAttempted) {
          retainedHandle = Object.freeze({token});
          return {status: 'error', reason: 'cleanup_failed', causeReason: reason, handle: retainedHandle};
        }
        try {
          await discardToken(token);
        } catch (_) {
          retainedHandle = Object.freeze({token});
          return {status: 'error', reason: 'cleanup_failed', causeReason: reason, handle: retainedHandle};
        }
      }
      return {status: ['cancelled', 'context_changed'].includes(reason) ? 'stale' : 'error', reason};
    } finally {
      active = false;
    }
  }

  return {
    run,
    release,
    // Call on EVERY document/page transition, including away-and-back (ABA).
    // Existing successful previews still need explicit release(handle).
    cancel() { epoch += 1; },
    getState() { return {enabled, busy: active, retained: retainedHandle !== null}; },
  };
}

module.exports = {
  FIXTURE_NAME, PAGE_INDEX, TOTAL_PAGES, WIDTH, HEIGHT, MAX_PNG_BYTES,
  createAnnotationPreviewProbe,
};
