'use strict';

// Diagnostic only: do not normalize dimensions, infer missing ink, retry,
// change API arguments or relax the caller's canvas-authority checks. Never
// log a file path, arbitrary SDK message, content, token or entire response.
async function observeSdkCanvas(api, filePath, pageIndex, observe, markDiagnostic = null) {
  const emit = sample => {
    try { observe(sample); } catch (_) { /* Diagnostics cannot change behavior. */ }
  };
  let response;
  try {
    response = await api(filePath, pageIndex);
  } catch (error) {
    emit({pageIndex, status: 'threw', width: 'invalid', height: 'invalid', code: 'unknown'});
    throw error;
  }
  let sample = {pageIndex, status: 'invalid', width: 'invalid', height: 'invalid', code: 'unknown'};
  try {
    const dimension = value => typeof value === 'number' && Number.isFinite(value) ? value : 'invalid';
    const code = response?.error?.code;
    sample = {
      pageIndex,
      status: response?.success === true ? 'success' : response?.success === false ? 'error' : 'invalid',
      width: dimension(response?.result?.width),
      height: dimension(response?.result?.height),
      code: Number.isSafeInteger(code) ? code : 'unknown',
    };
  } catch (_) { /* Preserve an uninspectable response unchanged. */ }
  emit(sample);
  if (sample.status === 'error' && sample.code === 1207) {
    // One read-only diagnostic, never an empty-page/canvas fallback. The caller
    // supplies the existing activation/presentation fence; cleanup waits for
    // real settlement and the original canvas response is still returned.
    try { await observeMarkPages(markDiagnostic, filePath, pageIndex); } catch (_) { /* Preserve response. */ }
  }
  return response;
}

async function observeMarkPages(diagnostic, filePath, pageIndex) {
  if (!diagnostic || diagnostic.attempted !== false ||
      typeof diagnostic.getMarkPages !== 'function' || typeof diagnostic.isCurrent !== 'function' ||
      typeof diagnostic.observe !== 'function' || !Number.isSafeInteger(diagnostic.totalPages) ||
      diagnostic.totalPages < 1 || diagnostic.totalPages > 2) return;
  diagnostic.attempted = true; // Consume before any await, including reentrant callers.
  const emit = sample => {
    try { diagnostic.observe({pageIndex, indexBase: 'unverified', ...sample}); } catch (_) { /* Diagnostic only. */ }
  };
  try {
    if (await diagnostic.isCurrent(filePath, pageIndex) !== true) {
      emit({status: 'stale', indices: 'unavailable', code: 'unknown'});
      return;
    }
    const response = await diagnostic.getMarkPages(filePath);
    if (await diagnostic.isCurrent(filePath, pageIndex) !== true) {
      emit({status: 'stale', indices: 'unavailable', code: 'unknown'});
      return;
    }
    let sample = {status: 'invalid', indices: 'unavailable', code: 'unknown'};
    try {
      // Do not guess index base or classify absent pages. Permit both boundary
      // indices for observation only; this cannot authorize any raster/absence.
      const success = response?.success;
      const code = response?.error?.code;
      const source = response?.result;
      const length = Array.isArray(source) ? source.length : -1;
      const indices = [];
      if (Number.isSafeInteger(length) && length >= 0 && length <= diagnostic.totalPages) {
        for (let index = 0; index < length; index++) indices.push(source[index]);
      }
      const valid = Array.isArray(source) && length >= 0 && length <= diagnostic.totalPages &&
        indices.every(index => Number.isSafeInteger(index) && index >= 0 && index <= diagnostic.totalPages) &&
        new Set(indices).size === indices.length;
      sample = {
        status: success === true && valid ? 'success' : success === false ? 'error' : 'invalid',
        indices: success === true && valid ? indices : 'unavailable',
        code: Number.isSafeInteger(code) ? code : 'unknown',
      };
    } catch (_) { /* Never expose messages, paths, tokens or arbitrary result fields. */ }
    emit(sample);
  } catch (_) {
    emit({status: 'threw', indices: 'unavailable', code: 'unknown'});
  }
}

module.exports = {observeSdkCanvas};
