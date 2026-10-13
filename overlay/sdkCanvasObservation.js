'use strict';

// Diagnostic only: do not normalize dimensions, infer missing ink, retry,
// change API arguments or relax the caller's canvas-authority checks. Never
// log a file path, arbitrary SDK message, content, token or entire response.
async function observeSdkCanvas(api, filePath, pageIndex, observe) {
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
    sample = {
      pageIndex,
      status: response?.success === true ? 'success' : response?.success === false ? 'error' : 'invalid',
      width: dimension(response?.result?.width),
      height: dimension(response?.result?.height),
      code: Number.isSafeInteger(response?.error?.code) ? response.error.code : 'unknown',
    };
  } catch (_) { /* Preserve an uninspectable response unchanged. */ }
  emit(sample);
  return response;
}

module.exports = {observeSdkCanvas};
