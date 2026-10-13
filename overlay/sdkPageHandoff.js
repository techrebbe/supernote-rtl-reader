'use strict';

// Shared by Edit and ordinary Close. Only the supported current-document SDK
// jump is a mutation. Preparation/validation read our own preferences and the
// public PDF; never access Document's private CONFIG or restart its process.
async function handoffSavedPage({preferences, comm, doc, isCurrent, expected}) {
  const current = () => {
    if (isCurrent() !== true) throw new Error('Reader handoff owner changed.');
  };
  const result = async (promise, label) => {
    const response = await promise;
    if (response?.success !== true) throw new Error(response?.error?.message ?? `${label} failed`);
    return response.result;
  };
  current();
  if (!preferences?.handoffLastSavedPage || !preferences?.validatePreparedPageHandoff ||
      !comm?.jumpToPage || !comm?.getCurrentFilePath || !comm?.getCurrentPageNum ||
      !doc?.getCurrentTotalPages) throw new Error('Supported page handoff is unavailable.');
  const target = await preferences.handoffLastSavedPage();
  current();
  if (target?.annotationRecovery === true) throw new Error('Annotation recovery blocks page handoff.');
  if (typeof target?.filePath !== 'string' || !target.filePath ||
      !Number.isInteger(target.pageIndex) || target.pageIndex < 0 ||
      typeof target.requestId !== 'string' || !target.requestId) {
    throw new Error('Invalid saved page handoff.');
  }
  if (expected && (target.filePath !== expected.filePath || target.pageIndex !== expected.pageIndex)) {
    throw new Error('Saved page handoff does not match the requested document/page.');
  }
  const file = async () => {
    if (await result(comm.getCurrentFilePath(), 'current document') !== target.filePath) {
      throw new Error('The native document changed during page handoff.');
    }
  };
  const validate = async () => {
    if (await preferences.validatePreparedPageHandoff(target.requestId) !== true) {
      throw new Error('Saved preferences or source PDF changed during page handoff.');
    }
  };
  await file(); current();
  const count = await result(doc.getCurrentTotalPages(), 'page count'); current();
  if (!Number.isInteger(count) || count < 1 || target.pageIndex >= count ||
      (expected?.totalPages != null && count !== expected.totalPages)) {
    throw new Error('Saved page is outside the current document.');
  }
  await validate(); current();
  await file(); current(); // Last supported document check before dispatch.
  const jumped = await result(comm.jumpToPage(target.pageIndex), 'page jump');
  if (jumped !== true) throw new Error('The native reader rejected the page jump.');
  // Once dispatched, finish read-only verification even after an unmount. The
  // caller may retain an accepted return record, but must not close a new view.
  await file();
  const page = await result(comm.getCurrentPageNum(), 'current page');
  const afterCount = await result(doc.getCurrentTotalPages(), 'page count');
  await validate();
  await file();
  if (page !== target.pageIndex || afterCount !== count) {
    throw new Error('The native reader did not confirm the requested page.');
  }
  return {...target, navigation: 'sdk-verified'};
}

module.exports = {handoffSavedPage};
