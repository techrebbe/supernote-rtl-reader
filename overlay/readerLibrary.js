// Favourites are launch choices, not an interception of Supernote's file list.
// No PDF/annotation writes and no saved-page or Edit-return authority here.
const MAX_BOOKS = 50;
function entry(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      typeof value.filePath !== 'string' || value.filePath.length > 1024 ||
      !value.filePath.startsWith('/') || !/\.pdf$/i.test(value.filePath) ||
      /[\u0000-\u001f\\]/.test(value.filePath) || value.filePath.split('/').some(x => x === '.' || x === '..') ||
      typeof value.sourceSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.sourceSha256) ||
      !Number.isInteger(value.pageCount) || value.pageCount < 1 || value.pageCount > 10000) {
    throw Error('Invalid favourite PDF identity.');
  }
  return {filePath:value.filePath, sourceSha256:value.sourceSha256, pageCount:value.pageCount};
}
function decodeLibrary(raw) {
  if (typeof raw !== 'string' || raw.length > 100000) throw Error('Favourites storage is invalid.');
  const value = JSON.parse(raw);
  if (value?.version !== 1 || !Array.isArray(value.entries) || value.entries.length > MAX_BOOKS) {
    throw Error('Favourites storage is invalid.');
  }
  const entries = value.entries.map(entry);
  if (new Set(entries.map(x => x.filePath)).size !== entries.length) throw Error('Duplicate favourite PDF.');
  return entries;
}
function assertLibraryContext(target, context) {
  if (!target) return;
  const saved = entry(target);
  if (context?.filePath !== saved.filePath || context?.totalPages !== saved.pageCount) {
    throw Error('The favourite did not open as the expected document. No page was rendered.');
  }
}
function assertLibraryOwner(target, owner) {
  if (!target) return;
  assertLibraryContext(target, {filePath:owner?.filePath, totalPages:owner?.pageCount});
  if (owner?.sourceSha256 !== target.sourceSha256) {
    throw Error('This favourite PDF was replaced. Remove it and save the current PDF again.');
  }
}
async function openFavourite(value, {store, manager, files, comm, doc, drain, isCurrent, wait,
    ensureReadAccess}) {
  const saved = entry(value);
  if (globalThis.RTL_READER_LIBRARY_OPEN_IN_FLIGHT) throw Error('Another favourite is still opening.');
  const ticket={};globalThis.RTL_READER_LIBRARY_OPEN_IN_FLIGHT=ticket;
  const current = () => {if (isCurrent() !== true || globalThis.RTL_READER_LIBRARY_OPEN_IN_FLIGHT!==ticket)
    throw Error('Favourite opening cancelled.');};
  try {
  current();
  await drain(); current();
  await ensureReadAccess(manager, isCurrent); current();
  if (await store.verify(saved.filePath, saved.sourceSha256) !== true) throw Error('Favourite PDF verification failed.');
  current();
  // Exactly one supported open. -1 delegates the native last-viewed page;
  // the normal source-bound preference/Edit-return loader still chooses page.
  const opened = await files.openFile(saved.filePath, -1); current();
  if (opened?.success !== true || opened.result !== true) throw Error('Supernote did not confirm opening the favourite. No retry was sent.');
  let confirmed = false;
  for (let attempt = 0; attempt < 8; attempt++) {
    const path = await comm.getCurrentFilePath(); current();
    const count = await doc.getCurrentTotalPages(); current();
    const pathAgain = await comm.getCurrentFilePath(); current();
    if (path?.success === true && pathAgain?.success === true && count?.success === true &&
        path.result === saved.filePath && pathAgain.result === saved.filePath && count.result === saved.pageCount) {
      confirmed = true; break;
    }
    if (attempt < 7) {await wait(100); current();}
  }
  if (!confirmed) throw Error('Favourite document confirmation timed out. No retry was sent.');
  if (await store.verify(saved.filePath, saved.sourceSha256) !== true) throw Error('Favourite PDF changed while opening.');
  current();
  if (await manager.showPluginView() !== true) throw Error('Supernote did not confirm reopening RTL Reader.');
  current();
  return saved; // App must still authenticate the actual staged PDFium owner.
  } finally {
    if(globalThis.RTL_READER_LIBRARY_OPEN_IN_FLIGHT===ticket)globalThis.RTL_READER_LIBRARY_OPEN_IN_FLIGHT=null;
  }
}
module.exports = {MAX_BOOKS, entry, decodeLibrary, assertLibraryContext, assertLibraryOwner, openFavourite};
