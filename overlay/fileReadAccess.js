// Public SDK permission flow only. No cached grant, filesystem escape, private
// native-reader access, write/delete/internet request or background auto-prompt.
const FILE_READ_PERMISSION = 'plugin.permission.FILE:READ';

async function ensureFileReadAccess(manager, isCurrent = () => true) {
  const current = () => {
    if (isCurrent() !== true) throw new Error('Reader session closed while checking file access.');
  };
  current();
  if (typeof manager?.hasPermission !== 'function' ||
      typeof manager?.requestPermission !== 'function') {
    throw new Error('The supported file-read permission API is unavailable.');
  }
  const status = await manager.hasPermission(FILE_READ_PERMISSION);
  current();
  // The guide describes granted=1, while the pinned SDK native spec also
  // permits permanent=2. Admit those two explicit numeric grant statuses only.
  if (status === 1 || status === 2) return;
  if (status !== 0) throw new Error('File-read permission status could not be verified.');
  const granted = await manager.requestPermission(FILE_READ_PERMISSION,
    'Read access is required to display your PDF and its saved annotations.');
  current();
  if (granted !== 1 && granted !== 2) {
    throw new Error('File read access was not granted. No PDF was opened by RTL Reader.');
  }
  const verified = await manager.hasPermission(FILE_READ_PERMISSION);
  current();
  if (verified !== 1 && verified !== 2) throw new Error('File-read permission expired before the PDF could open.');
}

module.exports = {FILE_READ_PERMISSION, ensureFileReadAccess};
