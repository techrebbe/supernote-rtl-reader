// Original-PDF reading only. No SDK, writer, filesystem or global key listener.
function validateOwner(value, context) {
  if (!value || !context || !/^[1-9][0-9]{0,15}$/.test(value.sessionId) ||
      value.filePath !== context.filePath || value.pageCount !== context.totalPages ||
      !Number.isInteger(value.pageCount) || value.pageCount < 1 || value.pageCount > 10000 ||
      !/^[a-f0-9]{64}$/.test(value.sourceSha256)) throw Error('PDF session identity mismatch');
  return Object.freeze({...value});
}
function restoreSourcePreferences(raw, sha256) {
  let saved;
  try { saved = typeof raw === 'string' ? JSON.parse(raw) : raw; } catch (_) { return raw; }
  if (!saved || !Object.prototype.hasOwnProperty.call(saved, 'pdfSourceSha256')) return raw;
  if (saved.pdfSourceSha256 === sha256) return raw;
  // Preserve explicit layout/direction/cover/key preferences, but not old page
  // authority or an Edit return for a replaced document at the same path.
  const next = {...saved};
  delete next.lastPageIndex; delete next.editReturn; delete next.pdfSourceSha256;
  return JSON.stringify(next);
}
function validPose(pose) {
  if (pose == null) return null;
  if (pose.kind === 'Fit') return {kind:'Fit'};
  const finite = x => typeof x === 'number' && Number.isFinite(x) && Math.abs(x) <= 1000000;
  if (pose.kind === 'scale' && finite(pose.scale) && pose.scale > 0) return {kind:'scale',scale:pose.scale};
  if (pose.kind === 'XYZ' && [pose.left,pose.top,pose.zoom].every(x => x === null || finite(x)) &&
      (pose.zoom === null || pose.zoom >= 0) && finite(pose.fromScale) && pose.fromScale > 0 &&
      finite(pose.fromLeft) && finite(pose.fromTop)) return {...pose};
  throw Error('Unsupported PDF viewport destination');
}
function requestSpec({owner,token,page,slot,mode,blocked,pose,width,height,contentMode='fit'}) {
  if (!owner || !Number.isSafeInteger(token) || token < 1 || !Number.isInteger(page) ||
      page < 0 || page >= owner.pageCount || !['read','text','pan'].includes(mode) ||
      typeof blocked !== 'boolean' || !['single','left','right'].includes(slot) ||
      !Number.isFinite(width) || !Number.isFinite(height) || width <= 0 || height <= 0 ||
      !['fit','native_fill'].includes(contentMode))
    throw Error('Invalid PDF viewport request');
  const safePose = validPose(pose);
  const requestId = JSON.stringify([owner.sessionId,token,page,slot,mode,blocked,safePose,width,height,contentMode]);
  return {sessionId:owner.sessionId,requestId,renderToken:token,pageIndex:page,slot,mode,blocked,pose:safePose,width,height,contentMode};
}
function packetMatches(packet, spec) {
  return Boolean(packet && spec && packet.sessionId === spec.sessionId &&
    packet.requestId === spec.requestId && packet.pageIndex === spec.pageIndex);
}
function internalDestination(action, from, pageCount) {
  if (!action || action.kind !== 'internal' || !Number.isInteger(action.pageIndex) ||
      action.pageIndex < 0 || action.pageIndex >= pageCount) throw Error('Unsupported PDF action');
  if (action.mode === 'Fit') return {page:action.pageIndex,pose:{kind:'Fit'}};
  if (action.mode !== 'XYZ') throw Error('Unsupported PDF destination');
  return {page:action.pageIndex,pose:validPose({kind:'XYZ',left:action.left,top:action.top,
    zoom:action.zoom,fromScale:from.scale,fromLeft:from.left,fromTop:from.top})};
}
function flattenOutline(tree) {
  if (!Array.isArray(tree)) throw Error('Invalid PDF bookmarks');
  const result=[];
  function walk(nodes, depth) {
    if (depth > 32 || !Array.isArray(nodes)) throw Error('PDF bookmark hierarchy bound');
    for (const node of nodes) {
      if (result.length >= 1000 || !node || typeof node.title !== 'string' || node.title.length > 4096)
        throw Error('PDF bookmark bound');
      result.push({title:node.title,depth,action:node.destination});walk(node.children,depth+1);
    }
  }
  walk(tree,0);return result;
}
module.exports={validateOwner,restoreSourcePreferences,requestSpec,packetMatches,internalDestination,flattenOutline,validPose};
