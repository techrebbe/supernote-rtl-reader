// Original PDF destinations only. No converted-page IDs, IO, writer or saved ink.
export class DestinationError extends Error {}
const numberOrNull = value => value === null || (typeof value === 'number' && Number.isFinite(value));

export async function resolveDestination(pdf, value, isCurrent = () => true) {
  const current = () => { if (isCurrent() !== true) throw new DestinationError('Stale destination'); };
  current();
  let dest = value;
  if (typeof dest === 'string') {
    if (!dest || dest.length > 4096) throw new DestinationError('Invalid named destination');
    dest = await pdf.getDestination(dest);
    current();
  }
  if (!Array.isArray(dest) || dest.length < 2 || !dest[1] || typeof dest[1].name !== 'string') {
    throw new DestinationError('Unresolved or malformed destination');
  }
  let pageIndex = dest[0];
  if (pageIndex && typeof pageIndex === 'object' && !Array.isArray(pageIndex) &&
      Number.isSafeInteger(pageIndex.num) && pageIndex.num > 0 &&
      Number.isSafeInteger(pageIndex.gen) && pageIndex.gen >= 0) {
    pageIndex = await pdf.getPageIndex({num: pageIndex.num, gen: pageIndex.gen});
    current();
  }
  if (!Number.isSafeInteger(pdf.numPages) || pdf.numPages < 1 ||
      !Number.isSafeInteger(pageIndex) || pageIndex < 0 || pageIndex >= pdf.numPages) {
    throw new DestinationError('Destination page outside original PDF');
  }
  const mode = dest[1].name;
  if (mode === 'Fit' && dest.length === 2) return Object.freeze({pageIndex, mode});
  if (mode === 'XYZ' && dest.length === 5 && dest.slice(2).every(numberOrNull) &&
      (dest[4] === null || dest[4] >= 0)) {
    return Object.freeze({pageIndex, mode, left: dest[2], top: dest[3], zoom: dest[4]});
  }
  if (mode === 'FitH' && dest.length === 3 && numberOrNull(dest[2])) {
    return Object.freeze({pageIndex, mode, top: dest[2]});
  }
  throw new DestinationError(`Unsupported destination mode: ${mode}`);
}

export function classifyLink(annotation) {
  if (!annotation || annotation.subtype !== 'Link') return {kind: 'not-link'};
  if (annotation.actions && Object.keys(annotation.actions).length) return {kind: 'unsupported', reason: 'PDF script action disabled'};
  if (annotation.dest !== undefined && annotation.dest !== null) return {kind: 'internal', destination: annotation.dest};
  const raw = annotation.unsafeUrl ?? annotation.url;
  if (typeof raw === 'string') {
    try {
      const url = new URL(raw);
      if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password) throw Error();
      return {kind: 'external', url: url.href};
    } catch (_) { return {kind: 'unsupported', reason: 'Unsafe or unsupported URL'}; }
  }
  return {kind: 'unsupported', reason: 'Unsupported PDF action'};
}

export function annotationRect(viewport, rect) {
  if (!Array.isArray(rect) || rect.length !== 4 || !rect.every(Number.isFinite)) {
    throw new DestinationError('Invalid link rectangle');
  }
  // PDF.js 6 exposes point conversion, not the older rectangle helper. Use the
  // exact canvas/TextLayer viewport for all four corners (including crop/rotate).
  const mapped = [[rect[0],rect[1]],[rect[0],rect[3]],[rect[2],rect[1]],[rect[2],rect[3]]]
    .map(([x,y])=>viewport.convertToViewportPoint(x,y));
  if (mapped.some(point=>!Array.isArray(point) || point.length!==2 || !point.every(Number.isFinite))) {
    throw new DestinationError('Invalid mapped link rectangle');
  }
  const xs=mapped.map(point=>point[0]),ys=mapped.map(point=>point[1]);
  return {left:Math.min(...xs),top:Math.min(...ys),width:Math.max(...xs)-Math.min(...xs),height:Math.max(...ys)-Math.min(...ys)};
}

// DOM offsetTop/Left may be body-relative. Anchor using actual canvas and scroll
// viewport rectangles, independent of offsetParent, toolbar or outline placement.
export function scrollAnchor(canvasRect, stageRect, stage, point, align=[0,0]) {
  return {
    left:stage.scrollLeft+canvasRect.left-stageRect.left-stage.clientLeft+point[0]-stage.clientWidth*align[0],
    top:stage.scrollTop+canvasRect.top-stageRect.top-stage.clientTop+point[1]-stage.clientHeight*align[1],
  };
}

export function destinationView(dest, prior, pdfToCss) {
  if(dest.mode==='XYZ') return {
    scale:dest.zoom!==null && dest.zoom!==0?dest.zoom*pdfToCss:prior.effectiveScale,
    fit:null, point:[dest.left??prior.topLeft[0],dest.top??prior.topLeft[1]],
  };
  if(dest.mode==='FitH') return {scale:null,fit:'width',point:[prior.topLeft[0],dest.top??prior.topLeft[1]]};
  if(dest.mode==='Fit') return {scale:null,fit:'page',point:null};
  throw new DestinationError('Unsupported resolved destination');
}
