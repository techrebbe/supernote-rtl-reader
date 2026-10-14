import * as pdfjs from '/pdfjs/legacy/build/pdf.mjs';
import {resolveDestination, classifyLink, annotationRect, scrollAnchor, destinationView} from './destinations.mjs';
import {getVisualSpread, getSpreadPair} from '/core/layout.mjs';
import {createPageTurnerKeys} from '/core/keys.mjs';

pdfjs.GlobalWorkerOptions.workerSrc = '/pdfjs/legacy/build/pdf.worker.mjs';
const $ = id => document.getElementById(id);
const stage = $('stage'), pages = $('pages');
const state = {pdf:null, loadingTask:null, cleanup:null, documentId:'', page:0, request:0, navigation:0, busy:true,
  mode:'auto', direction:'rtl', scale:null, fit:'page', selected:false, outline:false,
  modal:false, closed:false, rendered:new Map(), tasks:[], history:[]};
const handles = new Map();
const PDF_TO_CSS = 96 / 72;
function status(text, error=false) { $('status').textContent=text; $('status').dataset.error=String(error); }
function spread() { return state.mode === 'spread' || (state.mode === 'auto' && innerWidth > innerHeight); }
function clearSelection() { window.getSelection()?.removeAllRanges(); }
function snapshot() {
  const current=state.rendered.get(state.page);
  if (!current) throw Error('No settled original-page viewport');
  const a=current.element.querySelector('canvas').getBoundingClientRect(), b=stage.getBoundingClientRect();
  return {page:state.page, scale:state.scale, fit:state.fit, align:[.5,.5],effectiveScale:current.viewport.scale,
    topLeft:current.viewport.convertToPdfPoint(b.left+stage.clientLeft-a.left,b.top+stage.clientTop-a.top),
    point:current.viewport.convertToPdfPoint(b.left+stage.clientLeft-a.left+stage.clientWidth/2, b.top+stage.clientTop-a.top+stage.clientHeight/2)};
}
function cancelRender() { for (const task of state.tasks) { try { task.cancel(); } catch (_) {} } state.tasks=[]; }
function controls() {
  const hasPdf=!!state.pdf && !state.closed;
  const settled=hasPdf && stage.dataset.ready==='true' && state.rendered.has(state.page);
  for (const id of ['previous','next','zoom-in','zoom-out']) $(id).disabled=state.busy || !settled;
  // Fit/layout are explicit recovery paths after a failed destination render.
  for (const id of ['fit','layout','direction']) $(id).disabled=state.busy || !hasPdf;
  $('previous').disabled ||= stage.dataset.ready!=='true' || state.page===0;
  $('next').disabled ||= stage.dataset.ready!=='true' || state.page >= (state.pdf?.numPages ?? 1)-1;
  $('back').disabled=state.busy || !hasPdf || !state.history.length;
}
async function external(url) {
  state.modal=true;
  try { if (window.confirm(`Open this external website?\n${url}`)) window.open(url,'_blank','noopener,noreferrer'); }
  finally { state.modal=false; }
}
async function follow(value) {
  const ticket=++state.navigation, pdf=state.pdf;
  try {
    const dest=await resolveDestination(pdf,value,()=>!state.closed && state.pdf===pdf && state.navigation===ticket);
    if (state.navigation!==ticket) return;
    const prior=snapshot(); state.history.push(prior); if(state.history.length>32) state.history.shift();
    state.page=dest.pageIndex;
    const view=destinationView(dest,prior,PDF_TO_CSS);
    state.scale=view.scale;state.fit=view.fit;
    await render(view.point, false);
  } catch(error) { if(state.navigation===ticket) status(error.message,true); }
}
function links(page, viewport, annotations, container) {
  let unsupported=0;
  for(const annotation of annotations) {
    const link=classifyLink(annotation);
    if(link.kind==='not-link') continue;
    const button=document.createElement('button'); button.type='button'; button.className='pdfLink';
    const rect=annotationRect(viewport,annotation.rect);
    if(rect.width<=0 || rect.height<=0) throw Error('Unsupported zero-size link rectangle');
    Object.assign(button.style,{left:`${rect.left}px`,top:`${rect.top}px`,width:`${rect.width}px`,height:`${rect.height}px`});
    button.dataset.sourcePage=String(page.pageNumber-1);
    if(link.kind==='internal') { button.setAttribute('aria-label',typeof link.destination==='string'?`Named link ${link.destination}`:'Internal PDF link'); button.onclick=()=>follow(link.destination); }
    else if(link.kind==='external') { button.setAttribute('aria-label','External PDF link'); button.onclick=()=>external(link.url); }
    else { unsupported++; button.classList.add('unsupported'); button.disabled=true; button.title=link.reason; button.setAttribute('aria-label',link.reason); }
    container.append(button);
  }
  return unsupported;
}
async function render(point=null, invalidateNavigation=true, align=[0,0]) {
  if(!state.pdf || state.closed) return;
  if(invalidateNavigation) state.navigation++;
  const ticket=++state.request, pdf=state.pdf; cancelRender(); clearSelection();
  state.busy=true; stage.inert=true;stage.dataset.ready='false';controls(); status('Rendering original PDF…');
  const width=Math.max(100,stage.clientWidth-40), height=Math.max(100,stage.clientHeight-26);
  const visual=spread()?getVisualSpread(state.page,false,pdf.numPages,state.direction):{left:state.page,right:null};
  const indices=[visual.left,visual.right].filter(Number.isInteger);
  const fragment=document.createDocumentFragment(), rendered=new Map();
  let unsupported=0, pixels=0;
  const current=()=>!state.closed && state.request===ticket && state.pdf===pdf;
  try {
    for(const index of indices) {
      const page=await pdf.getPage(index+1); if(!current()) return;
      const unscaled=page.getViewport({scale:1});
      const available=spread()?(width-16)/2:width;
      const fitScale=state.fit==='width'?available/unscaled.width:Math.min(available/unscaled.width,height/unscaled.height);
      const scale=state.scale ?? fitScale;
      if(!Number.isFinite(scale) || scale<=0 || scale>12) throw Error('Zoom outside prototype limits');
      const viewport=page.getViewport({scale});
      const ratio=Math.min(devicePixelRatio || 1,2);
      const canvas=document.createElement('canvas'); canvas.width=Math.ceil(viewport.width*ratio); canvas.height=Math.ceil(viewport.height*ratio);
      pixels+=canvas.width*canvas.height; if(pixels>16000000) throw Error('Zoom exceeds prototype canvas budget');
      canvas.style.width=`${viewport.width}px`; canvas.style.height=`${viewport.height}px`;
      const element=document.createElement('section'); element.className='pageShell'; element.dataset.pageIndex=String(index); element.dataset.focused=String(index===state.page);
      element.setAttribute('aria-label',`Original source page ${index+1}`); element.style.width=`${viewport.width}px`; element.style.height=`${viewport.height}px`;
      element.style.setProperty('--scale-factor',String(scale)); element.style.setProperty('--total-scale-factor',String(scale)); element.append(canvas);
      const renderTask=page.render({canvasContext:canvas.getContext('2d'),viewport,transform:ratio===1?null:[ratio,0,0,ratio,0,0]});
      state.tasks.push(renderTask); await renderTask.promise; if(!current()) return;
      const text=document.createElement('div'); text.className='textLayer'; element.append(text);
      const textTask=new pdfjs.TextLayer({textContentSource:await page.getTextContent(),container:text,viewport});
      if(!current()) return; state.tasks.push(textTask); await textTask.render(); if(!current()) return;
      const annotations=await page.getAnnotations({intent:'display'}); if(!current()) return;
      const layer=document.createElement('div'); layer.className='linkLayer'; element.append(layer);
      unsupported+=links(page,viewport,annotations,layer);
      rendered.set(index,{viewport,element,page}); fragment.append(element);
    }
    if(!current()) return;
    pages.replaceChildren(fragment); state.rendered=rendered;
    if(point) {
      const target=rendered.get(state.page), mapped=target.viewport.convertToViewportPoint(point[0],point[1]);
      const anchor=scrollAnchor(target.element.querySelector('canvas').getBoundingClientRect(),stage.getBoundingClientRect(),stage,mapped,align);
      stage.scrollLeft=anchor.left; stage.scrollTop=anchor.top;
    } else { stage.scrollLeft=0; stage.scrollTop=0; }
    $('position').textContent=`Original page ${state.page+1} / ${pdf.numPages} · ${spread()?'Spread':'Portrait/Single'}`;
    status(`READY · ${state.direction.toUpperCase()} · ${indices.map(index=>index+1).join(', ')} · ${unsupported} unsupported PDF link actions disabled · desktop proof only`);
    state.tasks=[];
    stage.dataset.ready='true';stage.inert=false;
  } catch(error) { if(current() && error.name!=='RenderingCancelledException') { status(error.message,true); stage.dataset.ready='false'; } }
  finally { if(current()) { state.busy=false; controls(); } }
}
function turn(action) {
  if(state.busy || stage.dataset.ready!=='true' || state.modal || state.selected || state.outline) return;
  const step=spread()?2:1;
  const anchor=spread()?getSpreadPair(state.page,false,state.pdf.numPages).earlier:state.page;
  const target=action==='next'?Math.min(state.pdf.numPages-1,anchor+step):Math.max(0,anchor-step);
  if(target===state.page) return;
  state.page=target; state.scale=null; state.fit='page'; void render();
}
const keys=createPageTurnerKeys({currentContext:()=>({activationId:`view-${state.request}`,documentId:state.documentId,
  enabled:$('keys').checked,focused:stage===document.activeElement || stage.contains(document.activeElement),
  blocked:state.busy || stage.dataset.ready!=='true' || state.modal || state.outline || state.selected,direction:state.direction}),turn});
const codeMap={ArrowUp:19,ArrowDown:20,ArrowLeft:21,ArrowRight:22,PageUp:92,PageDown:93};
stage.addEventListener('keydown',event=> {
  const code=codeMap[event.key]; if(!code) return;
  if(!event.repeat) handles.set(code,Math.max(0,Math.floor(event.timeStamp)));
  const result=keys.handle({activationId:`view-${state.request}`,documentId:state.documentId,keyCode:code,deviceId:0,
    downTime:handles.get(code) ?? 0,repeatCount:event.repeat?1:0,action:0});
  if(result.handled) event.preventDefault();
});
stage.addEventListener('keyup',event=> {
  const code=codeMap[event.key]; if(!code) return;
  const result=keys.handle({activationId:`view-${state.request}`,documentId:state.documentId,keyCode:code,deviceId:0,
    downTime:handles.get(code) ?? 0,repeatCount:0,action:1}); if(result.handled) event.preventDefault();
});
document.addEventListener('selectionchange',()=> {
  const selection=window.getSelection(); state.selected=!!selection && !selection.isCollapsed && stage.contains(selection.anchorNode);
  stage.classList.toggle('selecting',state.selected);
  $('selection').textContent=state.selected?`Selected: ${selection.toString()}`:'Embedded text selection available';
});
$('next').onclick=()=>turn('next'); $('previous').onclick=()=>turn('previous');
$('fit').onclick=()=> {state.scale=null;state.fit='page';void render();};
for(const [id,factor] of [['zoom-in',1.25],['zoom-out',.8]]) $(id).onclick=()=> {
  if(state.busy || state.closed || stage.dataset.ready!=='true' || !state.rendered.has(state.page)) return;
  const prior=snapshot(), current=state.rendered.get(state.page); if(!current) return;
  state.scale=current.viewport.scale*factor;state.fit=null;void render(prior.point,true,prior.align);
};
$('layout').onchange=()=> {state.mode=$('layout').value;state.scale=null;state.fit='page';void render();};
$('direction').onchange=()=> {state.direction=$('direction').value;void render();};
$('back').onclick=()=> {const old=state.history.pop();if(!old)return;state.page=old.page;state.scale=old.scale;state.fit=old.fit;void render(old.point,true,old.align);};
$('bookmarks').onclick=()=> {state.outline=!state.outline;$('outline').hidden=!state.outline;void render();};
function outlineTree(nodes,depth=0,seen=new Set()) {
  if(!Array.isArray(nodes) || depth>32) throw Error('Unsupported outline structure');
  const list=document.createElement('ul');
  for(const node of nodes) {
    if(!node || seen.has(node) || seen.size>=1000 || typeof node.title!=='string') throw Error('Unsupported outline structure');
    seen.add(node); const item=document.createElement('li'), button=document.createElement('button'); button.type='button'; button.textContent=node.title;
    button.onclick=()=> {state.outline=false;$('outline').hidden=true;if(node.dest!==null && node.dest!==undefined) void follow(node.dest);else if(node.url) {const classified=classifyLink({subtype:'Link',url:node.url});if(classified.kind==='external')void external(classified.url);else status('Unsupported bookmark action',true);}else status('Bookmark has no supported destination',true);};
    item.append(button); if(node.items?.length)item.append(outlineTree(node.items,depth+1,seen));list.append(item);
  }
  return list;
}
let resizeTimer; addEventListener('resize',()=> {clearTimeout(resizeTimer);resizeTimer=setTimeout(()=>{state.scale=null;state.fit='page';void render();},100);});
function shutdown() {
  if(state.cleanup) return state.cleanup;
  state.closed=true;state.request++;state.navigation++;stage.inert=true;stage.dataset.ready='false';
  clearTimeout(resizeTimer);cancelRender();keys.dispose();handles.clear();
  // PDF.js 6 removed PDFDocumentProxy.destroy. The loading task owns the
  // worker/transport, including shutdown while its promise is still pending.
  state.cleanup=Promise.resolve().then(()=>state.loadingTask?.destroy());
  return state.cleanup;
}
addEventListener('pagehide',()=> {void shutdown().catch(()=>status('Prototype cleanup failed',true));});
try {
  const manifest=await (await fetch('/source.json')).json(); state.documentId=manifest.sha256;
  if(state.closed) throw Error('Prototype closed during load');
  state.loadingTask=pdfjs.getDocument({url:'/document.pdf',isEvalSupported:false,enableXfa:false,disableAutoFetch:true,disableStream:true,
    cMapUrl:'/pdfjs/cmaps/',cMapPacked:true,standardFontDataUrl:'/pdfjs/standard_fonts/',wasmUrl:'/pdfjs/wasm/'});
  state.pdf=await state.loadingTask.promise;
  if(state.closed) throw Error('Prototype closed during load');
  const outline=await state.pdf.getOutline(); $('outline').replaceChildren(outlineTree(outline ?? []));
  await render();
} catch(error) {if(!state.closed){state.busy=false;controls();status(`Prototype unavailable: ${error.message}`,true);}}
