import {test} from 'node:test';
import assert from 'node:assert/strict';
import {resolveDestination,classifyLink,annotationRect,scrollAnchor,destinationView} from './destinations.mjs';
import {canonicalCoreModules} from './canonical-core.mjs';
import {fileURLToPath} from 'node:url';
import fs from 'node:fs';
const pdf={numPages:4,getDestination:async()=>[{num:9,gen:0},{name:'XYZ'},44,738,1.25],getPageIndex:async()=>2};
test('actual canonical browser modules compile without shadowing the reused controller',async()=> {
  const modules=canonicalCoreModules(fileURLToPath(new URL('../..',import.meta.url)));
  const layout=await import('data:text/javascript,'+encodeURIComponent(modules.layout));
  const keys=await import('data:text/javascript,'+encodeURIComponent(modules.keys));
  assert.equal(typeof keys.createPageTurnerKeys,'function');
  assert.deepEqual(layout.getVisualSpread(0,false,4,'rtl'),{left:1,right:0});
  assert.deepEqual(layout.getVisualSpread(4,false,5,'rtl'),{left:null,right:4});
});
test('named and direct original page identity are not doubled or converted',async()=> {
  assert.deepEqual(await resolveDestination(pdf,'chapter-three'),{pageIndex:2,mode:'XYZ',left:44,top:738,zoom:1.25});
  assert.deepEqual(await resolveDestination(pdf,[1,{name:'Fit'}]),{pageIndex:1,mode:'Fit'});
});
test('nullable XYZ and FitH semantics survive resolver',async()=> {
  assert.deepEqual(await resolveDestination(pdf,[0,{name:'XYZ'},null,240,0]),{pageIndex:0,mode:'XYZ',left:null,top:240,zoom:0});
  assert.deepEqual(await resolveDestination(pdf,[3,{name:'FitH'},null]),{pageIndex:3,mode:'FitH',top:null});
});
test('malformed, out-of-range, unsupported and unresolved destinations fail explicitly',async()=> {
  for(const dest of [null,[],[-1,{name:'Fit'}],[4,{name:'Fit'}],[0,{name:'FitR'},0,0,10,10],
    [0,{name:'XYZ'},0,NaN,1],[0,{name:'XYZ'},0,1,-1],[0,{name:'Fit'},'extra']]) await assert.rejects(resolveDestination(pdf,dest));
  await assert.rejects(resolveDestination({...pdf,getDestination:async()=>null},'missing'));
});
test('document replacement during named lookup or page-ref lookup cannot navigate',async()=> {
  let current=true;
  await assert.rejects(resolveDestination({...pdf,getDestination:async()=>{current=false;return[0,{name:'Fit'}];}},'x',()=>current),/Stale/);
  current=true;
  await assert.rejects(resolveDestination({...pdf,getPageIndex:async()=>{current=false;return 2;}},[{num:9,gen:0},{name:'Fit'}],()=>current),/Stale/);
});
test('external HTTP links require intent; scripts, files, custom schemes and credentials are unsupported',()=> {
  assert.equal(classifyLink({subtype:'Link',url:'https://example.org/test'}).kind,'external');
  for(const url of ['javascript:alert(1)','file:///secret','intent://launch','https://user:pw@example.org']) assert.equal(classifyLink({subtype:'Link',unsafeUrl:url}).kind,'unsupported');
  assert.equal(classifyLink({subtype:'Link',dest:[0,{name:'Fit'}],actions:{U:['evil']}}).kind,'unsupported');
  assert.equal(classifyLink({subtype:'Link'}).kind,'unsupported');
  assert.equal(classifyLink({subtype:'Highlight'}).kind,'not-link');
});
test('link hit rectangle uses exactly the canvas/text viewport including rotation and crop',()=> {
  const viewport={convertToViewportPoint:(x,y)=>[y-30,590-x]};
  assert.deepEqual(annotationRect(viewport,[40,50,140,70]),{left:20,top:450,width:20,height:100});
  assert.throws(()=>annotationRect(viewport,[0,0,NaN,1]));
});
test('destination anchors are scroll-container-relative, never body offsetTop',()=> {
  const stage={scrollLeft:0,scrollTop:0,clientLeft:0,clientTop:0,clientWidth:900,clientHeight:1005};
  assert.deepEqual(scrollAnchor({left:13,top:153},{left:0,top:141},stage,[73,90]),{left:86,top:102});
  assert.deepEqual(scrollAnchor({left:-73,top:-90},{left:0,top:141},{...stage,scrollLeft:86,scrollTop:243},[73,90]),{left:86,top:102});
});
test('XYZ null/zero retains effective magnification and top-left, not center or new-page fit',()=> {
  const prior={effectiveScale:1.6,topLeft:[44,738],point:[300,400],scale:null,fit:'page'};
  for(const zoom of [null,0]) assert.deepEqual(destinationView({mode:'XYZ',left:null,top:null,zoom},prior,4/3),{scale:1.6,fit:null,point:[44,738]});
  assert.deepEqual(destinationView({mode:'XYZ',left:0,top:240,zoom:1.25},prior,4/3),{scale:1.25*(4/3),fit:null,point:[0,240]});
  assert.deepEqual(destinationView({mode:'Fit'},prior,4/3),{scale:null,fit:'page',point:null});
});
test('actual viewer shutdown owns the loading task, is idempotent and fences pending work',async()=> {
  const viewer=fs.readFileSync(new URL('./viewer.mjs',import.meta.url),'utf8');
  const start=viewer.indexOf('function shutdown() {'),end=viewer.indexOf("addEventListener('pagehide'",start);
  assert.ok(start>=0 && end>start,'Actual shutdown function must exist');
  let destroyed=0,cancelled=0,disposed=0;
  const state={cleanup:null,closed:false,request:5,navigation:8,loadingTask:{destroy:async()=>{destroyed++;}}};
  const stage={inert:false,dataset:{ready:'true'}},handles=new Map([[1,1]]);
  const shutdown=new Function('state','stage','resizeTimer','cancelRender','keys','handles',viewer.slice(start,end)+'; return shutdown;')
    (state,stage,undefined,()=>cancelled++,{dispose:()=>disposed++},handles);
  const first=shutdown();assert.equal(shutdown(),first);await first;
  assert.equal(destroyed,1);assert.equal(cancelled,1);assert.equal(disposed,1);assert.equal(handles.size,0);
  assert.deepEqual([state.closed,state.request,state.navigation,stage.inert,stage.dataset.ready],[true,6,9,true,'false']);
});
test('actual failed-surface controls block zoom without an exception and retain Fit recovery',()=> {
  const source=fs.readFileSync(new URL('./viewer.mjs',import.meta.url),'utf8');
  const snapshot=source.slice(source.indexOf('function snapshot()'),source.indexOf('function cancelRender()'));
  const controls=source.slice(source.indexOf('function controls()'),source.indexOf('async function external('));
  const zoom=source.slice(source.indexOf('for(const [id,factor]'),source.indexOf("$('layout').onchange"));
  const elements=Object.fromEntries(['previous','next','zoom-in','zoom-out','fit','layout','direction','back'].map(id=>[id,{disabled:false}]));
  const state={busy:false,pdf:null,closed:false,history:[],rendered:new Map(),page:0},stage={dataset:{ready:'false'}};
  let renders=0;
  const update=new Function('state','stage','$','render',snapshot+controls+zoom+';return controls;')(state,stage,id=>elements[id],()=>renders++);
  update();assert.equal(elements['zoom-in'].disabled,true);assert.equal(elements.fit.disabled,true);
  assert.doesNotThrow(()=>elements['zoom-in'].onclick());assert.equal(renders,0);
  state.pdf={numPages:4};state.page=2;state.rendered.set(0,{});update();
  assert.equal(elements['zoom-out'].disabled,true);assert.equal(elements.fit.disabled,false);
  assert.doesNotThrow(()=>elements['zoom-out'].onclick());assert.equal(renders,0);
});
