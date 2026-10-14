'use strict';
// Execute the actual hook closures. Only React/native bridge boundaries are
// mocked; no copied ownership, navigation, close or selection implementation.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),vm=require('node:vm');
const api=require('../overlay/interactivePdf');
const source=fs.readFileSync(require.resolve('../overlay/InteractivePdfReader.js'),'utf8');
const body=source.slice(source.indexOf('function serializeOperation'),source.indexOf('export function InteractivePdfPage'))
  .replace('export function useInteractivePdf','function useInteractivePdf');
const context={filePath:'/doc/disposable.pdf',totalPages:4,pageIndex:0};
const opened={sessionId:'11',filePath:context.filePath,pageCount:4,sourceSha256:'a'.repeat(64),
  outline:JSON.stringify([{title:'Chapter',destination:{kind:'internal',pageIndex:2,mode:'XYZ',left:null,top:738,zoom:null},children:[]}])};
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b});return {resolve,reject,promise};};
const flush=()=>new Promise(setImmediate);
function harness(module={},global={},overrides={}) {
  const refs=[],states=[],effects=[],calls=[];let refIndex=0,stateIndex=0,effectIndex=0,scene=1,page=0;
  const callbacks={current:()=>true,canInteract:()=>true,admit:spec=>spec?.renderToken===scene,
    canRecover:()=>true,startRender:()=>calls.push('start-render'),clearError:()=>calls.push('clear-error'),
    fence:()=>calls.push('fence'),page:()=>page,navigate:next=>{page=next;calls.push(['navigate',next]);},
    gesture:event=>calls.push(['gesture',event]),...overrides};
  const fake={open:async()=>({...opened}),close:async(id,verify)=>{calls.push(['close',id,verify]);return true;},...module};
  const sandbox={...api,globalThis:global,NativeModules:{PdfiumReaderModule:fake},callbacks,
    findNodeHandle:()=>123,UIManager:{getViewManagerConfig:()=>({Commands:{copySelection:1}}),
      dispatchViewManagerCommand:(...args)=>calls.push(['command',...args])},
    useRef:initial=>{const i=refIndex++;return refs[i]??(refs[i]={current:initial});},
    useState:initial=>{const i=stateIndex++;if(!(i in states))states[i]=initial;
      return [states[i],value=>{states[i]=typeof value==='function'?value(states[i]):value;}];},
    useEffect:setup=>{const i=effectIndex++;if(!(i in effects))effects[i]={setup};}};
  vm.createContext(sandbox);vm.runInContext(body,sandbox);
  let reader;
  function render(){refIndex=stateIndex=effectIndex=0;reader=vm.runInContext('useInteractivePdf(callbacks)',sandbox);
    for(const effect of effects)if(!effect.ran){effect.ran=true;effect.cleanup=effect.setup();}return reader;}
  render();
  return {render,get reader(){return reader;},calls,setScene:n=>{scene=n;},setPage:n=>{page=n;},
    async unmount(){for(const effect of effects)effect.cleanup?.();await global.RTL_PDFIUM_SESSION_CHAIN;},
    spec:(n=0)=>api.requestSpec({owner:opened,token:scene,page:n,slot:'single',mode:'read',blocked:false,width:600,height:800}),
    bind(spec){reader.bind(spec.pageIndex,{current:{}},spec);},
    packet(spec,extra,onRendered=()=>calls.push('rendered'),onError=()=>calls.push('error')){
      reader.packet({nativeEvent:{sessionId:spec.sessionId,requestId:spec.requestId,pageIndex:spec.pageIndex,...extra}},spec,onRendered,onError);
    }};
}
test('actual hook opens exact owner, registers global drain, closes once',async()=>{
  const h=harness();await h.reader.open(context);h.render();assert.equal(h.reader.owner.sessionId,'11');
  assert.ok(h.reader.owner.sourceSha256);await h.reader.close(true);await h.reader.close(true);
  assert.deepEqual(h.calls.filter(x=>Array.isArray(x)&&x[0]==='close'),[['close','11',true]]);await h.unmount();
});
test('malformed/mismatched open cleans only returned owner before rejecting',async()=>{
  const h=harness({open:async()=>({...opened,pageCount:3})});
  await assert.rejects(h.reader.open(context),/identity mismatch/);
  assert.deepEqual(h.calls.filter(x=>Array.isArray(x)&&x[0]==='close'),[['close','11',false]]);await h.unmount();
});
test('old scene packets cannot navigate, select, error or settle new scene',async()=>{
  const h=harness();await h.reader.open(context);h.render();const old=h.spec();h.bind(old);h.setScene(2);
  for(const kind of ['rendered','gesture','selection','error'])h.packet(old,{kind,text:'stale',dx:100,dy:0});
  assert.deepEqual(h.calls,[]);assert.equal(h.render().selection,null);await h.unmount();
});
test('input fence drops gestures/copy but still lets current rendering settle',async()=>{
  const h=harness();await h.reader.open(context);h.render();const spec={...h.spec(),inputBlocked:true};h.bind(spec);
  h.packet(spec,{kind:'gesture',dx:200,dy:0});h.packet(spec,{kind:'rendered',scale:2,fromLeft:44,fromTop:738});
  assert.deepEqual(h.calls,['rendered']);await h.unmount();
});
test('selection/copy use current exact stamp; stale copy never dispatches',async()=>{
  const h=harness();await h.reader.open(context);h.render();const spec=h.spec();h.bind(spec);
  h.packet(spec,{kind:'selection',text:'Original PDF words'});h.render();h.reader.copy();
  assert.equal(h.calls.filter(x=>Array.isArray(x)&&x[0]==='command').length,1);
  h.setScene(2);h.reader.copy();assert.equal(h.calls.filter(x=>Array.isArray(x)&&x[0]==='command').length,1);await h.unmount();
});
test('nullable bookmark uses observed current source anchor, never guessed0',async()=>{
  const h=harness();await h.reader.open(context);h.render();const spec=h.spec();h.bind(spec);
  h.packet(spec,{kind:'rendered',scale:2,fromLeft:44,fromTop:738});h.reader.showBookmarks();h.render();
  h.reader.chooseBookmark(h.reader.bookmarks[0].action);h.render();
  const pose=h.reader.poses.current.get(2);
  assert.equal(pose.fromLeft,44);assert.equal(pose.fromTop,738);assert.equal(pose.left,null);assert.equal(pose.zoom,null);
  assert.ok(h.calls.some(x=>Array.isArray(x)&&x[0]==='navigate'&&x[1]===2));await h.unmount();
});
test('unmount during open drains old owner before next activation opens',async()=>{
  const gate=deferred(),global={},events=[];
  const a=harness({open:async()=>{events.push('old-open');return gate.promise;},
    close:async id=>{events.push('old-close:'+id);return true;}},global);
  const first=a.reader.open(context);await flush();const unmounted=a.unmount();
  const b=harness({open:async()=>{events.push('new-open');return {...opened,sessionId:'12'};}},global);
  const next=b.reader.open(context);await flush();assert.deepEqual(events,['old-open']);
  gate.resolve({...opened});await assert.rejects(first,/cancelled/);await unmounted;await next;
  assert.deepEqual(events,['old-open','old-close:11','new-open']);await b.unmount();
});
test('source replacement error never downgrades Edit check; normal no-handoff close can drain',async()=>{
  const h=harness({close:async()=>{const e=Error('source changed');e.code='PDFIUM_SOURCE';throw e;}});
  await h.reader.open(context);h.render();await assert.rejects(h.reader.close(true),/source changed/);
  assert.equal(h.reader.sourceInvalid.current,true);await assert.rejects(h.reader.close(true),/source changed/);
  assert.equal(await h.reader.close(false),true);await h.unmount();
});
test('zoom after navigation uses authoritative original page, not old focused state',async()=>{
  const h=harness();await h.reader.open(context);h.render();h.setPage(2);const spec=h.spec(2);h.bind(spec);
  h.packet(spec,{kind:'rendered',scale:2,fromLeft:44,fromTop:738});h.reader.zoom(1.25);h.render();
  assert.equal(h.reader.poses.current.get(2).scale,2.5);assert.equal(h.reader.poses.current.has(0),false);await h.unmount();
});
test('Fit recovery fences and starts rendering before clearing error; cannot recover retired source',async()=>{
  const h=harness({close:async()=>{const e=Error('source changed');e.code='PDFIUM_SOURCE';throw e;}});
  await h.reader.open(context);h.render();h.reader.recoverFit();
  assert.deepEqual(h.calls,['fence','start-render','clear-error']);
  await assert.rejects(h.reader.close(true));h.reader.recoverFit();assert.equal(h.calls.length,3);await h.unmount();
});
