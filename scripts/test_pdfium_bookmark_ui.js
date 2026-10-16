'use strict';
// Render the actual JSX component with controlled RN peers, not a second menu.
// Babel is supplied by the existing plug-in toolchain; no network/device access.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const root=path.resolve(__dirname,'..');
const resolve=name=>require.resolve(name,{paths:[process.env.BABEL_MODULE_ROOT,root].filter(Boolean)});
const transformed=require(resolve('@babel/core')).transformSync(
  fs.readFileSync(path.join(root,'overlay/InteractivePdfReader.js'),'utf8'),{
    babelrc:false,configFile:false,plugins:[resolve('@babel/plugin-transform-react-jsx'),
      resolve('@babel/plugin-transform-modules-commonjs')],
  }).code;
function menu(bookmarks){
  const calls=[],exports={};
  const reader={bookmarks,hideBookmarks:()=>calls.push('close'),
    canChooseBookmark:action=>action?.kind==='internal',chooseBookmark:action=>calls.push(action)};
  const React={createElement:(type,props,...children)=>({type,props:props??{},children:children.flat()})};
  const native={Pressable:'Pressable',ScrollView:'ScrollView',Text:'Text',View:'View',
    requireNativeComponent:()=>null};
  const sandbox={exports,require:name=>name==='react'?React:name==='react-native'?native:require('../overlay/interactivePdf')};
  vm.createContext(sandbox);vm.runInContext(transformed,sandbox);
  return {tree:exports.InteractivePdfBookmarks({reader}),calls,reader};
}
test('actual bookmark rows retain titles/hierarchy and disable unsupported parents only',()=>{
  const unsupported={kind:'unsupported'},supported={kind:'internal',pageIndex:2,mode:'Fit'};
  const m=menu([{title:'Unsupported parent',depth:0,action:unsupported},
    {title:'Valid child',depth:1,action:supported}]);
  const rows=m.tree.children.find(x=>x.type==='ScrollView').children;
  assert.equal(rows.length,2);assert.equal(rows[0].props.disabled,true);
  assert.equal(rows[0].props.accessibilityState.disabled,true);
  assert.ok(rows[0].props.style.opacity<rows[1].props.style.opacity);
  assert.equal(rows[0].children[0].children[0],'Unsupported parent');
  assert.equal(rows[1].children[0].children[0],'Valid child');
  assert.equal(rows[1].props.disabled,false);assert.equal(rows[1].props.accessibilityState.disabled,false);
  assert.ok(rows[1].props.style.paddingLeft>rows[0].props.style.paddingLeft);
  // Even direct invocation of a disabled row's stale callback cannot navigate.
  rows[0].props.onPress?.();assert.deepEqual(m.calls,[]);
  rows[1].props.onPress();assert.deepEqual(m.calls,[supported]);
  m.tree.children[0].props.onPress();assert.equal(m.calls.at(-1),'close');
});
test('closed bookmark modal renders nothing',()=>assert.equal(menu(null).tree,null));

test('actual child layout during fatal error keeps rejected pose blocked until explicit Fit scene',()=>{
  const refs=[],states=[],exports={};let refIndex,stateIndex;
  const React={createElement:(type,props,...children)=>({type,props:props??{},children:children.flat()}),
    useRef:init=>{const i=refIndex++;return refs[i]??(refs[i]={current:init});},
    useState:init=>{const i=stateIndex++;if(!(i in states))states[i]=init;
      return [states[i],value=>{states[i]=typeof value==='function'?value(states[i]):value;}];},
    useEffect:()=>{}};
  const native={requireNativeComponent:()=> 'PdfiumPageView'};
  const bindings=[];
  const reader={owner:{sessionId:'11',pageCount:4},mode:'pan',poses:{current:new Map([[0,{kind:'scale',scale:2.5}]])},
    inputEpoch:{current:0},bind:(page,ref,spec)=>bindings.push(spec),unbind:()=>{},packet:()=>{}};
  const sandbox={exports,require:name=>name==='react'?React:name==='react-native'?native:require('../overlay/interactivePdf')};
  vm.createContext(sandbox);vm.runInContext(transformed,sandbox);
  const props={reader,page:0,slot:'single',token:9,width:600,height:700,blocked:false,inputBlocked:false,contentMode:'fit'};
  const render=()=>{refIndex=stateIndex=0;return exports.InteractivePdfPage(props);};
  let view=render();view.props.onLayout({nativeEvent:{layout:{width:600,height:700}}});view=render();
  const rejected=JSON.parse(view.props.requestSpec);
  assert.equal(rejected.blocked,false);assert.equal(rejected.pose.scale,2.5);
  // The actual parent generator is separately checked to pass fatalError into
  // every slot's blocked prop. Exercise the real child's independent onLayout.
  props.blocked=true;view=render();
  view.props.onLayout({nativeEvent:{layout:{width:600,height:900}}});view=render();
  const behindPanel=JSON.parse(view.props.requestSpec);
  assert.notEqual(behindPanel.requestId,rejected.requestId);
  assert.equal(behindPanel.renderToken,9);assert.equal(behindPanel.pose.scale,2.5);
  assert.equal(behindPanel.blocked,true);assert.equal(behindPanel.height,900);
  // Existing recoverFit clears the pose/revision before clearing fatalError;
  // the parent then mints a fresh keyed native-view generation.
  reader.poses.current.set(0,{kind:'Fit'});reader.mode='read';props.token=10;props.blocked=false;
  view=render();const fit=JSON.parse(view.props.requestSpec);
  assert.equal(fit.pose.kind,'Fit');assert.equal(fit.blocked,false);assert.equal(fit.renderToken,10);
  assert.notEqual(fit.requestId,behindPanel.requestId);assert.equal(bindings.at(-1).requestId,fit.requestId);
});

let generatedApp;
function actualGeneratedApp() {
  if(generatedApp)return generatedApp;
  const os=require('node:os'),{spawnSync}=require('node:child_process');
  const temp=fs.mkdtempSync(path.join(os.tmpdir(),'pdfium-scene-jsx-'));
  try {
    const out=path.join(temp,'generated');
    // build.sh normalizes PYTHON_BIN for Git Bash; Node still spawns Windows
    // executables directly. Accept that exact drive form without another tool.
    let python=process.env.PYTHON_BIN;
    if(python&&process.platform==='win32')python=python.replace(/^\/([A-Za-z])\//,(_,drive)=>drive+':/');
    const interpreters=python?[[python]]:[['python3'],['python'],['py','-3']];
    let result;
    for(const [command,...prefix] of interpreters){
      result=spawnSync(command,[...prefix,path.join(root,'scripts/test_pdfium_integration.py'),'--emit',out],{encoding:'utf8'});
      if(result.error?.code!=='ENOENT')break; // Never mask a real generator failure.
    }
    assert.equal(result.status,0,result.stderr||result.error?.message);
    generatedApp=fs.readFileSync(path.join(out,'App.js'),'utf8').replace(/\r\n/g,'\n');
    return generatedApp;
  } finally {fs.rmSync(temp,{recursive:true,force:true});}
}

async function actualSceneTransition(app,effectiveMode) {
  // Run the real hook, real generated scene effect and all applicable slot JSX.
  // Deliberately defer the parent passive effect after the controller changes.
  const stores=new Map();let store;
  const React={createElement:(type,props,...children)=>({type,props:props??{},children:children.flat()}),
    useRef:initial=>{const i=store.ref++;return store.refs[i]??(store.refs[i]={current:initial});},
    useState:initial=>{const i=store.state++;if(!(i in store.states))store.states[i]=initial;
      const owner=store;return [owner.states[i],value=>{owner.states[i]=typeof value==='function'?value(owner.states[i]):value;}];},
    useEffect:()=>{}};
  const render=(key,fn)=>{store=stores.get(key);if(!store){store={refs:[],states:[]};stores.set(key,store);}
    store.ref=store.state=0;return fn();};
  const context={filePath:'/disposable.pdf',totalPages:4,pageIndex:0};
  const opened={sessionId:'11',filePath:context.filePath,pageCount:4,sourceSha256:'a'.repeat(64),outline:'[]'};
  const native={NativeModules:{PdfiumReaderModule:{open:async()=>({...opened}),close:async()=>true}},
    requireNativeComponent:()=> 'PdfiumPageView'};
  const s={exports:{},React,console:{log(){}},require:name=>name==='react'?React:name==='react-native'?native:require('../overlay/interactivePdf'),
    preferencesReady:true,documentContext:context,pageAreaReady:true,pageIndex:0,effectiveMode,direction:'rtl',coverSeparate:false,
    spreadSizing:'fit',measuredPageWidth:1000,pageAreaLayout:{height:700},window:{width:1000},
    totalPagesRef:{current:4},renderTokenRef:{current:8},nativeRenderRef:{current:{}},pdfiumSceneRef:{current:null},
    interactionTimingRef:{current:{pageIndex:null,startedAtMs:0}},lastNavigationDeltaRef:{current:1},
    fatalError:null,rendering:false,settingsOpen:false,jumpOpen:false,editBusy:false,
    styles:{pageImage:{}},savedInkTokenFor:()=>null,readerTransitionLocked:()=>false,
    setFatalError:value=>{s.fatalError=value;},setRendering:value=>{s.rendering=value;},setDisplay:value=>{s.display=value;},
    handleNativeRendered:()=>{},handleNativeError:()=>{}};
  vm.createContext(s);vm.runInContext(transformed,s);
  s.InteractivePdfPage=s.exports.InteractivePdfPage;
  const helpersStart=app.indexOf('function normalizePage('),helpersEnd=app.indexOf('function viewModeLabel(',helpersStart);
  assert.ok(helpersStart>=0&&helpersEnd>helpersStart);
  vm.runInContext(app.slice(helpersStart,helpersEnd),s);
  const start=app.lastIndexOf('  useEffect(() => {',app.indexOf('    if (!pdfium.owner'));
  const end=app.indexOf('\n\n  const handleNativeRendered',start);
  assert.ok(start>=0&&end>start);const effect=app.slice(start,end);
  const jsx=[...app.matchAll(/<InteractivePdfPage\b[\s\S]*?\/>/g)];assert.equal(jsx.length,3);
  const slotCode=new Map(jsx.map(match=>[match[0].match(/slot="(\w+)"/)[1],
    require(resolve('@babel/core')).transformSync('('+match[0]+')',{
      babelrc:false,configFile:false,plugins:[resolve('@babel/plugin-transform-react-jsx')]}).code]));
  const callbacks={current:()=>true,canInteract:()=>!s.rendering,canRecover:()=>true,
    startRender:()=>{s.rendering=true;},clearError:()=>{s.fatalError=null;},fence:()=>{},
    page:()=>s.pageIndex,navigate:value=>{s.pageIndex=value;},gesture:()=>{},
    admit:spec=>spec.renderToken===s.nativeRenderRef.current.token&&s.nativeRenderRef.current.expected.has(spec.pageIndex)};
  const hook=()=>{s.pdfium=render('hook',()=>s.exports.useInteractivePdf(callbacks));return s.pdfium;};
  hook();await s.pdfium.open(context);hook();
  s.useEffect=fn=>fn();vm.runInContext(effect,s);s.rendering=false;
  const slots=effectiveMode==='single'?['single']:['left','right'];
  function page(slot,resize=false) {
    const element=vm.runInContext(slotCode.get(slot),s);
    const key=element.props.key;
    let view=render(key,()=>element.type(element.props));
    view.props.onLayout({nativeEvent:{layout:{width:500,height:resize?710:700}}});
    view=render(key,()=>element.type(element.props));
    return {element,view,spec:JSON.parse(view.props.requestSpec)};
  }
  for(const slot of slots){const item=page(slot);assert.equal(item.spec.blocked,false,'settled scene is admitted');
    item.view.props.onPdfiumEvent({nativeEvent:{...item.spec,kind:'rendered',scale:1,fromLeft:0,fromTop:0}});}
  const oldToken=s.display.renderToken,oldKeys=slots.map(slot=>page(slot).element.props.key);
  s.pdfium.zoom(1.25);hook();assert.equal(s.pdfium.revision,1);assert.equal(s.pdfium.mode,'pan');
  for(const slot of slots)for(const resize of [false,true]){
    const item=page(slot,resize);assert.equal(item.spec.renderToken,oldToken);
    assert.equal(item.spec.blocked,true,'old display must block new controller pose before scene effect');
  }
  vm.runInContext(effect,s);
  assert.equal(s.display.pdfiumRevision,s.pdfium.revision,'new display owns the exact controller revision');
  assert.ok(s.display.renderToken>oldToken);
  for(const [index,slot] of slots.entries()){
    const item=page(slot);assert.notEqual(item.element.props.key,oldKeys[index]);
    assert.equal(item.spec.blocked,false,'fresh matching scene admits the intended request');
    assert.equal(item.spec.renderToken,s.display.renderToken);
    if(item.spec.pageIndex===0)assert.equal(item.spec.pose.scale,1.25);
    // An input-only/modal fence must not retire an otherwise matching raster.
    s.settingsOpen=true;assert.equal(page(slot).spec.blocked,false);assert.equal(page(slot).spec.inputBlocked,true);
    s.settingsOpen=false;s.fatalError='terminal failure';assert.equal(page(slot).spec.blocked,true);s.fatalError=null;
  }
  // Real explicit recovery advances revision before the error clears: the old
  // display remains blocked until the effect installs a fresh Fit generation.
  s.pdfium.recoverFit();hook();
  for(const slot of slots)assert.equal(page(slot,true).spec.blocked,true);
  vm.runInContext(effect,s);
  for(const slot of slots){const item=page(slot);assert.equal(item.spec.blocked,false);
    if(item.spec.pageIndex===0)assert.equal(item.spec.pose.kind,'Fit');}
  await s.pdfium.close(true);
}

test('actual zoom and Fit revisions fence retiring single/spread slots before the passive scene effect',async()=>{
  const app=actualGeneratedApp();
  for(const mode of ['single','spread'])await actualSceneTransition(app,mode);
});

test('actual scene regression rejects missing revision fence and either missing display stamp',async()=>{
  const app=actualGeneratedApp(),fence='Boolean(fatalError) || display.pdfiumRevision !== pdfium.revision';
  assert.equal(app.split(fence).length-1,3);
  await assert.rejects(actualSceneTransition(app.replaceAll(fence,'Boolean(fatalError)'),'single'),/old display must block/);
  const stamp='pdfiumRevision: pdfium.revision,';
  assert.equal(app.split(stamp).length-1,2);
  for(const [index,mode] of ['single','spread'].entries()){
    let at=-1;for(let i=0;i<=index;i++)at=app.indexOf(stamp,at+1);
    const mutant=app.slice(0,at)+app.slice(at+stamp.length);
    await assert.rejects(actualSceneTransition(mutant,mode),/settled scene is admitted/);
  }
});
