'use strict';
// Execute the actual launch/favourite JSX and closures with controlled RN/SDK
// boundaries. No device access and no duplicate navigation implementation.
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const root=path.resolve(__dirname,'..'),resolve=name=>require.resolve(name,{paths:[process.env.BABEL_MODULE_ROOT,root].filter(Boolean)});
const transformed=require(resolve('@babel/core')).transformSync(fs.readFileSync(path.join(root,'overlay/ReaderLaunch.js'),'utf8'),{
  babelrc:false,configFile:false,plugins:[resolve('@babel/plugin-transform-react-jsx'),resolve('@babel/plugin-transform-modules-commonjs')],
}).code;
const book={filePath:'/test/disposable.pdf',sourceSha256:'a'.repeat(64),pageCount:4,sessionId:'11'};
const index=entries=>JSON.stringify({version:1,entries}),tick=()=>new Promise(setImmediate);
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};};
function harness(raw=index([]),overrides={},globals={}) {
  const refs=[],states=[],effects=[],exports={},calls=[];let ri,si,ei;const cleanups=[];
  const React={createElement:(type,props,...children)=>({type,props:props??{},children:children.flat()}),
    useRef:initial=>{const i=ri++;return refs[i]??(refs[i]={current:initial});},
    useState:initial=>{const i=si++;if(!(i in states))states[i]=initial;
      return [states[i],value=>{states[i]=typeof value==='function'?value(states[i]):value;}];},
    useEffect:(setup,deps)=>{const i=ei++,old=effects[i];if(!old||deps.some((x,j)=>x!==old.deps[j])){
      old?.cleanup?.();effects[i]={setup,deps};}}};
  const store={load:async()=>raw,verify:async()=>true,put:async(...args)=>{calls.push(['put',...args]);return index([book]);},
    remove:async(...args)=>{calls.push(['remove',...args]);return index([]);},...overrides};
  const native={NativeModules:{ReaderLibraryModule:store},BackHandler:{addEventListener:(name,handler)=>{
    calls.push(['back',handler]);return {remove:()=>calls.push(['back-remove'])};}},
    Pressable:'Pressable',Text:'Text',View:'View',ScrollView:'ScrollView'};
  const manager={closePluginView:async()=>{calls.push(['close',globals.RTL_READER_TRANSITION_IN_FLIGHT]);return true;},
    hasPermission:async()=>1,requestPermission:async()=>1,showPluginView:async()=>{calls.push(['show']);return true;}};
  const files={openFile:async(...args)=>{calls.push(['open',...args]);return {success:true,result:true};}};
  const sandbox={exports,globalThis:globals,Promise,setTimeout,require:name=>name==='react'?React:name==='react-native'?native:
    name==='sn-plugin-lib'?{PluginManager:manager,PluginFileAPI:files,
      PluginCommAPI:{getCurrentFilePath:async()=>({success:true,result:book.filePath})},
      PluginDocAPI:{getCurrentTotalPages:async()=>({success:true,result:4})}}:name==='./readerLibrary'?require('../overlay/readerLibrary'):
    require('../overlay/fileReadAccess')};
  vm.createContext(sandbox);vm.runInContext(transformed+'\nexports.drainPreviousReader=drainPreviousReader;',sandbox);
  let component=exports.default,props={App:'ActualApp'};
  function render(){ri=si=ei=0;const tree=component(props);for(const effect of effects)if(!effect.ran){effect.ran=true;effect.cleanup=effect.setup();}return tree;}
  return {calls,exports,globals,manager,render,choose:name=>{component=exports[name];props={owner:book,disabled:false};},props,
    unmount:()=>{for(const effect of effects)effect.cleanup?.();},
    all(tree,type){return tree&&typeof tree==='object'?[...(tree.type===type?[tree]:[]),...(tree.children??[]).flatMap(c=>this.all(c,type))]:[];},
    button(tree,text){return this.all(tree,'Pressable').find(x=>this.all(x,'Text').some(t=>t.children.includes(text)));}};
}
test('empty library keeps current-document launch behavior; saved books show deliberate chooser',async()=>{
  const empty=harness();empty.render();await tick();assert.equal(empty.render().type,'ActualApp');empty.unmount();
  const saved=harness(index([book]));saved.render();await tick();const tree=saved.render();
  assert.ok(saved.button(tree,'disposable.pdf'));assert.ok(saved.button(tree,'Read current PDF'));
  assert.ok(saved.button(tree,'Remove favourite'));assert.ok(saved.button(tree,'Close to native reader'));
  assert.ok(saved.all(tree,'Text').some(t=>t.children.some(x=>typeof x==='string'&&x.includes('own file list'))));
  await saved.button(tree,'Read current PDF').props.onPress();assert.equal(saved.render().type,'ActualApp');saved.unmount();
});
test('corrupt store is not overwritten/reset and does not prevent current-document reading',async()=>{
  const h=harness('broken');h.render();await tick();const tree=h.render();
  assert.ok(h.all(tree,'Text').some(t=>t.children.some(x=>typeof x==='string'&&x.includes('not reset'))));
  assert.ok(!h.calls.some(x=>['put','remove'].includes(x[0])));
  await h.button(tree,'Read current PDF').props.onPress();assert.equal(h.render().type,'ActualApp');h.unmount();
});
test('launch drain waits for actual PDF, page-save and ink cleanup before proceeding',async()=>{
  const pdf=deferred(),prefs=deferred(),ink=deferred(),h=harness('',{},
    {RTL_PDFIUM_SESSION_CHAIN:pdf.promise,RTL_READER_PREFERENCES_WRITE_CHAIN:prefs.promise,RTL_READER_INK_CLEANUP:ink.promise});
  let done=false;const drain=h.exports.drainPreviousReader().then(()=>{done=true;});
  await tick();assert.equal(done,false);pdf.resolve();await tick();assert.equal(done,false);
  prefs.resolve();await tick();assert.equal(done,false);ink.resolve(true);await drain;assert.equal(done,true);
  for(const key of ['RTL_PDFIUM_CLEANUP_FAILURE','RTL_READER_INK_CLEANUP_BLOCKED','RTL_READER_TRANSITION_IN_FLIGHT',
    'RTL_READER_KEY_EXIT_PENDING','RTL_READER_INK_EXIT_PENDING','RTL_READER_INK_LIFECYCLE']) {
    h.globals[key]={};await assert.rejects(h.exports.drainPreviousReader(),/cleanup/);delete h.globals[key];
  }
  h.globals.RTL_READER_INK_CLEANUP=Promise.resolve(false);await assert.rejects(h.exports.drainPreviousReader(),/cleanup/);
});
test('removal changes only favourites metadata, not page preferences or native document',async()=>{
  const h=harness(index([book]));h.render();await tick();await h.button(h.render(),'Remove favourite').props.onPress();
  assert.deepEqual(h.calls.filter(x=>['put','remove','close'].includes(x[0])),[['remove',book.filePath]]);
  assert.ok(!h.button(h.render(),'disposable.pdf'));h.unmount();
});
test('actual launch row opens exactly one saved PDF then mounts target-bound App',async()=>{
  const h=harness(index([book]));h.render();await tick();const row=h.button(h.render(),'disposable.pdf');
  const first=row.props.onPress(),second=row.props.onPress();await Promise.all([first,second]);
  assert.deepEqual(h.calls.filter(x=>['open','show','close'].includes(x[0])),[['open',book.filePath,-1],['show']]);
  const tree=h.render();assert.equal(tree.type,'ActualApp');assert.equal(tree.props.libraryTarget.sourceSha256,book.sourceSha256);
  assert.equal(tree.props.libraryTarget.filePath,book.filePath);h.unmount();
});

test('early host resume reveals only the waiting chooser until post-open source verification completes',async()=>{
  const hold=deferred();let verified=0;
  const h=harness(index([book]),{verify:async()=>++verified===1?true:hold.promise});
  h.render();await tick();const pending=h.button(h.render(),'disposable.pdf').props.onPress();
  await tick();
  assert.deepEqual(h.calls.filter(x=>['open','show'].includes(x[0])),[['open',book.filePath,-1],['show']]);
  const waiting=h.render();assert.notEqual(waiting.type,'ActualApp');
  assert.ok(h.all(waiting,'Text').some(t=>t.children.includes('Please wait…')));
  assert.equal(h.button(waiting,'disposable.pdf').props.disabled,true);
  hold.resolve(true);await pending;
  assert.equal(h.render().type,'ActualApp');h.unmount();
});

test('a changed source after native open/resume leaves a visible chooser error, never an unverified App',async()=>{
  let verified=0;const h=harness(index([book]),{verify:async()=>++verified===1});
  h.render();await tick();await h.button(h.render(),'disposable.pdf').props.onPress();
  const tree=h.render();assert.notEqual(tree.type,'ActualApp');
  assert.ok(h.all(tree,'Text').some(t=>t.children.some(x=>typeof x==='string'&&x.includes('changed while opening'))));
  assert.deepEqual(h.calls.filter(x=>['open','show','close'].includes(x[0])),[['open',book.filePath,-1],['show']]);
  assert.equal(h.button(tree,'disposable.pdf').props.disabled,false);h.unmount();
});
test('chooser Close uses normal close with explicit no-page-handoff and duplicate close fenced',async()=>{
  const h=harness(index([book]));h.render();await tick();const close=h.button(h.render(),'Close to native reader');
  await close.props.onPress();await close.props.onPress();
  const calls=h.calls.filter(x=>x[0]==='close');assert.equal(calls.length,1);
  assert.equal(calls[0][1].skipHandoff,true);assert.equal(calls[0][1].allowClose,true);
  assert.equal(h.globals.RTL_READER_TRANSITION_IN_FLIGHT,null);h.unmount();
});
test('unacknowledged chooser Close is visible failure, releases only its lock and allows current-PDF recovery',async()=>{
  const h=harness(index([book]));h.manager.closePluginView=async()=>false;
  h.render();await tick();await h.button(h.render(),'Close to native reader').props.onPress();
  assert.ok(h.all(h.render(),'Text').some(t=>t.children.some(x=>typeof x==='string'&&x.includes('did not acknowledge'))));
  assert.equal(h.globals.RTL_READER_TRANSITION_IN_FLIGHT,null);
  await h.button(h.render(),'Read current PDF').props.onPress();assert.equal(h.render().type,'ActualApp');h.unmount();
});
test('actual save button stores authenticated owner, suppresses duplicate in-flight taps and survives unmount',async()=>{
  const hold=deferred(),h=harness(index([]),{put:async(...args)=>{h.calls.push(['put',...args]);return hold.promise;}});
  h.choose('FavouriteButton');h.render();await tick();const button=h.button(h.render(),'Save to favourites');
  const first=button.props.onPress(),second=button.props.onPress();await second;
  assert.deepEqual(h.calls,[['put',book.filePath,book.sourceSha256,4]]);
  h.unmount();hold.resolve(index([book]));await first;
});
test('actual favourite toggle never clobbers saved-page/Edit state; explicit remove only',async()=>{
  const h=harness(index([book]));h.choose('FavouriteButton');h.render();await tick();
  await h.button(h.render(),'Remove favourite').props.onPress();
  assert.deepEqual(h.calls,[['remove',book.filePath]]);h.unmount();
});
