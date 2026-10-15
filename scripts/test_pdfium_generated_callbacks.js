'use strict';
// Execute corrected generated callback bodies, not a copied state machine.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const app=fs.readFileSync(process.argv[2],'utf8').replace(/\r\n/g,'\n');
const slice=(start,end)=>{const a=app.indexOf(start),b=app.indexOf(end,a);assert.ok(a>=0&&b>a);return app.slice(a,b);};
const helpers=slice('function normalizePage(', 'function viewModeLabel(');
const geometry=slice('  const readerKeyPageGeometry =','  readerKeyUiRef.current =');
const setter=slice('  const setPageIndex = value => {','  const displayRef =');
const fence=slice('  const fenceReaderKeys =','  const readerTransitionLocked =');
const calls=[];
const s={filePathRef:{current:'/test.pdf'},pageIndex:0,effectiveMode:'spread',direction:'rtl',coverSeparate:false,fatalError:null,
  totalPagesRef:{current:4},pageAreaWidthRef:{current:1000},renderTokenRef:{current:8},readerKeyPresentationRef:{current:null},
  pageIndexRef:{current:0},effectiveModeRef:{current:'spread'},coverSeparateRef:{current:false},directionRef:{current:'rtl'},
  readerKeyFenceEpochRef:{current:0},readerKeysRef:{current:{fence:()=>calls.push('key-fence')}},
  pdfiumInputFenceRef:{current:()=>calls.push('pdf-fence')},readerTransitionLocked:()=>false,
  invalidateSavedInkPresentation:()=>calls.push('ink-fence'),setPageIndexRaw:n=>calls.push(['page',n])};
vm.createContext(s);vm.runInContext(helpers+fence+setter,s);
vm.runInContext('{'+geometry+'}',s);assert.equal(s.readerKeyPresentationRef.current.afterToken,8);
s.renderTokenRef.current=9;vm.runInContext('setPageIndex(1)',s);s.pageIndex=1;
vm.runInContext('{'+geometry+'}',s);assert.equal(s.readerKeyPresentationRef.current.afterToken,8);
assert.ok(9>s.readerKeyPresentationRef.current.afterToken);assert.deepEqual(calls,['key-fence',['page',1]]);
calls.length=0;vm.runInContext('setPageIndex(2)',s);s.pageIndex=2;vm.runInContext('{'+geometry+'}',s);
assert.equal(s.readerKeyPresentationRef.current.afterToken,9);assert.deepEqual(calls,['pdf-fence','key-fence','ink-fence',['page',2]]);
// Execute the actual rollback through successful and failed preference repair.
const rollback=slice('    const rollback = async failure => {','\n\n    try {\n      await quiesceSavedInk();');
const repair=[];
Object.assign(s,{previous:{editReturn:null,payload:{lastPageIndex:0}},editReturnRef:{current:{}},latestPreferencesRef:{current:{}},
  editInFlightRef:{current:true},editRecoveryRef:{current:null},mountedRef:{current:true},
  savePreferences:async()=>repair.push('saved'),releaseReaderTransition:()=>repair.push('released'),
  setEditBusy:x=>repair.push(['busy',x]),setEditRecoveryAvailable:x=>repair.push(['recovery',x]),
  setEditNotice:x=>repair.push(['notice',x]),setFatalError:x=>repair.push(['fatal',x]),setRendering:x=>repair.push(['rendering',x]),
  pdfium:{isRetired:()=>true},EDIT_BLOCKED_MESSAGES:{handoff_failed:'handoff failed',rollback_failed:'repair failed'},
  SAVED_INK_CLEANUP_FAILED_MESSAGE:'ink blocked',console});
vm.runInContext(rollback+'\nglobalThis.runRollback=rollback;',s);
(async()=>{await s.runRollback('handoff_failed');assert.equal(s.editInFlightRef.current,false);
  assert.equal(s.editReturnRef.current,null);assert.deepEqual(s.latestPreferencesRef.current,{lastPageIndex:0});
  assert.ok(repair.some(x=>Array.isArray(x)&&x[0]==='fatal'&&x[1].includes('Close and reopen')));
  assert.ok(repair.some(x=>Array.isArray(x)&&x[0]==='rendering'&&x[1]===false));
  // Actual foreground effect: a post-rollback dock/layout resize must not clear
  // the terminal error, mint a token, render retired pixels or resurrect input.
  const foreground=slice('    if (!pdfium.owner','  }, [\n    preferencesReady,');
  const renderCalls=[];
  Object.assign(s,{pdfium:{owner:{sessionId:'11'},revision:0,isRetired:()=>true},
    measuredPageWidth:500,pageAreaLayout:{height:700},spreadSizing:'fit',pdfiumSceneRef:{current:'before'},
    interactionTimingRef:{current:{pageIndex:null,startedAtMs:0}},lastNavigationDeltaRef:{current:1},
    nativeRenderRef:{current:{token:9}},setDisplay:x=>renderCalls.push(['display',x]),
    setFatalError:x=>renderCalls.push(['fatal',x]),setRendering:x=>renderCalls.push(['rendering',x])});
  const tokenBefore=s.renderTokenRef.current;
  vm.runInContext('(function(){'+foreground+'})()',s);
  s.pageAreaLayout.height=900;vm.runInContext('(function(){'+foreground+'})()',s);
  assert.deepEqual(renderCalls,[]);assert.equal(s.renderTokenRef.current,tokenBefore);
  assert.equal(s.pdfiumSceneRef.current,'before');
  s.pdfium.isRetired=()=>false;s.readerTransitionLocked=()=>true;
  vm.runInContext('(function(){'+foreground+'})()',s);assert.deepEqual(renderCalls,[]);
  assert.equal(s.pdfiumSceneRef.current,null);
  // Execute the actual effect AND dependency tuple across React renders. A
  // pre-retirement Edit failure must rearm on unlock, including Auto rotation.
  const effectStart=app.lastIndexOf('  useEffect(() => {',app.indexOf('    if (!pdfium.owner'));
  const effectEnd=app.indexOf('\n\n  const handleNativeRendered',effectStart);
  assert.ok(effectStart>=0&&effectEnd>effectStart);
  const effect=app.slice(effectStart,effectEnd);let deps;
  Object.assign(s,{preferencesReady:true,documentContext:{filePath:'/test.pdf'},pageAreaReady:true,
    effectiveMode:'single',editBusy:false,fatalError:null,pageAreaLayout:{height:700},
    useEffect:(fn,next)=>{if(!deps||next.some((x,i)=>!Object.is(x,deps[i]))){deps=next;fn();}}});
  s.readerTransitionLocked=()=>s.editBusy;
  vm.runInContext(effect,s);assert.ok(renderCalls.some(x=>x[0]==='display'&&x[1].kind==='single'));
  s.editBusy=true;vm.runInContext(effect,s);assert.equal(s.pdfiumSceneRef.current,null);
  s.effectiveMode='spread';s.pageAreaLayout.height=500;vm.runInContext(effect,s);
  renderCalls.length=0;s.editBusy=false;vm.runInContext(effect,s);
  assert.ok(renderCalls.some(x=>x[0]==='display'&&x[1].kind==='spread'));
  s.editBusy=true;vm.runInContext(effect,s);renderCalls.length=0;
  s.editBusy=false;vm.runInContext(effect,s);
  assert.ok(renderCalls.some(x=>x[0]==='display'&&x[1].kind==='spread'));
  // Real H6b path: native raster rejection removes chrome, which resizes the
  // viewport. That layout must not clear the failure and silently retry zoom.
  const errorCallback=slice('  const handleNativeError =','\n\n  const close =');
  s.console={...console,error:()=>{}};
  s.setFatalError=value=>{s.fatalError=value;renderCalls.push(['fatal',value]);};
  vm.runInContext(errorCallback+'\nglobalThis.nativeError=handleNativeError;',s);
  s.nativeRenderRef.current.expected=new Set([0,1]);
  const failure='PDF page/zoom rejected: Zoom exceeds the shared raster budget; use Fit';
  s.nativeError({nativeEvent:{pageIndex:0,message:failure}},s.nativeRenderRef.current.token);
  assert.equal(s.fatalError,failure);renderCalls.length=0;
  const failedToken=s.renderTokenRef.current;
  vm.runInContext(effect,s);s.pageAreaLayout.height=750;vm.runInContext(effect,s);
  s.pageAreaLayout.height=900;vm.runInContext(effect,s);
  assert.deepEqual(renderCalls,[],'native failure survives chrome/layout changes');
  assert.equal(s.fatalError,failure);assert.equal(s.renderTokenRef.current,failedToken);
  // Explicit Try Fit (already independently hook-tested) changes revision,
  // starts rendering, and clears the error. Only then may a scene be minted.
  s.pdfium.revision++;s.fatalError=null;vm.runInContext(effect,s);
  assert.ok(renderCalls.some(x=>x[0]==='display'&&x[1].kind==='spread'));
  s.readerTransitionLocked=()=>false;s.pdfium.isRetired=()=>true;
  repair.length=0;s.editInFlightRef.current=true;s.savePreferences=async()=>{throw Error('disk repair failed');};
  await s.runRollback('handoff_failed');assert.equal(s.editInFlightRef.current,true);
  assert.equal(typeof s.editRecoveryRef.current,'function');assert.ok(!repair.includes('released'));
  console.log('Actual generated same-pair/navigation/retired-Edit/layout/rollback callbacks PASS');
})().catch(error=>{console.error(error);process.exitCode=1;});
