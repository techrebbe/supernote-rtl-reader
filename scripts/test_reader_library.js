'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {entry,decodeLibrary,assertLibraryContext,assertLibraryOwner,openFavourite}=require('../overlay/readerLibrary');
const book={filePath:'/storage/emulated/0/Document/disposable.pdf',sourceSha256:'a'.repeat(64),pageCount:4};
const index=entries=>JSON.stringify({version:1,entries});
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};};
function harness(change={}) {
  const calls=[];let live=true;
  const response=value=>({success:true,result:value});
  const action=(name,result)=>async(...args)=>{calls.push([name,...args]);return result;};
  const deps={store:{verify:action('verify',true)},manager:{showPluginView:action('show',true)},
    files:{openFile:action('open',response(true))},comm:{getCurrentFilePath:action('path',response(book.filePath))},
    doc:{getCurrentTotalPages:action('count',response(4))},drain:action('drain',true),
    isCurrent:()=>live,wait:action('wait',true),ensureReadAccess:action('read',true),...change};
  return {deps,calls,cancel:()=>{live=false;},run:()=>openFavourite(book,deps)};
}
test('strict source-bound metadata; no saved-page or Edit-return authority',()=>{
  assert.deepEqual(entry({...book,lastPageIndex:3,editReturn:{bad:true}}),book);
  assert.deepEqual(decodeLibrary(index([book])),[book]);
  for(const value of [null,'',false,[],{}, {...book,filePath:'http://x/a.pdf'}, {...book,filePath:'/x/../a.pdf'},
    {...book,filePath:'/x/./a.pdf'},{...book,filePath:'/a\nb.pdf'},{...book,filePath:'/a\\b.pdf'},
    {...book,filePath:'/a.mark'},{...book,filePath:'a.pdf'},{...book,filePath:'/'+ 'a'.repeat(1025)+'.pdf'},
    {...book,sourceSha256:'a'.repeat(63)},{...book,sourceSha256:'A'.repeat(64)},
    {...book,pageCount:'4'},{...book,pageCount:0},{...book,pageCount:1.5},{...book,pageCount:10001}]) {
    assert.throws(()=>entry(value));
  }
  for(const raw of [null,'','[]','{}',index([book,book]),index(Array(51).fill(book)),
    JSON.stringify({version:'1',entries:[]}),JSON.stringify({version:2,entries:[]}),index([null]),'x'.repeat(100001)]) {
    assert.throws(()=>decodeLibrary(raw));
  }
  assert.equal(decodeLibrary(index(Array.from({length:50},(_,i)=>({...book,filePath:`/${i}.pdf`})))).length,50);
});
test('actual staged owner and current SDK context must match saved source before render',()=>{
  assertLibraryContext(book,{filePath:book.filePath,totalPages:4});assertLibraryContext(null,{});
  assertLibraryOwner(book,book);assertLibraryOwner(null,{});
  for(const target of [{...book,filePath:'/other.pdf'},{...book,pageCount:5}])
    assert.throws(()=>assertLibraryContext(target,{filePath:book.filePath,totalPages:4}));
  for(const value of [null,{...book,sourceSha256:'b'.repeat(64)},{...book,pageCount:5},{...book,filePath:'/other.pdf'}])
    assert.throws(()=>assertLibraryOwner(book,value));
});
test('one supported native open, native last page, exact context and source checks, then show',async()=>{
  const h=harness();assert.deepEqual(await h.run(),book);
  assert.deepEqual(h.calls.map(x=>x[0]),['drain','read','verify','open','path','count','path','verify','show']);
  assert.deepEqual(h.calls.find(x=>x[0]==='open'),['open',book.filePath,-1]);
  assert.equal(globalThis.RTL_READER_LIBRARY_OPEN_IN_FLIGHT,null);
});
test('ordinary native transition latency gets bounded read-only confirmation, never reopens',async()=>{
  const h=harness();let reads=0;
  h.deps.comm.getCurrentFilePath=async()=>{h.calls.push(['path']);return {success:true,result:++reads<3?'/old.pdf':book.filePath};};
  await h.run();assert.equal(h.calls.filter(x=>x[0]==='open').length,1);
  assert.equal(h.calls.filter(x=>x[0]==='wait').length,1);
});
test('confirmation bound exhausts without guessing a destination or retrying mutation',async()=>{
  const h=harness({doc:{getCurrentTotalPages:async()=>({success:true,result:99})}});
  await assert.rejects(h.run(),/timed out/);
  assert.equal(h.calls.filter(x=>x[0]==='open').length,1);
  assert.equal(h.calls.filter(x=>x[0]==='wait').length,7);
  assert.equal(h.calls.filter(x=>x[0]==='show').length,0);
});
test('a path switch during count read cannot satisfy confirmation',async()=>{
  let reads=0;const h=harness({comm:{getCurrentFilePath:async()=>({success:true,result:++reads%2?book.filePath:'/other.pdf'})}});
  await assert.rejects(h.run(),/timed out/);assert.ok(!h.calls.some(x=>x[0]==='show'));
});
for(const stage of ['drain','read','verify','open','path','count','show']) {
  test(`failure at ${stage} never mounts a reader or retries native open`,async()=>{
    const h=harness(),failure=async()=>{throw Error(stage+' failed');};
    if(stage==='verify')h.deps.store.verify=failure;
    else if(stage==='open')h.deps.files.openFile=failure;
    else if(stage==='path')h.deps.comm.getCurrentFilePath=failure;
    else if(stage==='count')h.deps.doc.getCurrentTotalPages=failure;
    else if(stage==='show')h.deps.manager.showPluginView=failure;
    else if(stage==='read')h.deps.ensureReadAccess=failure;
    else h.deps.drain=failure;
    await assert.rejects(h.run(),new RegExp(stage+' failed'));
    assert.ok(h.calls.filter(x=>x[0]==='open').length<=1);
    assert.equal(globalThis.RTL_READER_LIBRARY_OPEN_IN_FLIGHT,null);
  });
}
test('false/ambiguous native success and source verify replies fail closed',async()=>{
  for(const result of [null,true,{success:1,result:true},{success:true,result:1},{success:true,result:false},{success:false,result:true}]) {
    const h=harness({files:{openFile:async()=>result}});await assert.rejects(h.run(),/did not confirm/);
    assert.ok(!h.calls.some(x=>x[0]==='show'));
  }
  for(const result of [false,null,1,'true']) {
    const h=harness({store:{verify:async()=>result}});await assert.rejects(h.run());
    assert.ok(!h.calls.some(x=>x[0]==='open'));
  }
  const h=harness({manager:{showPluginView:async()=>false}});await assert.rejects(h.run(),/reopening/);
});
test('source replacement after SDK open prevents show/reader admission',async()=>{
  const h=harness();let checks=0;h.deps.store.verify=async()=>++checks===1;
  await assert.rejects(h.run(),/changed while opening/);assert.ok(!h.calls.some(x=>x[0]==='show'));
});
test('synchronous global lease rejects overlapping opens, including a replacement launch',async()=>{
  const hold=deferred(),h=harness({drain:()=>hold.promise}),second=harness();
  const first=h.run();await assert.rejects(second.run(),/still opening/);
  assert.deepEqual(second.calls,[]);h.cancel();hold.resolve(true);await assert.rejects(first,/cancelled/);
  assert.deepEqual(h.calls,[]);assert.equal(globalThis.RTL_READER_LIBRARY_OPEN_IN_FLIGHT,null);
});
test('unmount at each async boundary prevents all later actions',async()=>{
  for(const stage of ['drain','read','verify','open','path','count','show']) {
    const h=harness(),hold=deferred();let started=false;
    const stop=async()=>{started=true;await hold.promise;return stage==='path'?{success:true,result:book.filePath}:
      stage==='count'?{success:true,result:4}:stage==='open'?{success:true,result:true}:true;};
    if(stage==='verify')h.deps.store.verify=stop;else if(stage==='open')h.deps.files.openFile=stop;
    else if(stage==='path')h.deps.comm.getCurrentFilePath=stop;else if(stage==='count')h.deps.doc.getCurrentTotalPages=stop;
    else if(stage==='show')h.deps.manager.showPluginView=stop;else if(stage==='read')h.deps.ensureReadAccess=stop;else h.deps.drain=stop;
    const promise=h.run();while(!started)await new Promise(setImmediate);
    h.cancel();const before=h.calls.length;hold.resolve();await assert.rejects(promise,/cancelled/);
    assert.equal(h.calls.length,before,stage+' sent a later call');
  }
});
