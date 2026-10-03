'use strict';
// Actual production controller; controlled native/SDK responses, no device IO.
const test = require('node:test');
const assert = require('node:assert/strict');
const MODULE = require.resolve('../overlay/savedInk');
const FILE = '/storage/emulated/0/Document/RTL_INK_GEOMETRY_T008_20261002.pdf';
const DIR = '/data/user/0/com.ratta.supernote.pluginhost/files/plugins/snrtl20260726001';
const TOKENS = ['f3d09692-3a12-48cb-823b-62041968c761', 'e3d09692-3a12-48cb-823b-62041968c761'];
const batch = (pages = [0, 1]) => ({filePath: FILE, totalPages: 2, pluginDir: DIR, pageIndices: pages});
function deferred() { let resolve; const promise = new Promise(yes => { resolve = yes; }); return {promise, resolve}; }
async function entered(h, name, count) { for (let i=0; i<200 && h.calls.filter(c=>c.name===name).length<count; ++i) await Promise.resolve(); assert.equal(h.calls.filter(c=>c.name===name).length,count); }
function harness(overrides = {}) {
  delete require.cache[MODULE];
  const production = require(MODULE);
  let current = batch();
  const calls = [];
  const records = new Map();
  let issued = 0;
  const defaults = {
    currentContext: async () => current,
    getPageSize: async () => ({success:true,result:{width:1404,height:1872}}),
    prepare: async context => {
      const profile = production.selectSavedInkProfile(FILE, 2, context.pageIndex);
      const token = TOKENS[issued++];
      const record = {token,filePath:FILE,pageIndex:context.pageIndex,pageCount:2,
        profileId:profile.id,geometryId:profile.id,sourceSha256:profile.sourceSha256,
        width:1404,height:1872,pngPath:`${DIR}/saved-ink-cache/${token}/ink.png`,sourceVerified:true};
      records.set(token,record); return record;
    },
    generateThumbnail: async () => ({success:true,result:true}),
    finish: async ({token,missingMark}) => ({...records.get(token),sourceUnchanged:true,markUnchanged:true,
      ...(missingMark ? {missingMark:true} : {savedInkToken:token,decoded:true,
        sha256:'a'.repeat(64),byteLength:100,alphaMin:0,alphaMax:255})}),
    validateBatch: async ({tokens}) => ({firstToken:tokens[0],secondToken:tokens[1]??'',batchUnchanged:true}),
    discard: async ({token}) => ({token,discarded:true}),
  };
  const deps = {};
  for (const name of Object.keys(defaults)) deps[name] = async (...args) => {
    calls.push({name,args}); return (overrides[name] ?? defaults[name])(...args);
  };
  return {production,calls,controller:production.createSavedInkController(deps),records,
    change(value) {current=value;}, count(name) {return calls.filter(c=>c.name===name).length;}};
}

test('both profiles are exact-page-bound; invalid page sets allocate nothing', async () => {
  const h = harness();
  assert.equal(h.production.selectSavedInkProfile(FILE,2,1).id,'t008-page2-stock-portrait-fit-v1');
  for (const pages of [[],[undefined],[null],['0'],[NaN],[-1],[2],[0,0],[0,1,0]]) {
    assert.equal((await h.controller.runBatch(batch(pages))).reason,'unsupported_context');
  }
  assert.equal(h.count('prepare'),0); await h.controller.dispose();
});

test('one owner performs sequential two-page export then native whole-batch validation', async () => {
  const h = harness(); const result = await h.controller.runBatch(batch());
  assert.equal(result.status,'ready');
  assert.deepEqual(result.pages.map(p=>[p.pageIndex,p.savedInkToken]),[[0,TOKENS[0]],[1,TOKENS[1]]]);
  const prepares=h.calls.filter(c=>c.name==='prepare');
  assert.equal(prepares[0].args[0].siblingToken,undefined);
  assert.equal(prepares[1].args[0].siblingToken,TOKENS[0]);
  assert.ok(h.calls.findIndex(c=>c.name==='finish') < h.calls.indexOf(prepares[1]));
  assert.equal(h.count('validateBatch'),1);
  assert.equal((await h.controller.runBatch(batch())).reason,'ink_retained');
  assert.deepEqual(await h.controller.dispose(),{status:'disposed'});
  assert.deepEqual(h.calls.filter(c=>c.name==='discard').map(c=>c.args[0].token),TOKENS);
});

test('single PAGE2 uses its own batch and profile', async () => {
  const h=harness(); h.change(batch([1]));
  const result=await h.controller.runBatch(batch([1]));
  assert.equal(result.status,'ready'); assert.equal(result.pages[0].pageIndex,1);
  assert.equal(h.calls.find(c=>c.name==='prepare').args[0].profileId,'t008-page2-stock-portrait-fit-v1');
  await h.controller.dispose();
});

test('native batch rejects a changed sibling snapshot: no partial ready output', async () => {
  const h=harness({validateBatch:async()=>{throw Error('mark changed');}});
  assert.equal((await h.controller.runBatch(batch())).status,'error');
  assert.equal(h.count('discard'),2); assert.equal(h.controller.getState().retained,false);
  await h.controller.dispose();
});

test('cancel during second SDK waits actual settlement before discarding both handles', async () => {
  const sdk=deferred(); let generated=0;
  const h=harness({generateThumbnail:()=>++generated===1?{success:true,result:true}:sdk.promise});
  const work=h.controller.runBatch(batch()); await entered(h,'generateThumbnail',2);
  const cleanup=h.controller.dispose(); assert.equal(h.count('discard'),0);
  sdk.resolve({success:true,result:true});
  assert.equal((await work).reason,'cancelled'); assert.deepEqual(await cleanup,{status:'disposed'});
  assert.deepEqual(new Set(h.calls.filter(c=>c.name==='discard').map(c=>c.args[0].token)),new Set(TOKENS));
});

test('page set away/back cancellation cannot publish old images', async () => {
  const sdk=deferred(); const h=harness({generateThumbnail:()=>sdk.promise});
  const work=h.controller.runBatch(batch()); await entered(h,'generateThumbnail',1);
  h.change(batch([1])); h.controller.cancel(); h.change(batch());
  sdk.resolve({success:true,result:true});
  assert.equal((await work).reason,'cancelled'); assert.equal(h.count('prepare'),1);
  await h.controller.dispose();
});

test('one missing annotation page retains its witness and does not hide its inked sibling', async () => {
  const h=harness({generateThumbnail:async(file,page)=>page===0?{success:false,error:{code:1302}}:{success:true,result:true}});
  const result=await h.controller.runBatch(batch()); assert.equal(result.status,'ready');
  assert.deepEqual(result.pages.map(p=>p.status),['no_page','ready']);
  assert.equal(result.pages[0].savedInkToken,undefined); assert.equal(result.pages[1].savedInkToken,TOKENS[1]);
  assert.equal(h.count('discard'),0); await h.controller.dispose(); assert.equal(h.count('discard'),2);
});

test('second SDK failure rejects whole batch and releases first retained ink', async () => {
  let generated=0; const h=harness({generateThumbnail:async()=>({success:true,result:++generated===1})});
  assert.equal((await h.controller.runBatch(batch())).reason,'generation_failed');
  assert.equal(h.count('discard'),2); assert.equal(h.count('validateBatch'),0);
  await h.controller.dispose();
});

test('two cleanup failures preserve both exact handles without overwrite', async () => {
  let fail=true;
  const h=harness({discard:async({token})=>{if(fail)throw Error('failed');return{token,discarded:true};}});
  await h.controller.runBatch(batch()); const cleanup=await h.controller.dispose();
  assert.equal(cleanup.reason,'cleanup_failed'); assert.deepEqual(cleanup.handles.map(x=>x.token),TOKENS);
  assert.equal(h.controller.getState().retained,true);
  fail=false; assert.deepEqual(await h.controller.release(),{status:'released'});
  assert.equal(h.controller.getState().retained,false);
});

test('second-page generation plus cleanup failure does not retry it in the same batch', async () => {
  let generated=0; let fail=true;
  const h=harness({generateThumbnail:async()=>({success:true,result:++generated===1}),
    discard:async({token})=>{if(fail&&token===TOKENS[1])throw Error('failed');return{token,discarded:true};}});
  const result=await h.controller.runBatch(batch()); assert.equal(result.reason,'cleanup_failed');
  assert.deepEqual(result.handles.map(x=>x.token),[TOKENS[1]]);
  assert.equal(h.calls.filter(c=>c.name==='discard'&&c.args[0].token===TOKENS[1]).length,1);
  fail=false; await h.controller.release(); await h.controller.dispose();
});

test('native duplicate issued token never triggers a second SDK or double cleanup', async () => {
  let n=0; const h=harness({prepare:async context=>{
    const profile=h.production.selectSavedInkProfile(FILE,2,context.pageIndex);
    const record={token:TOKENS[0],filePath:FILE,pageIndex:context.pageIndex,pageCount:2,
      profileId:profile.id,geometryId:profile.id,sourceSha256:profile.sourceSha256,width:1404,height:1872,
      pngPath:`${DIR}/saved-ink-cache/${TOKENS[0]}/ink.png`,sourceVerified:true};
    if(++n===1)h.records.set(TOKENS[0],record); return record;
  }});
  assert.equal((await h.controller.runBatch(batch())).reason,'duplicate_token');
  assert.equal(h.count('generateThumbnail'),1); assert.equal(h.count('discard'),1);
  await h.controller.dispose();
});
