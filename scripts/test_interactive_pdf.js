'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const api=require('../overlay/interactivePdf');
const context={filePath:'/doc/test.pdf',totalPages:4};
const owner=api.validateOwner({sessionId:'12',filePath:context.filePath,pageCount:4,sourceSha256:'a'.repeat(64)},context);
const request={owner,token:1,page:0,slot:'single',mode:'read',blocked:false,pose:null,width:600,height:800};
test('exact original document identity; no mismatched SDK count or path',()=>{
  assert.throws(()=>api.validateOwner({...owner,pageCount:3},context));
  assert.throws(()=>api.validateOwner({...owner,filePath:'/doc/other.pdf'},context));
  assert.throws(()=>api.validateOwner({...owner,sourceSha256:'old'},context));
});
test('every source/page/geometry/mode/pose fence mints a distinct request',()=>{
  const base=api.requestSpec(request);
  for(const change of [{token:2},{page:1},{slot:'right'},{mode:'text'},{blocked:true},
    {width:800},{height:600},{pose:{kind:'scale',scale:2}},{contentMode:'native_fill'},
    {owner:{...owner,sessionId:'13'}}]){
    const next=api.requestSpec({...request,...change});assert.notEqual(next.requestId,base.requestId);
    assert.equal(api.packetMatches({sessionId:base.sessionId,pageIndex:base.pageIndex,requestId:base.requestId},next),false);
  }
  assert.equal(api.packetMatches({sessionId:base.sessionId,pageIndex:base.pageIndex,requestId:base.requestId},base),true);
});
test('invalid geometry/pages/stamps fail explicitly',()=>{
  for(const change of [{token:0},{page:4},{page:1.5},{width:NaN},{height:0},{mode:'writer'},
    {blocked:'false'},{contentMode:'silent-default'},{pose:{kind:'scale',scale:Infinity}}])
    assert.throws(()=>api.requestSpec({...request,...change}));
});
test('document replacement drops old page/Edit authority, not explicit settings',()=>{
  const before={lastPageIndex:2,editReturn:{editPage:2},pdfSourceSha256:'b'.repeat(64),
    direction:'rtl',coverSeparate:false,pageTurnerEnabled:false};
  assert.deepEqual(JSON.parse(api.restoreSourcePreferences(JSON.stringify(before),owner.sourceSha256)),
    {direction:'rtl',coverSeparate:false,pageTurnerEnabled:false});
  const same={...before,pdfSourceSha256:owner.sourceSha256};
  assert.equal(api.restoreSourcePreferences(JSON.stringify(same),owner.sourceSha256),JSON.stringify(same));
});
test('Fit, named resolved page indices and nullable XYZ preserve meaning',()=>{
  assert.deepEqual(api.internalDestination({kind:'internal',pageIndex:3,mode:'Fit'},{},4),{page:3,pose:{kind:'Fit'}});
  assert.deepEqual(api.internalDestination({kind:'internal',pageIndex:2,mode:'XYZ',left:null,top:240,zoom:null},
    {scale:2,left:44,top:738},4),{page:2,pose:{kind:'XYZ',left:null,top:240,zoom:null,fromScale:2,fromLeft:44,fromTop:738}});
  for(const action of [{kind:'script'},{kind:'internal',pageIndex:4,mode:'Fit'},
    {kind:'internal',pageIndex:1,mode:'FitH'}])assert.throws(()=>api.internalDestination(action,{},4));
});
test('bookmarks retain hierarchy, title ordering and original destination',()=>{
  const action={kind:'internal',pageIndex:0,mode:'Fit'};
  const result=api.flattenOutline([{title:'Root',destination:action,children:[{title:'ברכה',destination:action,children:[]}]}]);
  assert.deepEqual(result.map(x=>[x.title,x.depth]),[['Root',0],['ברכה',1]]);
  assert.equal(result[1].action,action);
  assert.throws(()=>api.flattenOutline([{title:'bad',children:null}]));
});
