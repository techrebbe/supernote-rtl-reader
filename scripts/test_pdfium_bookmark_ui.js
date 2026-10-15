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
