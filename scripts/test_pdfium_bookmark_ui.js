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
