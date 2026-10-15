import React, {useEffect,useRef,useState} from 'react';
import {NativeModules,Pressable,ScrollView,Text,View,findNodeHandle,
  requireNativeComponent,UIManager} from 'react-native';
import {validateOwner,requestSpec,packetMatches,internalDestination,flattenOutline} from './interactivePdf';

const NativePage=requireNativeComponent('PdfiumPageView');
function serializeOperation(action) {
  const prior=globalThis.RTL_PDFIUM_SESSION_CHAIN ?? Promise.resolve();
  const operation=prior.catch(()=>{}).then(action);
  globalThis.RTL_PDFIUM_SESSION_CHAIN=operation.catch(()=>{});
  return operation;
}
export function useInteractivePdf(callbacks) {
  const live=useRef(true),closing=useRef(false),owned=useRef(null),closePromise=useRef(null);
  const sourceInvalid=useRef(false);
  const inputEpoch=useRef(0),inputBlockedRef=useRef(null);
  const latest=useRef(callbacks);latest.current=callbacks;
  const views=useRef(new Map()),poses=useRef(new Map()),scales=useRef(new Map()),anchors=useRef(new Map());
  const [owner,setOwner]=useState(null),[revision,setRevision]=useState(0);
  const [mode,setMode]=useState('read'),[focused,setFocused]=useState(null);
  const [selection,setSelection]=useState(null),[notice,setNotice]=useState('');
  const [bookmarks,setBookmarks]=useState(null),[modal,setModal]=useState(false);
  const modalRef=useRef(false),history=useRef([]);
  const current=()=>live.current && !closing.current && owned.current!=null && latest.current.current();
  const mutate=fn=>{if(!current()||modalRef.current||!latest.current.canInteract())return;latest.current.fence();fn();setSelection(null);setRevision(x=>x+1);};
  function cleanupFailed(error) {
    // Preserve an uncertain drain across mounts in this existing JS session.
    // No automatic retry/restart or empty-owner synthetic cleanup receipt.
    globalThis.RTL_PDFIUM_CLEANUP_FAILURE=error;return error;
  }
  async function drain(id,verify) {
    try{return await NativeModules.PdfiumReaderModule.close(id,verify);}
    catch(error){if(error?.code==='PDFIUM_SOURCE')sourceInvalid.current=true;else cleanupFailed(error);throw error;}
  }
  async function open(context) {
    if(closing.current)throw Error('PDF open cancelled');
    return serializeOperation(async()=>{
      if(!live.current||closing.current)throw Error('PDF open cancelled');
      if(globalThis.RTL_PDFIUM_CLEANUP_FAILURE)throw globalThis.RTL_PDFIUM_CLEANUP_FAILURE;
      const module=NativeModules.PdfiumReaderModule;
      if(!module?.open||!module?.close)throw Error('Interactive PDF engine is not registered');
      let result;
      try{result=await module.open(context.filePath,context.totalPages);}
      catch(error){if(error?.code==='PDFIUM_CLEANUP')cleanupFailed(error);throw error;}
      if(!live.current||closing.current){await drain(result.sessionId,false);throw Error('PDF open cancelled');}
      let value;
      try{value=validateOwner(result,context);}catch(error){await drain(result.sessionId,false);throw error;}
      owned.current=value;setOwner(value);setFocused(context.pageIndex);return value;
    });
  }
  function close(verify=true) {
    closing.current=true;setSelection(null);views.current.clear();
    if(globalThis.RTL_PDFIUM_CLEANUP_FAILURE)return Promise.reject(globalThis.RTL_PDFIUM_CLEANUP_FAILURE);
    if(closePromise.current)return !verify&&sourceInvalid.current?Promise.resolve(true):closePromise.current;
    closePromise.current=serializeOperation(async()=>{
      if(globalThis.RTL_PDFIUM_CLEANUP_FAILURE)throw globalThis.RTL_PDFIUM_CLEANUP_FAILURE;
      const value=owned.current;
      if(value){try{await drain(value.sessionId,verify);}
        finally{owned.current=null;}}
      return true;
    });
    return closePromise.current;
  }
  useEffect(()=>()=>{live.current=false;close(false).catch(()=>{});},[]);
  function fenceInput(){++inputEpoch.current;setSelection(null);}
  function syncInput(blocked){if(inputBlockedRef.current!==blocked){fenceInput();inputBlockedRef.current=blocked;}}
  function setModalValue(value) {fenceInput();latest.current.fence();modalRef.current=value;setModal(value);}
  function bind(page,ref,spec) {views.current.set(page,{ref,spec});}
  function unbind(page,ref,spec) {const value=views.current.get(page);
    if(value?.ref===ref && value.spec.requestId===spec.requestId)views.current.delete(page);}
  function follow(action,from,packet=null) {
    if(!current() || (packet && (!packetMatches(packet,views.current.get(packet.pageIndex)?.spec)||
      !latest.current.admit(views.current.get(packet.pageIndex)?.spec))))return;
    if(action?.kind==='external-blocked') {
      const uri=action.uri;
      if(typeof uri!=='string'||uri.length>4096||!/^https?:\/\/[a-z0-9.-]+(?::[0-9]+)?(?:[/?#][^\s\\]*)?$/i.test(uri)) {setNotice('External PDF action is unsupported');return;}
      setNotice('External link is disabled in this alpha: '+uri);return;
    }
    try {
      const target=internalDestination(action,from,owned.current.pageCount);
      mutate(()=>{history.current.push({page:latest.current.page(),pose:poses.current.get(latest.current.page())??null});
        if(history.current.length>32)history.current.shift();poses.current.set(target.page,target.pose);
        setFocused(target.page);latest.current.navigate(target.page);});
    }catch(error){setNotice(error.message??'Unsupported PDF action');}
  }
  function packet(event,expected,onRendered,onError) {
    const value=event.nativeEvent;
    if(!current()||!latest.current.admit(expected)||!packetMatches(value,expected)||!packetMatches(value,views.current.get(expected.pageIndex)?.spec))return;
    if(!['rendered','error'].includes(value.kind) && (expected.inputBlocked || modalRef.current ||
      !latest.current.canInteract() || value.inputEpoch!==inputEpoch.current ||
      value.inputEpoch!==views.current.get(expected.pageIndex)?.spec.inputEpoch))return;
    if(value.kind==='rendered'){scales.current.set(value.pageIndex,value.scale);
      anchors.current.set(value.pageIndex,{scale:value.scale,left:value.fromLeft,top:value.fromTop});onRendered(event);}
    else if(value.kind==='error'){onError(event);}
    else if(value.kind==='link'){try{follow(JSON.parse(value.action),{scale:value.fromScale,left:value.fromLeft,top:value.fromTop},value);}catch(_){setNotice('Invalid PDF link');}}
    else if(value.kind==='selection') {if(typeof value.text==='string'&&value.text.length<=40000){setSelection({page:value.pageIndex,stamp:value.requestId,inputEpoch:value.inputEpoch,text:value.text});setFocused(value.pageIndex);latest.current.navigate(value.pageIndex);}}
    else if(value.kind==='copy')setNotice(value.verified===true?'Copied text (verified)':'Clipboard could not be verified');
    else if(value.kind==='viewport')anchors.current.set(value.pageIndex,{scale:value.scale,left:value.fromLeft,top:value.fromTop});
    else if(value.kind==='gesture')latest.current.gesture({...value,slot:expected.slot});
  }
  function changeMode(next) {mutate(()=>{setMode(next);setNotice('');});}
  function focusPage(){return latest.current.page();} // Existing original-page state is authoritative.
  function zoom(factor) {mutate(()=>{const page=focusPage(),scale=scales.current.get(page);
    if(Number.isFinite(scale)&&scale>0)poses.current.set(page,{kind:'scale',scale:scale*factor});setMode('pan');});}
  function fit() {mutate(()=>{poses.current.clear();poses.current.set(focusPage(),{kind:'Fit'});setMode('read');setNotice('');});}
  function recoverFit() {
    if(!live.current||closing.current||!owned.current||sourceInvalid.current||modalRef.current||!latest.current.canRecover())return;
    latest.current.fence();latest.current.startRender();poses.current.clear();poses.current.set(focusPage(),{kind:'Fit'});
    setMode('read');setSelection(null);setNotice('');setRevision(x=>x+1);latest.current.clearError();
  }
  function back() {mutate(()=>{const item=history.current.pop();if(item){poses.current.set(item.page,item.pose);setFocused(item.page);latest.current.navigate(item.page);}});}
  function copy() {
    if(!current()||modalRef.current||!latest.current.canInteract()||!selection)return;
    const target=views.current.get(selection.page);
    if(!target||!latest.current.admit(target.spec)||target.spec.requestId!==selection.stamp ||
      selection.inputEpoch!==inputEpoch.current || target.spec.inputEpoch!==selection.inputEpoch)return;
    const tag=findNodeHandle(target.ref.current),command=UIManager.getViewManagerConfig('PdfiumPageView')?.Commands?.copySelection;
    if(tag!=null&&command!=null)UIManager.dispatchViewManagerCommand(tag,command,[selection.stamp,selection.inputEpoch]);
  }
  function showBookmarks() {
    if(!current()||modalRef.current||!latest.current.canInteract())return;
    try{const items=flattenOutline(JSON.parse(owned.current.outline));setBookmarks(items);setModalValue(true);}
    catch(_){setNotice('PDF bookmarks could not be read');}
  }
  const publicOwner={close,sourceInvalid};
  useEffect(()=>{globalThis.RTL_PDFIUM_OWNER=publicOwner;return()=>{
    if(globalThis.RTL_PDFIUM_OWNER===publicOwner)globalThis.RTL_PDFIUM_OWNER=null;
  };},[]);
  return {owner,revision,mode,selection,notice,bookmarks,modal,modalRef,sourceInvalid,inputEpoch,fenceInput,syncInput,
    isRetired:()=>closing.current,open,close,bind,unbind,packet,
    poses,changeMode,zoom,fit,recoverFit,back,copy,showBookmarks,history,
    hideBookmarks:()=>{setBookmarks(null);setModalValue(false);},
    chooseBookmark:action=>{setBookmarks(null);setModalValue(false);const page=focusPage();
      const anchor=anchors.current.get(page);
      if(action?.mode==='XYZ'&&!anchor){setNotice('Bookmark needs a settled source viewport');return;}
      follow(action,anchor??{});}};
}
export function InteractivePdfPage({reader,page,slot,token,width,height,blocked,inputBlocked,contentMode,onRendered,onError,style}) {
  const ref=useRef(null);
  const [layout,setLayout]=useState(null);
  const spec=layout?{...requestSpec({owner:reader.owner,token,page,slot,mode:reader.mode,blocked,
    pose:reader.poses.current.get(page)??null,width:layout.width,height:layout.height,contentMode}),inputBlocked,inputEpoch:reader.inputEpoch.current}:null;
  const serialized=JSON.stringify(spec);
  // Bind in render so delayed packets are rejected against the newest desired
  // spec immediately, not only after the native property commit.
  if(spec)reader.bind(page,ref,spec);
  useEffect(()=>()=>{if(spec)reader.unbind(page,ref,spec);},[page,spec?.requestId]);
  return <NativePage ref={ref} style={style} requestSpec={serialized}
    onLayout={event=>{const value=event.nativeEvent.layout;
      if(value.width>0&&value.height>0)setLayout(previous=>previous?.width===value.width&&previous?.height===value.height?previous:{width:value.width,height:value.height});}}
    onPdfiumEvent={event=>{if(spec)reader.packet(event,spec,onRendered,onError);}}/>;
}
export function InteractivePdfTools({reader,disabled,activePage}) {
  const action=(label,callback,off=false)=><Pressable key={label} disabled={disabled||off}
    onPress={callback} style={{padding:9,opacity:(disabled||off)?0.45:1}}><Text>{label}</Text></Pressable>;
  return <View style={{flexDirection:'row',flexWrap:'wrap',backgroundColor:'white'}}>
    <Text style={{padding:9}}>Active p.{Number.isInteger(activePage)?activePage+1:'—'}</Text>
    {action('Read',()=>reader.changeMode('read'))}{action('Text',()=>reader.changeMode('text'))}
    {action('Pan',()=>reader.changeMode('pan'))}{action('−',()=>reader.zoom(.8))}
    {action('+',()=>reader.zoom(1.25))}{action('Fit',reader.fit)}{action('Bookmarks',reader.showBookmarks)}
    {action('Back',reader.back,reader.history.current.length===0)}{action('Copy',reader.copy,!reader.selection)}
    {reader.notice?<Text numberOfLines={2} ellipsizeMode="tail">{reader.notice}</Text>:null}
  </View>;
}
export function InteractivePdfBookmarks({reader}) {
  if(!reader.bookmarks)return null;
  return <View style={{position:'absolute',top:0,bottom:0,left:0,right:0,backgroundColor:'white',padding:20}}>
    <Pressable onPress={reader.hideBookmarks}><Text>Close bookmarks</Text></Pressable>
    <ScrollView>{reader.bookmarks.map((item,index)=><Pressable key={index}
      onPress={()=>reader.chooseBookmark(item.action)} style={{padding:14,paddingLeft:14+item.depth*16}}>
      <Text>{item.title}</Text></Pressable>)}</ScrollView>
  </View>;
}
