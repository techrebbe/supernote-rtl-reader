import React, {useEffect,useRef,useState} from 'react';
import {BackHandler,NativeModules,Pressable,ScrollView,Text,View} from 'react-native';
import {PluginCommAPI,PluginDocAPI,PluginFileAPI,PluginManager} from 'sn-plugin-lib';
import {ensureFileReadAccess} from './fileReadAccess';
import {entry,decodeLibrary,openFavourite} from './readerLibrary';

const store = NativeModules.ReaderLibraryModule;
const buttonStyle = {padding:14,borderWidth:1,marginVertical:4};
const label = value => value.filePath.split('/').pop();
async function drainPreviousReader() {
  // The prior App's unmount queues its real PDF drain. Never open a different
  // native document before that queue and the serialized page save settle.
  await globalThis.RTL_PDFIUM_SESSION_CHAIN;
  await globalThis.RTL_READER_PREFERENCES_WRITE_CHAIN;
  const inkClean=await (globalThis.RTL_READER_INK_CLEANUP ?? Promise.resolve(true));
  if (inkClean!==true || globalThis.RTL_PDFIUM_CLEANUP_FAILURE || globalThis.RTL_READER_INK_CLEANUP_BLOCKED ||
      globalThis.RTL_READER_TRANSITION_IN_FLIGHT || globalThis.RTL_READER_KEY_EXIT_PENDING ||
      globalThis.RTL_READER_INK_EXIT_PENDING || globalThis.RTL_READER_INK_LIFECYCLE) {
    throw Error('The previous reader has not completed cleanup. No favourite was opened.');
  }
}
export default function ReaderLaunch({App}) {
  const live = useRef(true), busy = useRef(false);
  const [books,setBooks] = useState(null), [route,setRoute] = useState('loading');
  const [target,setTarget] = useState(null), [error,setError] = useState(''), [working,setWorking] = useState(false);
  useEffect(() => {
    live.current = true;
    Promise.resolve().then(() => store.load()).then(raw => {
      if (!live.current) return;
      const values = decodeLibrary(raw); setBooks(values); setRoute(values.length ? 'library' : 'reader');
    }).catch(() => {if (live.current) {setBooks([]);setRoute('library');setError('Favourites could not be loaded. The list was not reset. You can still read the current PDF.');}});
    return () => {live.current = false;};
  }, []);
  async function run(action) {
    if (busy.current || !live.current) return;
    busy.current = true; setWorking(true); setError('');
    try {await action();}
    catch (failure) {if (live.current) setError(failure?.message ?? 'Favourites operation failed.');}
    finally {busy.current = false;if (live.current) setWorking(false);}
  }
  async function close() {await run(async () => {
    await drainPreviousReader();if(!live.current)return;
    // No App was opened in this route. Close must not apply a previous book's
    // saved page merely because its path happens to be current in Supernote.
    const token={allowClose:true,skipHandoff:true};
    if(globalThis.RTL_READER_TRANSITION_IN_FLIGHT)throw Error('A reader transition is still pending.');
    globalThis.RTL_READER_TRANSITION_IN_FLIGHT=token;
    try {
      if(await PluginManager.closePluginView()!==true)throw Error('Supernote did not acknowledge closing the chooser.');
      live.current=false;
    }
    finally {if(globalThis.RTL_READER_TRANSITION_IN_FLIGHT===token)globalThis.RTL_READER_TRANSITION_IN_FLIGHT=null;}
  });}
  useEffect(() => {
    if (route === 'reader') return;
    const back = BackHandler.addEventListener('hardwareBackPress', () => {close();return true;});
    return () => back.remove();
  }, [route]);
  if (route === 'reader') return <App libraryTarget={target}/>;
  const control = (text,action) => <Pressable disabled={working || route==='loading'} onPress={() => run(action)}
    style={buttonStyle}><Text>{text}</Text></Pressable>;
  return <View style={{flex:1,backgroundColor:'white',padding:20}}>
    <Text style={{fontSize:24}}>RTL Reader favourites</Text>
    <Text>Choose a saved PDF, or read the PDF currently open in Supernote.</Text>
    <Text>Supernote's own file list still opens its native reader. Edit and Close also stay native.</Text>
    {error ? <Text accessibilityRole="alert">{error}</Text> : null}
    {working || route==='loading' ? <Text>Please wait…</Text> : null}
    {control('Read current PDF',async () => {await drainPreviousReader();if (live.current) {setTarget(null);setRoute('reader');}})}
    <ScrollView>{(books ?? []).map(book => <View key={book.filePath}>
      {control(label(book), async () => {
        const opened = await openFavourite(book, {store,manager:PluginManager,files:PluginFileAPI,
          comm:PluginCommAPI,doc:PluginDocAPI,drain:drainPreviousReader,
          ensureReadAccess:ensureFileReadAccess,isCurrent:()=>live.current,
          wait:ms=>new Promise(resolve=>setTimeout(resolve,ms))});
        if (live.current) {setTarget(opened);setRoute('reader');}
      })}
      <Text numberOfLines={2}>{book.filePath}</Text>
      {control('Remove favourite',async () => {const raw=await store.remove(book.filePath);
        if (live.current) setBooks(decodeLibrary(raw));})}
    </View>)}</ScrollView>
    <Pressable disabled={working || route==='loading'} onPress={close} style={buttonStyle}><Text>Close to native reader</Text></Pressable>
  </View>;
}
export function FavouriteButton({owner,disabled}) {
  const live=useRef(true), busy=useRef(false), latest=useRef(owner);latest.current=owner;
  const [saved,setSaved]=useState(false), [notice,setNotice]=useState(''), [ready,setReady]=useState(false);
  useEffect(() => {
    live.current=true;let current=true;setReady(false);setSaved(false);
    Promise.resolve().then(()=>store.load()).then(raw=>{
      if (!current || !live.current) return;
      setSaved(decodeLibrary(raw).some(book=>book.filePath===owner?.filePath && book.sourceSha256===owner?.sourceSha256));setReady(true);
    }).catch(()=>{if(current && live.current)setNotice('Favourites storage is unavailable; nothing was changed.');});
    return()=>{current=false;live.current=false;};
  }, [owner?.sessionId]);
  async function toggle() {
    if(disabled || !ready || busy.current || !owner || latest.current!==owner)return;
    busy.current=true;
    try {
      const value=entry(owner);
      const raw=saved ? await store.remove(value.filePath) :
        await store.put(value.filePath,value.sourceSha256,value.pageCount);
      if(live.current && latest.current===owner){
        setSaved(decodeLibrary(raw).some(book=>book.filePath===value.filePath && book.sourceSha256===value.sourceSha256));
        setNotice(saved?'Removed from favourites.':'Saved. Choose this PDF next time you open RTL Reader.');
      }
    }catch(failure){if(live.current && latest.current===owner)setNotice(failure?.message??'Could not save favourite.');}
    finally{busy.current=false;}
  }
  return <View style={{backgroundColor:'white'}}>
    <Pressable disabled={disabled || !ready || !owner} onPress={toggle} style={{padding:9}}>
      <Text>{saved?'Remove favourite':'Save to favourites'}</Text>
    </Pressable>{notice?<Text numberOfLines={2}>{notice}</Text>:null}
  </View>;
}
