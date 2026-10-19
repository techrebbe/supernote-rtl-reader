'use strict';
// Execute the generated index's real exclusion guards, without a native host.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict');
const source=fs.readFileSync(process.argv[2],'utf8').replace(/\r\n/g,'\n'),calls=[];
const s={globalThis:{RTL_READER_LIBRARY_OPEN_IN_FLIGHT:{}},PluginManager:{},
  originalClosePluginView:async()=>{calls.push('native-close');return true;},
  handoffSavedPage:async()=>{calls.push('handoff');return {};},
  RTL_READER_BUTTON_ID:100,RTL_READER_ACTIVATE_EVENT:'activate',
  DeviceEventEmitter:{emit:event=>calls.push(event)},console:{log:()=>{},warn:()=>{}},ReaderPreferencesModule:{}};
vm.createContext(s);
const close=source.slice(source.indexOf('PluginManager.closePluginView = async'),source.indexOf('\nfunction ReaderRoot'));
vm.runInContext(close,s);
const marker='  onButtonPress: ',begin=source.indexOf(marker)+marker.length,end=source.lastIndexOf('\n  },\n});');
assert.ok(begin>marker.length && end>begin);
const press=vm.runInContext('('+source.slice(begin,end)+'\n  })',s);
(async()=>{
  await assert.rejects(s.PluginManager.closePluginView(),/favourite/);
  press({id:100});assert.deepEqual(calls,[],'a new activation must not replace the opening owner');
  s.globalThis.RTL_READER_LIBRARY_OPEN_IN_FLIGHT=null;
  press({id:100});assert.deepEqual(calls,['activate']);
  assert.equal(s.globalThis.RTL_READER_EDIT_HANDOFF_DONE,false);
  console.log('Actual generated favourite close/activation exclusion guards PASS');
})().catch(error=>{console.error(error);process.exitCode=1;});
