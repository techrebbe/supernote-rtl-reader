import React, {useEffect, useRef, useState} from 'react';
import {BackHandler, DeviceEventEmitter, Image, NativeModules, Pressable, StyleSheet, Text, View} from 'react-native';
import {PluginCommAPI, PluginDocAPI, PluginFileAPI, PluginManager} from 'sn-plugin-lib';
import {createAnnotationPreviewProbe} from './annotationPreview';

const {AnnotationPreviewModule} = NativeModules;

async function result(promise) {
  const response = await promise;
  if (response?.success !== true) throw new Error(response?.error?.message || 'Native context unavailable');
  return response.result;
}

async function currentContext() {
  return {
    filePath: await result(PluginCommAPI.getCurrentFilePath()),
    pageIndex: await result(PluginCommAPI.getCurrentPageNum()),
    totalPages: await result(PluginDocAPI.getCurrentTotalPages()),
  };
}

const SESSION_EVENT = 'RTL_INK_PROBE_SESSION_CHANGED';
// Ownership outlives an App remount; native token/cleanup retry is never stored only in a view.
let session = null;
function getSession() {
  if (!session) {
    const probe = createAnnotationPreviewProbe({
      currentContext,
      prepare: async ({filePath, pageIndex, width, height}) => {
        const directory = await PluginManager.getPluginDirPath();
        if (typeof directory !== 'string' || !directory) throw new Error('Diagnostic plugin directory unavailable');
        return AnnotationPreviewModule.prepare(filePath, pageIndex, width, height, directory);
      },
      finish: ({token, missingMark}) => AnnotationPreviewModule.finish(token, missingMark),
      discard: ({token}) => AnnotationPreviewModule.discard(token),
      generateThumbnail: (...args) => PluginFileAPI.generateMarkThumbnails(...args),
    }, {enabled: true});
    session = {probe, value: null, closing: false, notice: 'Disposable T004 PDF, PAGE 3 only. No writing or page changes during this probe.'};
  }
  return session;
}

function publish(shared) {
  globalThis.RTL_INK_PROBE_BUSY = shared.closing || shared.probe.getState().busy || shared.probe.getState().retained;
  DeviceEventEmitter.emit(SESSION_EVENT);
}

export default function App() {
  const shared = getSession();
  const [busy, setBusy] = useState(shared.probe.getState().busy || shared.closing);
  const [outcome, setOutcome] = useState(shared.value);
  const [notice, setNotice] = useState(shared.notice);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    const synchronize = () => {
      setBusy(shared.probe.getState().busy || shared.closing);
      setOutcome(shared.value);
      setNotice(shared.notice);
    };
    const listener = DeviceEventEmitter.addListener(SESSION_EVENT, synchronize);
    synchronize(); // Close the render-to-passive-effect missed-event window.
    const back = BackHandler.addEventListener('hardwareBackPress', () => {
      if (shared.closing || shared.probe.getState().busy || shared.probe.getState().retained) return true;
      return false;
    });
    return () => {
      mounted.current = false;
      shared.probe.cancel();
      listener.remove();
      back.remove();
      // Do not discard in cleanup: the session retains both pending call and retry handle.
    };
  }, []);

  const run = async () => {
    if (shared.closing || shared.probe.getState().busy || shared.probe.getState().retained) return;
    shared.notice = 'Waiting for the native handwriting renderer. Do not navigate or draw.';
    const pending = shared.probe.run({manual: true});
    publish(shared);
    const value = await pending;
    shared.value = value;
    console.log(`RTL_INK_PROBE_RESULT status=${value.status} reason=${value.reason || 'none'}`);
    shared.notice = value.status === 'preview'
      ? `PNG ${value.evidence.width}×${value.evidence.height}; alpha ${value.evidence.alphaMin}–${value.evidence.alphaMax}. Alignment/highlight coverage NOT validated.`
      : `${value.status}: ${value.reason || 'no image'}`;
    publish(shared);
  };

  const close = async () => {
    if (shared.closing || shared.probe.getState().busy) return;
    shared.closing = true;
    publish(shared);
    try {
    const value = shared.value;
    if (value?.handle) {
      const released = await shared.probe.release(value.handle);
      if (released.status !== 'released') {
        shared.notice = 'Owned preview cleanup failed. Retained for inspection; do not run another probe.';
        return;
      }
      shared.value = null;
    }
    // Stock plug-in close only. No RTL handoff wrapper, config rewrite, or kill.
    await PluginManager.closePluginView();
    } catch (error) {
      shared.notice = `Could not return: ${error?.message || String(error)}`;
    } finally {
      shared.closing = false;
      publish(shared);
    }
  };

  return <View style={styles.root}>
    <Text style={styles.title}>Native handwriting contract probe</Text>
    <Text style={styles.notice}>{notice}</Text>
    <View style={styles.actions}>
      <Pressable disabled={busy || Boolean(outcome?.handle)} onPress={run} style={styles.button}>
        <Text>Generate once</Text>
      </Pressable>
      <Pressable disabled={busy} onPress={close} style={styles.button}><Text>Return to stock reader</Text></Pressable>
    </View>
    {outcome?.status === 'preview' && <Image source={{uri: outcome.imageUri}} resizeMode="contain" style={styles.image} />}
  </View>;
}

const styles = StyleSheet.create({
  root: {flex: 1, backgroundColor: 'white', padding: 16},
  title: {fontSize: 22, color: 'black'}, notice: {fontSize: 15, color: 'black', marginVertical: 8},
  actions: {flexDirection: 'row'}, button: {borderWidth: 1, borderColor: 'black', padding: 12, marginRight: 12},
  image: {flex: 1, width: '100%', backgroundColor: '#e0e0e0'},
});
