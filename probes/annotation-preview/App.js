import React, {useEffect, useRef, useState} from 'react';
import {BackHandler, DeviceEventEmitter, Dimensions, Image, NativeModules, Pressable, StyleSheet, Text, View} from 'react-native';
import {PluginCommAPI, PluginDocAPI, PluginFileAPI, PluginManager} from 'sn-plugin-lib';
import {createAnnotationPreviewProbe, T008_PROFILE_ID} from './annotationPreview';

const {AnnotationPreviewModule} = NativeModules;

async function result(promise) {
  const response = await promise;
  if (response?.success !== true) throw new Error(response?.error?.message || 'Native context unavailable');
  return response.result;
}

async function currentContext() {
  const filePath = await result(PluginCommAPI.getCurrentFilePath());
  const pageIndex = await result(PluginCommAPI.getCurrentPageNum());
  const totalPages = await result(PluginDocAPI.getCurrentTotalPages());
  const window = Dimensions.get('window');
  return {
    filePath, pageIndex, totalPages,
    orientation: window.width > window.height ? 'landscape' : 'portrait',
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
      getPageSize: async (...args) => {
        const response = await PluginFileAPI.getPageSize(...args);
        console.log(`RTL_INK_PROBE_CANVAS success=${response?.success === true} width=${response?.result?.width} height=${response?.result?.height}`);
        return response;
      },
    }, {enabled: true, profileId: T008_PROFILE_ID});
    session = {probe, value: null, closing: false, attempted: false, presentationEpoch: 0,
      notice: 'Disposable T008 PDF, PAGE 1, landscape only. One fixed 1404×1872 request; do not write, rotate or turn pages.'};
  }
  return session;
}

function publish(shared) {
  globalThis.RTL_INK_PROBE_BUSY = shared.closing || shared.probe.getState().busy || shared.probe.getState().retained;
  DeviceEventEmitter.emit(SESSION_EVENT);
}

function invalidatePresentation(shared) {
  shared.presentationEpoch += 1;
  shared.probe.cancel();
  // Keep the exact cleanup capability without republishing a completed image on
  // remount. Native ownership is not released by UI lifetime or rotation.
  shared.value = shared.value?.handle ? {status: 'stale', handle: shared.value.handle} : null;
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
    const rotation = Dimensions.addEventListener('change', () => {
      invalidatePresentation(shared); // Includes landscape -> portrait -> landscape ABA.
      shared.notice = 'Window changed. Any preview is invalid; cleanup is required before leaving.';
      publish(shared);
    });
    synchronize(); // Close the render-to-passive-effect missed-event window.
    const back = BackHandler.addEventListener('hardwareBackPress', () => {
      if (shared.closing || shared.probe.getState().busy || shared.probe.getState().retained) return true;
      return false;
    });
    return () => {
      mounted.current = false;
      invalidatePresentation(shared);
      listener.remove();
      rotation.remove();
      back.remove();
      // Do not discard in cleanup: the session retains both pending call and retry handle.
    };
  }, []);

  const run = async () => {
    if (shared.attempted || shared.closing || shared.probe.getState().busy || shared.probe.getState().retained) return;
    shared.attempted = true; // One attempt per diagnostic JS session, including failures.
    const presentationEpoch = shared.presentationEpoch;
    shared.notice = 'Waiting for the native handwriting renderer. Do not navigate or draw.';
    const pending = shared.probe.run({manual: true});
    publish(shared);
    let value = await pending;
    // A completed controller result can await delivery while the view unmounts.
    // Fence that separate UI-publication window without discarding its handle.
    if (presentationEpoch !== shared.presentationEpoch) value = {
      status: 'stale', reason: 'presentation_changed', ...(value?.handle ? {handle: value.handle} : {}),
    };
    shared.value = value;
    console.log(`RTL_INK_PROBE_RESULT status=${value.status} reason=${value.reason || 'none'}`);
    if (value.status === 'preview') console.log(`RTL_INK_PROBE_EVIDENCE ${JSON.stringify(value.evidence)}`);
    shared.notice = value.status === 'preview'
      ? `PNG ${value.evidence.width}×${value.evidence.height}; native canvas ${value.evidence.nativePageSizeBefore.width}×${value.evidence.nativePageSizeBefore.height}. Alignment NOT validated; inspect the retained output.`
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
      <Pressable disabled={busy || shared.attempted || Boolean(outcome?.handle)} onPress={run} style={styles.button}>
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
