import React, {useEffect, useState} from 'react';
import {AppRegistry, DeviceEventEmitter, Image, NativeModules} from 'react-native';
import App from './App';
import {name as appName} from './app.json';
import {PluginManager} from 'sn-plugin-lib';

const {ReaderPreferencesModule} = NativeModules;
const RTL_READER_BUTTON_ID = 100;
const RTL_READER_ACTIVATE_EVENT = 'RTL_READER_ACTIVATE';
const icon = Image.resolveAssetSource(require('./assets/icon.png')).uri;

const originalClosePluginView = PluginManager.closePluginView.bind(PluginManager);
let handoffAttemptedThisActivation = false;

// App.js already flushes ReaderPreferencesModule.save() immediately before
// closePluginView(). Intercept that final close call so the native bridge can
// synchronize the just-saved lastPageIndex with Supernote's native reader.
// Regardless of handoff success/failure, still perform the normal plugin close.
PluginManager.closePluginView = async (...args) => {
  const transition = globalThis.RTL_READER_TRANSITION_IN_FLIGHT;
  if (transition && transition.allowClose !== true) {
    throw new Error('Reader hand-off or recovery is still in progress.');
  }
  if (globalThis.RTL_READER_KEY_EXIT_PENDING) {
    throw new Error('Reader close is already in progress.');
  }
  const keyOwner = globalThis.RTL_READER_KEY_OWNER ?? null;
  const keyExitPending = {};
  globalThis.RTL_READER_KEY_EXIT_PENDING = keyExitPending;
  try {
    keyOwner?.fence(); // Synchronous retirement, including queued pre-Close keys.
  // Last-resort gate for callers outside App's Close/Edit callbacks. Never
  // hand off/restart the native reader or close the host while the SDK can
  // still write its owned PNG, or while native bitmap leases remain undrained.
  const inkLifecycle = globalThis.RTL_READER_INK_LIFECYCLE;
  const inkExitPending = {};
  globalThis.RTL_READER_INK_EXIT_PENDING = inkExitPending;
  let inkClean = false;
  try {
    inkClean = await (inkLifecycle?.quiesce() ??
      globalThis.RTL_READER_INK_CLEANUP ?? Promise.resolve(true));
  } catch (_) {
    // Keep a failed/rejected cleanup fenced; never fall through to handoff.
  }
  if (inkClean !== true) {
    globalThis.RTL_READER_INK_CLEANUP_BLOCKED = true;
    if (globalThis.RTL_READER_INK_EXIT_PENDING === inkExitPending) {
      globalThis.RTL_READER_INK_EXIT_PENDING = null;
    }
    throw new Error('Saved ink cleanup could not be verified; the reader stayed open.');
  }
  if (globalThis.RTL_READER_INK_EXIT_PENDING === inkExitPending) {
    globalThis.RTL_READER_INK_EXIT_PENDING = null;
  }
  if (globalThis.RTL_READER_TRANSITION_IN_FLIGHT !== transition ||
      (transition && transition.allowClose !== true) ||
      (!transition && globalThis.RTL_READER_INK_LIFECYCLE !== inkLifecycle)) {
    throw new Error('Reader hand-off or recovery changed while saved ink was settling.');
  }
  // Edit already ran (and checked) the native handoff itself this activation.
  if (globalThis.RTL_READER_EDIT_HANDOFF_DONE === true || transition?.skipHandoff === true) {
    handoffAttemptedThisActivation = true;
  }
  if (!handoffAttemptedThisActivation) {
    handoffAttemptedThisActivation = true;
    try {
      if (!ReaderPreferencesModule?.handoffLastSavedPage) {
        throw new Error('Native handoff method is not registered.');
      }
      const result = await ReaderPreferencesModule.handoffLastSavedPage();
      console.log(
        `RTL_READER_HANDOFF_PREPARED page=${
          Number.isInteger(result?.pageIndex) ? result.pageIndex + 1 : 'unknown'
        } uid=${result?.uid ?? 'unknown'} config=${result?.configPath ?? 'unknown'}`,
      );
    } catch (error) {
      console.warn(
        'RTL_READER_HANDOFF_SKIPPED',
        error?.message ?? String(error),
      );
    }
  }

    if (globalThis.RTL_READER_KEY_OWNER && globalThis.RTL_READER_KEY_OWNER !== keyOwner) {
      throw new Error('Reader key owner changed during close.');
    }
    // Await host Close: never release this independent key fence after only
    // the SDK drain or native handoff has finished.
    return await originalClosePluginView(...args);
  } finally {
    if (globalThis.RTL_READER_KEY_EXIT_PENDING === keyExitPending) {
      globalThis.RTL_READER_KEY_EXIT_PENDING = null;
    }
  }
};

function ReaderRoot() {
  const [activation, setActivation] = useState(0);

  useEffect(() => {
    const subscription = DeviceEventEmitter.addListener(
      RTL_READER_ACTIVATE_EVENT,
      () => {
        setActivation(current => current + 1);
      },
    );
    return () => subscription.remove();
  }, []);

  return <App key={activation} />;
}

AppRegistry.registerComponent(appName, () => ReaderRoot);
PluginManager.init();

PluginManager.registerButton(1, ['DOC'], {
  id: RTL_READER_BUTTON_ID,
  name: 'RTL Reader',
  icon,
  showType: 1,
});

PluginManager.registerButtonListener({
  onButtonPress: event => {
    if (event?.id === RTL_READER_BUTTON_ID) {
      const activate = () => {
        if (globalThis.RTL_READER_TRANSITION_IN_FLIGHT) return;
        if (globalThis.RTL_READER_KEY_EXIT_PENDING) return;
        handoffAttemptedThisActivation = false;
        globalThis.RTL_READER_EDIT_HANDOFF_DONE = false;
        console.log('RTL_READER_OPEN v0.4.24-keys-exp2-native-reader-v2');
        DeviceEventEmitter.emit(RTL_READER_ACTIVATE_EVENT);
      };
      if (globalThis.RTL_READER_KEY_EXIT_PENDING) {
        console.log('RTL_READER_ACTIVATION_BLOCKED reason=close_in_flight');
        return;
      }
      const transition = globalThis.RTL_READER_TRANSITION_IN_FLIGHT;
      if (transition) {
        console.log('RTL_READER_ACTIVATION_BLOCKED reason=transition_in_flight');
        if (typeof transition.recoverAfterUnmount === 'function') {
          Promise.resolve().then(() => transition.recoverAfterUnmount())
            .then(recovered => {
              if (recovered === true) activate();
            })
            .catch(error => console.warn('RTL_READER_ORPHAN_RECOVERY_FAILED', error));
        }
        return;
      }
      activate();
    }
  },
});
