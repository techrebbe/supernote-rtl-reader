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

  return originalClosePluginView(...args);
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
        handoffAttemptedThisActivation = false;
        globalThis.RTL_READER_EDIT_HANDOFF_DONE = false;
        console.log('RTL_READER_OPEN v0.4.24-edit-exp2-native-reader-v2');
        DeviceEventEmitter.emit(RTL_READER_ACTIVATE_EVENT);
      };
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
