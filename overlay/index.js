import React, {useEffect, useState} from 'react';
import {AppRegistry, DeviceEventEmitter, Image} from 'react-native';
import App from './App';
import {name as appName} from './app.json';
import {PluginManager} from 'sn-plugin-lib';

const RTL_READER_BUTTON_ID = 100;
const RTL_READER_ACTIVATE_EVENT = 'RTL_READER_ACTIVATE';
const icon = Image.resolveAssetSource(require('./assets/icon.png')).uri;

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

  // PluginHost keeps the React Native view alive after closePluginView().
  // Changing the key forces the actual reader App to unmount/remount on every
  // toolbar activation, so it re-reads the currently open DOC/PDF and loads
  // that document's own persisted settings instead of retaining stale state.
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
      console.log('RTL_READER_OPEN v0.0.7');
      DeviceEventEmitter.emit(RTL_READER_ACTIVATE_EVENT);
    }
  },
});
