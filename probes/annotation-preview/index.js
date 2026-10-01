import React, {useEffect, useState} from 'react';
import {AppRegistry, DeviceEventEmitter, Image} from 'react-native';
import {PluginManager} from 'sn-plugin-lib';
import App from './App';
import {name} from './app.json';

function Root() {
  const [epoch, setEpoch] = useState(0);
  useEffect(() => {
    const listener = DeviceEventEmitter.addListener('RTL_INK_PROBE_ACTIVATE', () => setEpoch(value => value + 1));
    return () => listener.remove();
  }, []);
  return <App key={epoch} />;
}

AppRegistry.registerComponent(name, () => Root);
PluginManager.init();
PluginManager.registerButton(1, ['DOC'], {
  id: 101, name: 'RTL Ink Probe', icon: Image.resolveAssetSource(require('./assets/icon.png')).uri, showType: 1,
});
PluginManager.registerButtonListener({onButtonPress: event => {
  if (event?.id === 101) {
    if (globalThis.RTL_INK_PROBE_BUSY === true) return;
    console.log('RTL_READER_OPEN v0.0.1-ink-probe');
    DeviceEventEmitter.emit('RTL_INK_PROBE_ACTIVATE');
  }
}});
