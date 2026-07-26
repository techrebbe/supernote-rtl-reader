import {AppRegistry, Image} from 'react-native';
import App from './App';
import {name as appName} from './app.json';
import {PluginManager} from 'sn-plugin-lib';

const RTL_READER_BUTTON_ID = 100;
const icon = Image.resolveAssetSource(require('./assets/icon.png')).uri;

AppRegistry.registerComponent(appName, () => App);
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
      console.log('RTL_READER_OPEN v0.0.5');
    }
  },
});