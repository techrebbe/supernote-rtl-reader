import {AppRegistry, Dimensions, Image, PanResponder} from 'react-native';
import App from './App';
import {name as appName} from './app.json';
import {PluginManager} from 'sn-plugin-lib';

const RTL_READER_BUTTON_ID = 100;
const icon = Image.resolveAssetSource(require('./assets/icon.png')).uri;

// Hardware testing on the Nomad shows that PluginHost mirrors horizontal tap
// coordinates even though PanResponder dx has the correct physical sign. App.js
// deliberately keeps the clean logical mapping; this small compatibility shim
// unmasks the physical X coordinate before the app's release handler sees it.
// Swipe behavior is unchanged because dx/dy are not modified.
const originalPanResponderCreate = PanResponder.create.bind(PanResponder);
PanResponder.create = config => {
  const originalRelease = config?.onPanResponderRelease;
  if (!originalRelease) return originalPanResponderCreate(config);

  return originalPanResponderCreate({
    ...config,
    onPanResponderRelease: (event, gestureState) => {
      const windowWidth = Math.max(1, Dimensions.get('window').width);
      const nativeEvent = event?.nativeEvent ?? {};
      const mirroredPageX = Number.isFinite(nativeEvent.pageX)
        ? windowWidth - nativeEvent.pageX
        : nativeEvent.pageX;
      const mirroredX0 = Number.isFinite(gestureState?.x0)
        ? windowWidth - gestureState.x0
        : gestureState?.x0;

      const correctedEvent = {
        ...event,
        nativeEvent: {
          ...nativeEvent,
          pageX: mirroredPageX,
        },
      };
      const correctedGestureState = {
        ...gestureState,
        x0: mirroredX0,
      };
      originalRelease(correctedEvent, correctedGestureState);
    },
  });
};

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
      console.log('RTL_READER_OPEN v0.0.4');
    }
  },
});