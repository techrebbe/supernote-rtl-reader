import React, {useEffect, useLayoutEffect, useRef, useState} from 'react';
import {findNodeHandle, NativeModules, requireNativeComponent, UIManager} from 'react-native';
import {createReaderKeySession} from './readerKeySession';

const NativeReaderKeyHost = requireNativeComponent('ReaderKeyHost');

export default function ReaderKeyView({controllerRef, context, currentContext, turn,
  onStatus, onLayout, children, ...viewProps}) {
  const viewRef = useRef(null);
  const ownerRef = useRef(null);
  const latest = useRef(null);
  const boundsRef = useRef(null);
  const [layoutEpoch, setLayoutEpoch] = useState(0);
  const [ownerEpoch, setOwnerEpoch] = useState(0);
  const [routeSpec, setRouteSpec] = useState(null);
  latest.current = {currentContext, turn, onStatus, onLayout};

  useEffect(() => {
    let live = true;
    const pending = {
      fence() { ownerRef.current?.fence(); },
      dispose() { live = false; ownerRef.current?.dispose(); },
    };
    controllerRef.current = pending;
    globalThis.RTL_READER_KEY_OWNER?.fence();
    globalThis.RTL_READER_KEY_OWNER = pending;
    const fail = () => {
      if (live) latest.current.onStatus('Unavailable: native key bridge failed. Close and reopen RTL Reader to retry.');
    };
    async function initialize() {
      try {
        const module = NativeModules.ReaderKeyModule;
        if (!module?.createRequestNamespace) throw new Error('missing key module');
        const namespace = await module.createRequestNamespace();
        if (!live) return;
        ownerRef.current = createReaderKeySession({namespace,
          currentContext: () => {
            const value = latest.current.currentContext();
            return {...value, blocked: value.blocked || boundsRef.current === null ||
              globalThis.RTL_READER_KEY_OWNER !== pending,
              presentationId: JSON.stringify([value.presentationId, boundsRef.current])};
          },
          turn: action => latest.current.turn(action),
          publishSpec: spec => { if (live) setRouteSpec(spec); },
          status: value => { if (live) latest.current.onStatus(value); },
          focus: requestId => {
            const tag = findNodeHandle(viewRef.current);
            const command = UIManager.getViewManagerConfig('ReaderKeyHost')?.Commands?.requestReaderKeyFocus;
            if (tag == null || command == null) throw new Error('missing native key host');
            UIManager.dispatchViewManagerCommand(tag, command, [requestId]);
          },
        });
        setOwnerEpoch(value => value + 1);
      } catch (_) { fail(); }
    }
    initialize();
    return () => {
      live = false;
      ownerRef.current?.dispose(); ownerRef.current = null;
      if (controllerRef.current === pending) controllerRef.current = null;
      if (globalThis.RTL_READER_KEY_OWNER === pending) globalThis.RTL_READER_KEY_OWNER = null;
    };
  }, [controllerRef]);

  useLayoutEffect(() => { ownerRef.current?.synchronize(); }, [context, layoutEpoch, ownerEpoch]);

  const onReaderKey = event => ownerRef.current?.handle(event.nativeEvent);
  const handleLayout = event => {
    const {width, height} = event.nativeEvent.layout;
    const next = Number.isFinite(width) && Number.isFinite(height) && width > 0 && height > 0
      ? [width, height] : null;
    if (JSON.stringify(next) !== JSON.stringify(boundsRef.current)) {
      ownerRef.current?.fence();
      boundsRef.current = next;
      setLayoutEpoch(value => value + 1);
    }
    latest.current.onLayout?.(event);
  };

  return (
    <NativeReaderKeyHost {...viewProps} ref={viewRef}
      {...(routeSpec ? {routeSpec} : {})}
      onReaderKey={onReaderKey}
      onTouchStart={() => ownerRef.current?.requestFocus()}
      onLayout={handleLayout}>
      {children}
    </NativeReaderKeyHost>
  );
}
