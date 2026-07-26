import React, {useEffect, useRef, useState} from 'react';
import {
  ActivityIndicator,
  Dimensions,
  Image,
  Keyboard,
  NativeModules,
  PanResponder,
  Pressable,
  SafeAreaView,
  StatusBar,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import {PluginCommAPI, PluginDocAPI, PluginManager} from 'sn-plugin-lib';

const {PdfRendererModule} = NativeModules;
const SWIPE_THRESHOLD = 56;
const TAP_SLOP = 18;
const EDGE_ZONE = 0.28;

async function requireResult(promise, label) {
  const response = await promise;
  if (!response?.success) {
    throw new Error(response?.error?.message ?? `${label} failed`);
  }
  return response.result;
}

async function getDocumentContext() {
  const filePath = await requireResult(
    PluginCommAPI.getCurrentFilePath(),
    'getCurrentFilePath',
  );
  const pageIndex = await requireResult(
    PluginCommAPI.getCurrentPageNum(),
    'getCurrentPageNum',
  );

  let totalPages = null;
  try {
    const response = await PluginDocAPI.getCurrentTotalPages();
    if (response?.success && Number.isInteger(response.result)) {
      totalPages = response.result;
    }
  } catch (error) {
    console.warn('RTL_READER_TOTAL_PAGES_FAILED', error);
  }

  return {filePath, pageIndex, totalPages};
}

function clampPage(pageIndex, totalPages) {
  if (!Number.isInteger(totalPages) || totalPages < 1) {
    return Math.max(0, pageIndex);
  }
  return Math.max(0, Math.min(totalPages - 1, pageIndex));
}

export default function App() {
  const [documentContext, setDocumentContext] = useState(null);
  const [pageIndex, setPageIndex] = useState(null);
  const [totalPages, setTotalPages] = useState(null);
  const [imageUri, setImageUri] = useState(null);
  const [rendering, setRendering] = useState(true);
  const [fatalError, setFatalError] = useState(null);
  const [direction, setDirection] = useState('rtl');
  const [chromeVisible, setChromeVisible] = useState(true);
  const [jumpOpen, setJumpOpen] = useState(false);
  const [jumpText, setJumpText] = useState('');

  const mountedRef = useRef(true);
  const renderTokenRef = useRef(0);
  const pageAreaWidthRef = useRef(Math.max(1, Dimensions.get('window').width));

  useEffect(() => {
    mountedRef.current = true;

    async function initialize() {
      try {
        if (!PdfRendererModule?.renderPage) {
          throw new Error('Native PDF renderer is not registered.');
        }

        const context = await getDocumentContext();
        if (!context.filePath?.toLowerCase().endsWith('.pdf')) {
          throw new Error('RTL Reader v0.0.2 currently supports PDF documents only.');
        }

        if (!mountedRef.current) return;
        setDocumentContext(context);
        setPageIndex(context.pageIndex);
        setTotalPages(context.totalPages);
        console.log(
          `RTL_READER_OPENED file=${context.filePath} page=${context.pageIndex + 1}`,
        );
      } catch (error) {
        console.error('RTL_READER_INIT_FAILED', error);
        if (mountedRef.current) {
          setFatalError(error?.message ?? String(error));
          setRendering(false);
        }
      }
    }

    initialize();
    return () => {
      mountedRef.current = false;
      renderTokenRef.current += 1;
    };
  }, []);

  useEffect(() => {
    if (!documentContext || !Number.isInteger(pageIndex)) return;

    const token = ++renderTokenRef.current;

    async function renderPage() {
      try {
        setRendering(true);
        const viewportWidth = Math.max(
          600,
          Math.round(pageAreaWidthRef.current || Dimensions.get('window').width),
        );
        const rendered = await PdfRendererModule.renderPage(
          documentContext.filePath,
          pageIndex,
          viewportWidth,
        );

        if (!mountedRef.current || token !== renderTokenRef.current) return;
        if (!rendered?.base64) {
          throw new Error('Native PDF renderer returned no image data.');
        }

        setImageUri(`data:image/png;base64,${rendered.base64}`);
        if (Number.isInteger(rendered.pageCount)) {
          setTotalPages(rendered.pageCount);
        }
        setFatalError(null);
        setRendering(false);

        console.log(
          `RTL_READER_RENDERED file=${documentContext.filePath} page=${pageIndex + 1} size=${rendered.width}x${rendered.height}`,
        );
      } catch (error) {
        console.error('RTL_READER_RENDER_FAILED', error);
        if (mountedRef.current && token === renderTokenRef.current) {
          setFatalError(error?.message ?? String(error));
          setRendering(false);
        }
      }
    }

    renderPage();
  }, [documentContext, pageIndex]);

  const close = () => {
    PluginManager.closePluginView().catch(error =>
      console.error('RTL_READER_CLOSE_FAILED', error),
    );
  };

  const goBy = delta => {
    setPageIndex(current => {
      if (!Number.isInteger(current)) return current;
      const next = clampPage(current + delta, totalPages);
      if (next !== current) {
        console.log(
          `RTL_READER_NAV from=${current + 1} to=${next + 1} direction=${direction}`,
        );
      }
      return next;
    });
  };

  const nextLogicalPage = () => goBy(1);
  const previousLogicalPage = () => goBy(-1);

  const handlePhysicalSwipe = dx => {
    if (dx > SWIPE_THRESHOLD) {
      if (direction === 'rtl') nextLogicalPage();
      else previousLogicalPage();
      return true;
    }
    if (dx < -SWIPE_THRESHOLD) {
      if (direction === 'rtl') previousLogicalPage();
      else nextLogicalPage();
      return true;
    }
    return false;
  };

  const handleEdgeTap = locationX => {
    const width = Math.max(1, pageAreaWidthRef.current);
    const fraction = locationX / width;

    if (fraction <= EDGE_ZONE) {
      if (direction === 'rtl') previousLogicalPage();
      else nextLogicalPage();
      return;
    }

    if (fraction >= 1 - EDGE_ZONE) {
      if (direction === 'rtl') nextLogicalPage();
      else previousLogicalPage();
      return;
    }

    setChromeVisible(value => !value);
  };

  const panResponderRef = useRef(null);
  if (!panResponderRef.current) {
    panResponderRef.current = PanResponder.create({
      onStartShouldSetPanResponder: () => true,
      onMoveShouldSetPanResponder: () => true,
      onPanResponderRelease: (event, gestureState) => {
        const {dx, dy} = gestureState;
        if (handlePhysicalSwipe(dx)) return;
        if (Math.abs(dx) <= TAP_SLOP && Math.abs(dy) <= TAP_SLOP) {
          handleEdgeTap(event.nativeEvent.locationX);
        }
      },
      onPanResponderTerminate: () => {},
    });
  }

  const toggleDirection = () => {
    setDirection(current => {
      const next = current === 'rtl' ? 'ltr' : 'rtl';
      console.log(`RTL_READER_DIRECTION ${next}`);
      return next;
    });
  };

  const openJump = () => {
    setJumpText(Number.isInteger(pageIndex) ? String(pageIndex + 1) : '');
    setJumpOpen(true);
  };

  const cancelJump = () => {
    Keyboard.dismiss();
    setJumpOpen(false);
  };

  const submitJump = () => {
    const requested = Number.parseInt(jumpText, 10);
    if (!Number.isFinite(requested)) return;
    const target = clampPage(requested - 1, totalPages);
    console.log(`RTL_READER_JUMP requested=${requested} target=${target + 1}`);
    setPageIndex(target);
    Keyboard.dismiss();
    setJumpOpen(false);
  };

  return (
    <SafeAreaView style={styles.root}>
      <StatusBar hidden />

      <View
        style={styles.pageArea}
        onLayout={event => {
          pageAreaWidthRef.current = Math.max(1, event.nativeEvent.layout.width);
        }}
        {...panResponderRef.current.panHandlers}>
        {imageUri ? (
          <Image
            source={{uri: imageUri}}
            resizeMode="contain"
            style={styles.pageImage}
          />
        ) : (
          <View style={styles.center} />
        )}
      </View>

      {rendering && (
        <View pointerEvents="none" style={styles.renderBadge}>
          <ActivityIndicator size="small" />
          <Text style={styles.renderBadgeText}>Rendering…</Text>
        </View>
      )}

      {fatalError && (
        <View style={styles.errorPanel}>
          <Text style={styles.errorTitle}>Could not render this page</Text>
          <Text style={styles.errorText}>{fatalError}</Text>
          <Pressable onPress={close} style={styles.panelButton}>
            <Text style={styles.panelButtonText}>Close</Text>
          </Pressable>
        </View>
      )}

      {chromeVisible && !fatalError && (
        <>
          <View style={styles.header}>
            <Pressable onPress={toggleDirection} style={styles.compactButton}>
              <Text style={styles.compactButtonText}>
                {direction === 'rtl' ? 'RTL' : 'LTR'}
              </Text>
            </Pressable>
            <Text style={styles.title}>RTL Reader</Text>
            <Pressable onPress={close} style={styles.compactButton}>
              <Text style={styles.compactButtonText}>Close</Text>
            </Pressable>
          </View>

          <View style={styles.footer}>
            <Pressable onPress={previousLogicalPage} style={styles.navButton}>
              <Text style={styles.navButtonText}>−</Text>
            </Pressable>
            <Pressable onPress={openJump} style={styles.pageButton}>
              <Text style={styles.pageLabel}>
                Page {Number.isInteger(pageIndex) ? pageIndex + 1 : '—'}
                {Number.isInteger(totalPages) ? ` / ${totalPages}` : ''}
              </Text>
            </Pressable>
            <Pressable onPress={nextLogicalPage} style={styles.navButton}>
              <Text style={styles.navButtonText}>+</Text>
            </Pressable>
          </View>
        </>
      )}

      {jumpOpen && (
        <View style={styles.jumpBackdrop}>
          <View style={styles.jumpPanel}>
            <Text style={styles.jumpTitle}>Jump to PDF page</Text>
            <TextInput
              autoFocus
              keyboardType="number-pad"
              onChangeText={setJumpText}
              onSubmitEditing={submitJump}
              returnKeyType="go"
              selectTextOnFocus
              style={styles.jumpInput}
              value={jumpText}
            />
            <Text style={styles.jumpHint}>
              {Number.isInteger(totalPages) ? `1–${totalPages}` : 'Enter a page number'}
            </Text>
            <View style={styles.jumpButtons}>
              <Pressable onPress={cancelJump} style={styles.panelButton}>
                <Text style={styles.panelButtonText}>Cancel</Text>
              </Pressable>
              <Pressable onPress={submitJump} style={styles.panelButton}>
                <Text style={styles.panelButtonText}>Go</Text>
              </Pressable>
            </View>
          </View>
        </View>
      )}
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  root: {
    flex: 1,
    backgroundColor: '#ffffff',
  },
  pageArea: {
    flex: 1,
    backgroundColor: '#ffffff',
  },
  pageImage: {
    flex: 1,
    width: '100%',
    backgroundColor: '#ffffff',
  },
  center: {
    flex: 1,
  },
  header: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    minHeight: 48,
    paddingHorizontal: 10,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    backgroundColor: '#ffffff',
    borderBottomWidth: 1,
    borderBottomColor: '#777777',
  },
  title: {
    fontSize: 18,
    fontWeight: '700',
    color: '#000000',
  },
  compactButton: {
    minWidth: 58,
    paddingHorizontal: 10,
    paddingVertical: 8,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#000000',
    borderRadius: 3,
    backgroundColor: '#ffffff',
  },
  compactButtonText: {
    fontSize: 16,
    color: '#000000',
  },
  footer: {
    position: 'absolute',
    left: 0,
    right: 0,
    bottom: 0,
    minHeight: 48,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#ffffff',
    borderTopWidth: 1,
    borderTopColor: '#777777',
  },
  navButton: {
    width: 64,
    height: 46,
    alignItems: 'center',
    justifyContent: 'center',
  },
  navButtonText: {
    fontSize: 28,
    lineHeight: 30,
    color: '#000000',
  },
  pageButton: {
    minWidth: 190,
    paddingHorizontal: 16,
    paddingVertical: 10,
    alignItems: 'center',
  },
  pageLabel: {
    fontSize: 16,
    color: '#000000',
  },
  renderBadge: {
    position: 'absolute',
    top: 58,
    alignSelf: 'center',
    flexDirection: 'row',
    alignItems: 'center',
    paddingHorizontal: 12,
    paddingVertical: 7,
    borderWidth: 1,
    borderColor: '#777777',
    backgroundColor: '#ffffff',
  },
  renderBadgeText: {
    marginLeft: 8,
    fontSize: 14,
    color: '#000000',
  },
  errorPanel: {
    position: 'absolute',
    left: 32,
    right: 32,
    top: '28%',
    padding: 24,
    alignItems: 'center',
    borderWidth: 2,
    borderColor: '#000000',
    backgroundColor: '#ffffff',
  },
  errorTitle: {
    fontSize: 21,
    fontWeight: '700',
    color: '#000000',
    marginBottom: 12,
  },
  errorText: {
    fontSize: 16,
    color: '#000000',
    textAlign: 'center',
    marginBottom: 18,
  },
  panelButton: {
    minWidth: 90,
    paddingHorizontal: 16,
    paddingVertical: 10,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#000000',
    borderRadius: 3,
    backgroundColor: '#ffffff',
  },
  panelButtonText: {
    fontSize: 17,
    color: '#000000',
  },
  jumpBackdrop: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: 'rgba(255,255,255,0.86)',
  },
  jumpPanel: {
    width: 330,
    maxWidth: '85%',
    padding: 22,
    alignItems: 'center',
    borderWidth: 2,
    borderColor: '#000000',
    backgroundColor: '#ffffff',
  },
  jumpTitle: {
    fontSize: 20,
    fontWeight: '700',
    color: '#000000',
    marginBottom: 14,
  },
  jumpInput: {
    width: 180,
    paddingVertical: 8,
    paddingHorizontal: 12,
    borderWidth: 1,
    borderColor: '#000000',
    fontSize: 24,
    textAlign: 'center',
    color: '#000000',
    backgroundColor: '#ffffff',
  },
  jumpHint: {
    marginTop: 8,
    marginBottom: 18,
    fontSize: 14,
    color: '#000000',
  },
  jumpButtons: {
    width: '100%',
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
});
