import React, {useEffect, useState} from 'react';
import {
  ActivityIndicator,
  Dimensions,
  Image,
  NativeModules,
  Pressable,
  SafeAreaView,
  StatusBar,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import {PluginCommAPI, PluginDocAPI, PluginManager} from 'sn-plugin-lib';

const {PdfRendererModule} = NativeModules;

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
    if (response?.success) {
      totalPages = response.result;
    }
  } catch (error) {
    console.warn('RTL_READER_TOTAL_PAGES_FAILED', error);
  }

  return {filePath, pageIndex, totalPages};
}

export default function App() {
  const [state, setState] = useState({status: 'loading'});

  useEffect(() => {
    let mounted = true;

    async function loadCurrentPage() {
      try {
        if (!PdfRendererModule?.renderPage) {
          throw new Error('Native PDF renderer is not registered.');
        }

        const context = await getDocumentContext();
        if (!context.filePath?.toLowerCase().endsWith('.pdf')) {
          throw new Error('RTL Reader v0.0.1 currently supports PDF documents only.');
        }

        const viewportWidth = Math.max(
          600,
          Math.round(Dimensions.get('window').width),
        );
        const rendered = await PdfRendererModule.renderPage(
          context.filePath,
          context.pageIndex,
          viewportWidth,
        );

        if (!rendered?.base64) {
          throw new Error('Native PDF renderer returned no image data.');
        }

        if (mounted) {
          setState({
            status: 'ready',
            ...context,
            imageUri: `data:image/png;base64,${rendered.base64}`,
            renderedWidth: rendered.width,
            renderedHeight: rendered.height,
          });
        }

        console.log(
          `RTL_READER_RENDERED file=${context.filePath} page=${context.pageIndex + 1} size=${rendered.width}x${rendered.height}`,
        );
      } catch (error) {
        console.error('RTL_READER_RENDER_FAILED', error);
        if (mounted) {
          setState({
            status: 'error',
            message: error?.message ?? String(error),
          });
        }
      }
    }

    loadCurrentPage();
    return () => {
      mounted = false;
    };
  }, []);

  const close = () => {
    PluginManager.closePluginView().catch(error =>
      console.error('RTL_READER_CLOSE_FAILED', error),
    );
  };

  return (
    <SafeAreaView style={styles.root}>
      <StatusBar hidden />
      <View style={styles.header}>
        <Text style={styles.title}>RTL Reader</Text>
        <Pressable onPress={close} style={styles.closeButton}>
          <Text style={styles.closeText}>Close</Text>
        </Pressable>
      </View>

      {state.status === 'loading' && (
        <View style={styles.center}>
          <ActivityIndicator size="large" />
          <Text style={styles.statusText}>Rendering current PDF page…</Text>
        </View>
      )}

      {state.status === 'error' && (
        <View style={styles.center}>
          <Text style={styles.errorTitle}>Could not render this page</Text>
          <Text style={styles.errorText}>{state.message}</Text>
        </View>
      )}

      {state.status === 'ready' && (
        <View style={styles.reader}>
          <Image
            source={{uri: state.imageUri}}
            resizeMode="contain"
            style={styles.pageImage}
          />
          <Text style={styles.pageLabel}>
            Page {state.pageIndex + 1}
            {Number.isInteger(state.totalPages) ? ` / ${state.totalPages}` : ''}
          </Text>
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
  header: {
    minHeight: 56,
    paddingHorizontal: 18,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    borderBottomWidth: 1,
    borderBottomColor: '#999999',
  },
  title: {
    fontSize: 22,
    fontWeight: '700',
    color: '#000000',
  },
  closeButton: {
    paddingHorizontal: 14,
    paddingVertical: 10,
    borderWidth: 1,
    borderColor: '#000000',
    borderRadius: 4,
  },
  closeText: {
    fontSize: 18,
    color: '#000000',
  },
  center: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    padding: 32,
  },
  statusText: {
    marginTop: 16,
    fontSize: 18,
    color: '#000000',
  },
  errorTitle: {
    fontSize: 22,
    fontWeight: '700',
    color: '#000000',
    marginBottom: 12,
  },
  errorText: {
    fontSize: 17,
    color: '#000000',
    textAlign: 'center',
  },
  reader: {
    flex: 1,
    padding: 8,
  },
  pageImage: {
    flex: 1,
    width: '100%',
    backgroundColor: '#ffffff',
  },
  pageLabel: {
    paddingVertical: 6,
    textAlign: 'center',
    fontSize: 16,
    color: '#000000',
  },
});
