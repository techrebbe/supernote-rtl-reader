import React, {useEffect, useRef, useState} from 'react';
import {
  ActivityIndicator,
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
  useWindowDimensions,
} from 'react-native';
import {PluginCommAPI, PluginDocAPI, PluginManager} from 'sn-plugin-lib';

const {PdfRendererModule} = NativeModules;
const SWIPE_THRESHOLD = 56;
const TAP_SLOP = 18;
const EDGE_ZONE = 0.28;
const CACHE_LIMIT = 8;

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

function cacheKey(pageIndex, width) {
  return `${pageIndex}:${width}`;
}

function normalizePage(pageIndex, totalPages) {
  if (!Number.isInteger(pageIndex) || pageIndex < 0) return null;
  if (Number.isInteger(totalPages) && pageIndex >= totalPages) return null;
  return pageIndex;
}

function getSpreadPair(pageIndex, coverSeparate, totalPages) {
  let earlier;
  let later;

  if (coverSeparate) {
    if (pageIndex <= 0) {
      earlier = 0;
      later = null;
    } else {
      const start = 1 + Math.floor((pageIndex - 1) / 2) * 2;
      earlier = start;
      later = start + 1;
    }
  } else {
    const start = Math.floor(pageIndex / 2) * 2;
    earlier = start;
    later = start + 1;
  }

  return {
    earlier: normalizePage(earlier, totalPages),
    later: normalizePage(later, totalPages),
  };
}

function getVisualSpread(pageIndex, coverSeparate, totalPages, direction) {
  const {earlier, later} = getSpreadPair(pageIndex, coverSeparate, totalPages);
  if (direction === 'rtl') {
    return {left: later, right: earlier};
  }
  return {left: earlier, right: later};
}

function cycleViewMode(current) {
  if (current === 'auto') return 'single';
  if (current === 'single') return 'spread';
  return 'auto';
}

function viewModeLabel(mode) {
  if (mode === 'single') return 'Single';
  if (mode === 'spread') return 'Spread';
  return 'Auto';
}

export default function App() {
  const window = useWindowDimensions();
  const isLandscape = window.width > window.height;

  const [documentContext, setDocumentContext] = useState(null);
  const [pageIndex, setPageIndex] = useState(null);
  const [totalPages, setTotalPages] = useState(null);
  const [display, setDisplay] = useState({kind: 'single', single: null});
  const [rendering, setRendering] = useState(true);
  const [fatalError, setFatalError] = useState(null);
  const [direction, setDirection] = useState('rtl');
  const [viewMode, setViewMode] = useState('auto');
  const [coverSeparate, setCoverSeparate] = useState(false);
  const [chromeVisible, setChromeVisible] = useState(true);
  const [jumpOpen, setJumpOpen] = useState(false);
  const [jumpText, setJumpText] = useState('');

  const effectiveMode =
    viewMode === 'auto' ? (isLandscape ? 'spread' : 'single') : viewMode;

  const mountedRef = useRef(true);
  const renderTokenRef = useRef(0);
  const pageAreaWidthRef = useRef(Math.max(1, window.width));
  const pageAreaLeftRef = useRef(0);
  const directionRef = useRef(direction);
  const totalPagesRef = useRef(totalPages);
  const effectiveModeRef = useRef(effectiveMode);
  const coverSeparateRef = useRef(coverSeparate);
  const cacheRef = useRef(new Map());
  const prefetchingRef = useRef(new Set());

  directionRef.current = direction;
  totalPagesRef.current = totalPages;
  effectiveModeRef.current = effectiveMode;
  coverSeparateRef.current = coverSeparate;
  pageAreaWidthRef.current = Math.max(1, window.width);

  const putCache = (key, value) => {
    const cache = cacheRef.current;
    if (cache.has(key)) cache.delete(key);
    cache.set(key, value);
    while (cache.size > CACHE_LIMIT) {
      const oldestKey = cache.keys().next().value;
      cache.delete(oldestKey);
    }
  };

  const renderPdfPage = async (targetPage, viewportWidth) => {
    const key = cacheKey(targetPage, viewportWidth);
    const cached = cacheRef.current.get(key);
    if (cached) {
      cacheRef.current.delete(key);
      cacheRef.current.set(key, cached);
      console.log(`RTL_READER_CACHE_HIT page=${targetPage + 1}`);
      return cached;
    }

    const rendered = await PdfRendererModule.renderPage(
      documentContext.filePath,
      targetPage,
      viewportWidth,
    );
    if (!rendered?.base64) {
      throw new Error('Native PDF renderer returned no image data.');
    }

    const result = {
      imageUri: `data:image/png;base64,${rendered.base64}`,
      width: rendered.width,
      height: rendered.height,
      pageCount: rendered.pageCount,
    };
    putCache(key, result);
    return result;
  };

  const prefetchPage = async (targetPage, viewportWidth, pageCount) => {
    const normalized = normalizePage(targetPage, pageCount);
    if (normalized === null) return;

    const key = cacheKey(normalized, viewportWidth);
    if (cacheRef.current.has(key) || prefetchingRef.current.has(key)) return;

    prefetchingRef.current.add(key);
    try {
      const rendered = await PdfRendererModule.renderPage(
        documentContext.filePath,
        normalized,
        viewportWidth,
      );
      if (rendered?.base64 && mountedRef.current) {
        putCache(key, {
          imageUri: `data:image/png;base64,${rendered.base64}`,
          width: rendered.width,
          height: rendered.height,
          pageCount: rendered.pageCount,
        });
        console.log(`RTL_READER_PREFETCHED page=${normalized + 1}`);
      }
    } catch (error) {
      console.warn(`RTL_READER_PREFETCH_FAILED page=${normalized + 1}`, error);
    } finally {
      prefetchingRef.current.delete(key);
    }
  };

  const prefetchAround = async (
    currentPage,
    viewportWidth,
    mode,
    coverIsSeparate,
    knownPageCount,
  ) => {
    const pageCount = Number.isInteger(knownPageCount)
      ? knownPageCount
      : totalPagesRef.current;

    if (mode === 'single') {
      await prefetchPage(currentPage + 1, viewportWidth, pageCount);
      await prefetchPage(currentPage - 1, viewportWidth, pageCount);
      return;
    }

    const nextPair = getSpreadPair(currentPage + 2, coverIsSeparate, pageCount);
    const previousPair = getSpreadPair(currentPage - 2, coverIsSeparate, pageCount);
    const candidates = [
      nextPair.earlier,
      nextPair.later,
      previousPair.earlier,
      previousPair.later,
    ];

    for (const candidate of candidates) {
      if (candidate !== null) {
        await prefetchPage(candidate, viewportWidth, pageCount);
      }
    }
  };

  useEffect(() => {
    mountedRef.current = true;

    async function initialize() {
      try {
        if (!PdfRendererModule?.renderPage) {
          throw new Error('Native PDF renderer is not registered.');
        }

        const context = await getDocumentContext();
        if (!context.filePath?.toLowerCase().endsWith('.pdf')) {
          throw new Error('RTL Reader v0.0.5 currently supports PDF documents only.');
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
      cacheRef.current.clear();
      prefetchingRef.current.clear();
    };
  }, []);

  useEffect(() => {
    if (!documentContext || !Number.isInteger(pageIndex)) return;

    const token = ++renderTokenRef.current;

    async function renderCurrentView() {
      const pageCount = totalPagesRef.current;

      try {
        if (effectiveMode === 'single') {
          const viewportWidth = Math.max(600, Math.round(window.width));
          const key = cacheKey(pageIndex, viewportWidth);
          const hadCachedPage = cacheRef.current.has(key);
          setRendering(!hadCachedPage);

          const rendered = await renderPdfPage(pageIndex, viewportWidth);
          if (!mountedRef.current || token !== renderTokenRef.current) return;

          setDisplay({
            kind: 'single',
            single: rendered.imageUri,
            singlePageIndex: pageIndex,
          });
          if (Number.isInteger(rendered.pageCount)) {
            setTotalPages(rendered.pageCount);
          }
          setFatalError(null);
          setRendering(false);

          console.log(
            `RTL_READER_RENDERED mode=single page=${pageIndex + 1} cached=${hadCachedPage}`,
          );

          void prefetchAround(
            pageIndex,
            viewportWidth,
            'single',
            coverSeparate,
            rendered.pageCount,
          );
          return;
        }

        const viewportWidth = Math.max(360, Math.floor(window.width / 2));
        const visual = getVisualSpread(
          pageIndex,
          coverSeparate,
          pageCount,
          direction,
        );
        const visibleIndexes = [visual.left, visual.right].filter(
          candidate => candidate !== null,
        );
        const allCached = visibleIndexes.every(candidate =>
          cacheRef.current.has(cacheKey(candidate, viewportWidth)),
        );
        setRendering(!allCached);

        const leftRendered =
          visual.left === null
            ? null
            : await renderPdfPage(visual.left, viewportWidth);
        const rightRendered =
          visual.right === null
            ? null
            : await renderPdfPage(visual.right, viewportWidth);

        if (!mountedRef.current || token !== renderTokenRef.current) return;

        const renderedPageCount =
          leftRendered?.pageCount ?? rightRendered?.pageCount ?? pageCount;
        setDisplay({
          kind: 'spread',
          left: leftRendered?.imageUri ?? null,
          right: rightRendered?.imageUri ?? null,
          leftPageIndex: visual.left,
          rightPageIndex: visual.right,
        });
        if (Number.isInteger(renderedPageCount)) {
          setTotalPages(renderedPageCount);
        }
        setFatalError(null);
        setRendering(false);

        console.log(
          `RTL_READER_RENDERED mode=spread left=${
            visual.left === null ? 'blank' : visual.left + 1
          } right=${visual.right === null ? 'blank' : visual.right + 1} cached=${allCached}`,
        );

        void prefetchAround(
          pageIndex,
          viewportWidth,
          'spread',
          coverSeparate,
          renderedPageCount,
        );
      } catch (error) {
        console.error('RTL_READER_RENDER_FAILED', error);
        if (mountedRef.current && token === renderTokenRef.current) {
          setFatalError(error?.message ?? String(error));
          setRendering(false);
        }
      }
    }

    renderCurrentView();
  }, [
    documentContext,
    pageIndex,
    effectiveMode,
    direction,
    coverSeparate,
    window.width,
  ]);

  const close = () => {
    PluginManager.closePluginView().catch(error =>
      console.error('RTL_READER_CLOSE_FAILED', error),
    );
  };

  const goBy = delta => {
    setPageIndex(current => {
      if (!Number.isInteger(current)) return current;
      const next = clampPage(current + delta, totalPagesRef.current);
      if (next !== current) {
        console.log(
          `RTL_READER_NAV from=${current + 1} to=${next + 1} direction=${directionRef.current} mode=${effectiveModeRef.current}`,
        );
      }
      return next;
    });
  };

  const pageStep = () => (effectiveModeRef.current === 'spread' ? 2 : 1);
  const nextLogicalPage = () => goBy(pageStep());
  const previousLogicalPage = () => goBy(-pageStep());

  const handlePhysicalSwipe = dx => {
    if (dx > SWIPE_THRESHOLD) {
      if (directionRef.current === 'rtl') nextLogicalPage();
      else previousLogicalPage();
      return true;
    }
    if (dx < -SWIPE_THRESHOLD) {
      if (directionRef.current === 'rtl') previousLogicalPage();
      else nextLogicalPage();
      return true;
    }
    return false;
  };

  const handlePhysicalTap = absoluteX => {
    const width = Math.max(1, pageAreaWidthRef.current);
    const rawFraction = (absoluteX - pageAreaLeftRef.current) / width;

    // PluginHost reports horizontal tap coordinates mirrored on the test Nomad.
    // Convert that coordinate back into physical left-to-right screen space.
    const fraction = 1 - rawFraction;

    if (fraction <= EDGE_ZONE) {
      if (directionRef.current === 'rtl') previousLogicalPage();
      else nextLogicalPage();
      return;
    }

    if (fraction >= 1 - EDGE_ZONE) {
      if (directionRef.current === 'rtl') nextLogicalPage();
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
        const {dx, dy, x0} = gestureState;
        if (handlePhysicalSwipe(dx)) return;
        if (Math.abs(dx) <= TAP_SLOP && Math.abs(dy) <= TAP_SLOP) {
          const absoluteX = Number.isFinite(event.nativeEvent.pageX)
            ? event.nativeEvent.pageX
            : x0;
          handlePhysicalTap(absoluteX);
        }
      },
      onPanResponderTerminate: () => {},
    });
  }

  const toggleDirection = () => {
    setDirection(current => {
      const next = current === 'rtl' ? 'ltr' : 'rtl';
      directionRef.current = next;
      console.log(`RTL_READER_DIRECTION ${next}`);
      return next;
    });
  };

  const toggleViewMode = () => {
    setViewMode(current => {
      const next = cycleViewMode(current);
      console.log(`RTL_READER_VIEW_MODE ${next}`);
      return next;
    });
  };

  const toggleCoverSeparate = () => {
    setCoverSeparate(current => {
      const next = !current;
      coverSeparateRef.current = next;
      console.log(`RTL_READER_COVER_SEPARATE ${next}`);
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
    const target = clampPage(requested - 1, totalPagesRef.current);
    console.log(`RTL_READER_JUMP requested=${requested} target=${target + 1}`);
    setPageIndex(target);
    Keyboard.dismiss();
    setJumpOpen(false);
  };

  const footerLabel = (() => {
    if (display.kind !== 'spread') {
      return `Page ${Number.isInteger(pageIndex) ? pageIndex + 1 : '—'}${
        Number.isInteger(totalPages) ? ` / ${totalPages}` : ''
      }`;
    }

    const left =
      display.leftPageIndex === null || display.leftPageIndex === undefined
        ? 'Blank'
        : String(display.leftPageIndex + 1);
    const right =
      display.rightPageIndex === null || display.rightPageIndex === undefined
        ? 'Blank'
        : String(display.rightPageIndex + 1);
    return `${left} | ${right}${
      Number.isInteger(totalPages) ? ` / ${totalPages}` : ''
    }`;
  })();

  return (
    <SafeAreaView style={styles.root}>
      <StatusBar hidden />

      <View
        style={styles.pageArea}
        onLayout={event => {
          pageAreaWidthRef.current = Math.max(1, event.nativeEvent.layout.width);
          pageAreaLeftRef.current = event.nativeEvent.layout.x ?? 0;
        }}
        {...panResponderRef.current.panHandlers}>
        {display.kind === 'spread' ? (
          <View style={styles.spread}>
            <View style={styles.spreadPage}>
              {display.left ? (
                <Image
                  source={{uri: display.left}}
                  resizeMode="contain"
                  style={styles.pageImage}
                />
              ) : (
                <View style={styles.blankPage} />
              )}
            </View>
            <View style={styles.spreadDivider} />
            <View style={styles.spreadPage}>
              {display.right ? (
                <Image
                  source={{uri: display.right}}
                  resizeMode="contain"
                  style={styles.pageImage}
                />
              ) : (
                <View style={styles.blankPage} />
              )}
            </View>
          </View>
        ) : display.single ? (
          <Image
            source={{uri: display.single}}
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
            <Pressable onPress={toggleViewMode} style={styles.compactButton}>
              <Text style={styles.compactButtonText}>{viewModeLabel(viewMode)}</Text>
            </Pressable>
            <Pressable onPress={toggleCoverSeparate} style={styles.compactButton}>
              <Text style={styles.compactButtonText}>
                {coverSeparate ? 'Cover: On' : 'Cover: Off'}
              </Text>
            </Pressable>
            <Pressable onPress={close} style={styles.compactButton}>
              <Text style={styles.compactButtonText}>Close</Text>
            </Pressable>
          </View>

          <View style={styles.footer}>
            <Pressable onPress={previousLogicalPage} style={styles.navButton}>
              <Text style={styles.navButtonText}>−</Text>
            </Pressable>
            <Pressable onPress={openJump} style={styles.pageButton}>
              <Text style={styles.pageLabel}>{footerLabel}</Text>
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
              {Number.isInteger(totalPages)
                ? `1–${totalPages}`
                : 'Enter a page number'}
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
    height: '100%',
    backgroundColor: '#ffffff',
  },
  spread: {
    flex: 1,
    flexDirection: 'row',
    backgroundColor: '#ffffff',
  },
  spreadPage: {
    flex: 1,
    backgroundColor: '#ffffff',
  },
  blankPage: {
    flex: 1,
    backgroundColor: '#ffffff',
  },
  spreadDivider: {
    width: 1,
    backgroundColor: '#999999',
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
    paddingHorizontal: 8,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    backgroundColor: '#ffffff',
    borderBottomWidth: 1,
    borderBottomColor: '#777777',
  },
  compactButton: {
    minWidth: 72,
    paddingHorizontal: 10,
    paddingVertical: 8,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#000000',
    borderRadius: 3,
    backgroundColor: '#ffffff',
  },
  compactButtonText: {
    fontSize: 15,
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
    minWidth: 210,
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