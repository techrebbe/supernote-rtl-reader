import React, {useEffect, useRef, useState} from 'react';
import {
  ActivityIndicator,
  BackHandler,
  Image,
  Keyboard,
  NativeModules,
  PanResponder,
  Pressable,
  SafeAreaView,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  TextInput,
  View,
  useWindowDimensions,
} from 'react-native';
import {PluginCommAPI, PluginDocAPI, PluginManager} from 'sn-plugin-lib';

const {PdfRendererModule, ReaderPreferencesModule} = NativeModules;
const SWIPE_THRESHOLD = 56;
const TAP_SLOP = 18;
const EDGE_ZONE = 0.28;
const CACHE_LIMIT = 8;
const PREFERENCES_SAVE_DELAY_MS = 350;

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

function viewModeLabel(mode) {
  if (mode === 'single') return 'Single';
  if (mode === 'spread') return 'Spread';
  return 'Auto';
}

function decodePreferences(raw, context) {
  let saved = null;
  if (typeof raw === 'string' && raw.length > 0) {
    try {
      saved = JSON.parse(raw);
    } catch (error) {
      console.warn('RTL_READER_PREFS_PARSE_FAILED', error);
    }
  }

  const direction = saved?.direction === 'ltr' ? 'ltr' : 'rtl';
  const viewMode = ['auto', 'single', 'spread'].includes(saved?.viewMode)
    ? saved.viewMode
    : 'auto';
  const coverSeparate = saved?.coverSeparate === true;

  const hasSavedPage = Number.isInteger(saved?.lastPageIndex);
  const hasPriorNativeAnchor = Number.isInteger(saved?.nativePageIndexAtOpen);
  const nativePositionChanged =
    hasPriorNativeAnchor && saved.nativePageIndexAtOpen !== context.pageIndex;

  const useSavedPage = hasSavedPage && !nativePositionChanged;
  const pageIndex = useSavedPage
    ? clampPage(saved.lastPageIndex, context.totalPages)
    : clampPage(context.pageIndex, context.totalPages);

  return {
    direction,
    viewMode,
    coverSeparate,
    pageIndex,
    source: useSavedPage ? 'saved' : nativePositionChanged ? 'native-changed' : 'native',
  };
}

function SegmentedButton({active, disabled = false, label, onPress, style}) {
  return (
    <Pressable
      disabled={disabled}
      onPress={onPress}
      style={[
        styles.segmentButton,
        active && styles.segmentButtonActive,
        disabled && styles.segmentButtonDisabled,
        style,
      ]}>
      <Text style={[styles.segmentButtonText, active && styles.segmentButtonTextActive]}>
        {label}
      </Text>
    </Pressable>
  );
}

export default function App() {
  const window = useWindowDimensions();
  const isLandscape = window.width > window.height;

  const [documentContext, setDocumentContext] = useState(null);
  const [preferencesReady, setPreferencesReady] = useState(false);
  const [pageIndex, setPageIndex] = useState(null);
  const [totalPages, setTotalPages] = useState(null);
  const [display, setDisplay] = useState({kind: 'single', single: null});
  const [rendering, setRendering] = useState(true);
  const [fatalError, setFatalError] = useState(null);
  const [direction, setDirection] = useState('rtl');
  const [viewMode, setViewMode] = useState('auto');
  const [coverSeparate, setCoverSeparate] = useState(false);
  const [chromeVisible, setChromeVisible] = useState(true);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [jumpOpen, setJumpOpen] = useState(false);
  const [jumpText, setJumpText] = useState('');

  const effectiveMode =
    viewMode === 'auto' ? (isLandscape ? 'spread' : 'single') : viewMode;

  const [nativeSpreadEnabled, setNativeSpreadEnabled] = useState(false);
  const [nativeSpreadEditable, setNativeSpreadEditable] = useState(false);
  const [nativeSpreadConfigured, setNativeSpreadConfigured] = useState(false);
  const [nativeSpreadConfiguredEditable, setNativeSpreadConfiguredEditable] =
    useState(false);
  const [nativeSpreadCompatible, setNativeSpreadCompatible] = useState(false);
  const [nativeSpreadBusy, setNativeSpreadBusy] = useState(false);
  const [nativeSpreadError, setNativeSpreadError] = useState(null);
  const [nativeBackupAvailable, setNativeBackupAvailable] = useState(false);
  const [nativeBackupOriginalMarkPresent, setNativeBackupOriginalMarkPresent] =
    useState(false);
  const [nativeBackupStatus, setNativeBackupStatus] = useState('missing');
  const [nativeEditableConfirmOpen, setNativeEditableConfirmOpen] =
    useState(false);

  const mountedRef = useRef(true);
  const nativeSpreadBusyRef = useRef(false);
  const renderTokenRef = useRef(0);
  const pageAreaWidthRef = useRef(Math.max(1, window.width));
  const pageAreaLeftRef = useRef(0);
  const directionRef = useRef(direction);
  const viewModeRef = useRef(viewMode);
  const pageIndexRef = useRef(pageIndex);
  const totalPagesRef = useRef(totalPages);
  const effectiveModeRef = useRef(effectiveMode);
  const coverSeparateRef = useRef(coverSeparate);
  const filePathRef = useRef(null);
  const nativePageIndexAtOpenRef = useRef(null);
  const latestPreferencesRef = useRef(null);
  const preferencesSaveTimerRef = useRef(null);
  const cacheRef = useRef(new Map());
  const prefetchingRef = useRef(new Set());

  directionRef.current = direction;
  viewModeRef.current = viewMode;
  pageIndexRef.current = pageIndex;
  totalPagesRef.current = totalPages;
  effectiveModeRef.current = effectiveMode;
  coverSeparateRef.current = coverSeparate;
  pageAreaWidthRef.current = Math.max(1, window.width);

  useEffect(() => {
    const subscription = BackHandler.addEventListener(
      'hardwareBackPress',
      () => {
        if (!nativeSpreadBusyRef.current) return false;
        setNativeSpreadError(
          'Wait for the native reader change to finish before closing.',
        );
        return true;
      },
    );
    return () => subscription.remove();
  }, []);

  if (preferencesReady && documentContext && Number.isInteger(pageIndex)) {
    latestPreferencesRef.current = {
      version: 1,
      direction,
      viewMode,
      coverSeparate,
      lastPageIndex: pageIndex,
      nativePageIndexAtOpen: nativePageIndexAtOpenRef.current,
      updatedAt: Date.now(),
    };
  }

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

  const savePreferences = async (reason, payload = latestPreferencesRef.current) => {
    const filePath = filePathRef.current;
    if (!filePath || !payload || !ReaderPreferencesModule?.save) return;

    await ReaderPreferencesModule.save(filePath, JSON.stringify(payload));
    console.log(
      `RTL_READER_PREFS_SAVED reason=${reason} page=${payload.lastPageIndex + 1} direction=${payload.direction} view=${payload.viewMode} cover=${payload.coverSeparate}`,
    );
  };

  useEffect(() => {
    mountedRef.current = true;

    async function initialize() {
      try {
        if (!PdfRendererModule?.renderPage) {
          throw new Error('Native PDF renderer is not registered.');
        }
        if (!ReaderPreferencesModule?.load || !ReaderPreferencesModule?.save) {
          throw new Error('Native reader preferences storage is not registered.');
        }

        const context = await getDocumentContext();
        if (!context.filePath?.toLowerCase().endsWith('.pdf')) {
          throw new Error('RTL Reader v0.1.0 currently supports PDF documents only.');
        }

        const rawPreferences = await ReaderPreferencesModule.load(context.filePath);
        const restored = decodePreferences(rawPreferences, context);
        let nativeSpread = null;
        if (ReaderPreferencesModule?.loadNativeSpreadMode) {
          try {
            nativeSpread = await ReaderPreferencesModule.loadNativeSpreadMode(
              context.filePath,
            );
          } catch (error) {
            console.warn('RTL_READER_NATIVE_SPREAD_LOAD_FAILED', error);
          }
        }

        if (!mountedRef.current) return;

        filePathRef.current = context.filePath;
        nativePageIndexAtOpenRef.current = context.pageIndex;
        directionRef.current = restored.direction;
        viewModeRef.current = restored.viewMode;
        coverSeparateRef.current = restored.coverSeparate;
        pageIndexRef.current = restored.pageIndex;

        setDocumentContext(context);
        setDirection(restored.direction);
        setViewMode(restored.viewMode);
        setCoverSeparate(restored.coverSeparate);
        setPageIndex(restored.pageIndex);
        setTotalPages(context.totalPages);
        setPreferencesReady(true);
        setNativeSpreadConfigured(nativeSpread?.configured === true);
        setNativeSpreadConfiguredEditable(
          nativeSpread?.configuredEditable === true,
        );
        setNativeSpreadEnabled(nativeSpread?.enabled === true);
        setNativeSpreadEditable(nativeSpread?.editable === true);
        setNativeSpreadCompatible(nativeSpread?.compatible === true);
        setNativeBackupAvailable(nativeSpread?.backupAvailable === true);
        setNativeBackupOriginalMarkPresent(
          nativeSpread?.backupOriginalMarkPresent === true,
        );
        setNativeBackupStatus(nativeSpread?.backupStatus ?? 'missing');

        console.log(
          `RTL_READER_PREFS_LOADED source=${restored.source} page=${restored.pageIndex + 1} direction=${restored.direction} view=${restored.viewMode} cover=${restored.coverSeparate}`,
        );
        console.log(
          `RTL_READER_OPENED file=${context.filePath} nativePage=${context.pageIndex + 1} readerPage=${restored.pageIndex + 1}`,
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
      if (preferencesSaveTimerRef.current) {
        clearTimeout(preferencesSaveTimerRef.current);
      }
      const payload = latestPreferencesRef.current;
      if (filePathRef.current && payload && ReaderPreferencesModule?.save) {
        ReaderPreferencesModule.save(
          filePathRef.current,
          JSON.stringify(payload),
        ).catch(error => console.warn('RTL_READER_PREFS_UNMOUNT_SAVE_FAILED', error));
      }
    };
  }, []);

  useEffect(() => {
    if (
      !preferencesReady ||
      !documentContext ||
      !Number.isInteger(pageIndex) ||
      !latestPreferencesRef.current
    ) {
      return undefined;
    }

    if (preferencesSaveTimerRef.current) {
      clearTimeout(preferencesSaveTimerRef.current);
    }
    preferencesSaveTimerRef.current = setTimeout(() => {
      savePreferences('debounced').catch(error =>
        console.warn('RTL_READER_PREFS_SAVE_FAILED', error),
      );
    }, PREFERENCES_SAVE_DELAY_MS);

    return () => {
      if (preferencesSaveTimerRef.current) {
        clearTimeout(preferencesSaveTimerRef.current);
        preferencesSaveTimerRef.current = null;
      }
    };
  }, [
    preferencesReady,
    documentContext,
    pageIndex,
    direction,
    viewMode,
    coverSeparate,
  ]);

  useEffect(() => {
    if (!preferencesReady || !documentContext || !Number.isInteger(pageIndex)) return;

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
          } right=${
            visual.right === null ? 'blank' : visual.right + 1
          } cached=${allCached}`,
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
    preferencesReady,
    documentContext,
    pageIndex,
    effectiveMode,
    direction,
    coverSeparate,
    window.width,
  ]);

  const close = async () => {
    if (nativeSpreadBusyRef.current) {
      setNativeSpreadError(
        'Wait for the native reader change to finish before closing.',
      );
      return;
    }
    if (preferencesSaveTimerRef.current) {
      clearTimeout(preferencesSaveTimerRef.current);
      preferencesSaveTimerRef.current = null;
    }

    try {
      await savePreferences('close');
    } catch (error) {
      console.warn('RTL_READER_PREFS_CLOSE_SAVE_FAILED', error);
    }

    PluginManager.closePluginView().catch(error =>
      console.error('RTL_READER_CLOSE_FAILED', error),
    );
  };

  const closeSettings = () => {
    if (nativeSpreadBusyRef.current) {
      setNativeSpreadError(
        'Wait for the native reader change to finish before closing.',
      );
      return;
    }
    setSettingsOpen(false);
  };

  const goBy = delta => {
    setPageIndex(current => {
      if (!Number.isInteger(current)) return current;
      const next = clampPage(current + delta, totalPagesRef.current);
      if (next !== current) {
        pageIndexRef.current = next;
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

  const setDirectionValue = async next => {
    if (
      (next !== 'rtl' && next !== 'ltr') ||
      nativeSpreadBusyRef.current
    ) {
      return;
    }
    if (
      next === 'ltr' && nativeSpreadConfigured
    ) {
      const disabled = await setNativeSpreadReadOnly(false);
      if (!disabled) {
        return;
      }
    }
    directionRef.current = next;
    setDirection(next);
    console.log(`RTL_READER_DIRECTION ${next}`);
  };

  const setViewModeValue = next => {
    if (!['auto', 'single', 'spread'].includes(next)) return;
    viewModeRef.current = next;
    setViewMode(next);
    console.log(`RTL_READER_VIEW_MODE ${next}`);
  };

  const setCoverSeparateValue = async next => {
    if (nativeSpreadBusyRef.current) return;
    const normalized = next === true;
    if (nativeSpreadConfigured && !nativeSpreadCompatible) {
      setNativeSpreadError(
        'Native Spread is configured but unavailable. Cover can be changed after the native hooks reconnect.',
      );
      return;
    }
    if (!nativeSpreadConfigured) {
      coverSeparateRef.current = normalized;
      setCoverSeparate(normalized);
      console.log(`RTL_READER_COVER_SEPARATE ${normalized}`);
      return;
    }

    nativeSpreadBusyRef.current = true;
    setNativeSpreadBusy(true);
    setNativeSpreadError(null);
    try {
      const result = nativeSpreadConfiguredEditable
        ? await ReaderPreferencesModule.configureNativeSpreadEditable(
            filePathRef.current,
            normalized,
          )
        : await ReaderPreferencesModule.configureNativeSpreadReadOnly(
            filePathRef.current,
            true,
            normalized,
          );
      coverSeparateRef.current = normalized;
      setCoverSeparate(normalized);
      if (nativeSpreadConfiguredEditable) {
        setNativeBackupAvailable(result?.backupAvailable === true);
        setNativeBackupOriginalMarkPresent(
          result?.backupOriginalMarkPresent === true,
        );
        setNativeBackupStatus(result?.backupStatus ?? 'verified');
      }
      console.log(`RTL_READER_COVER_SEPARATE ${normalized}`);
    } catch (error) {
      console.warn('RTL_READER_NATIVE_SPREAD_COVER_SYNC_FAILED', error);
      setNativeSpreadError(error?.message ?? String(error));
    } finally {
      nativeSpreadBusyRef.current = false;
      setNativeSpreadBusy(false);
    }
  };

  const setNativeSpreadReadOnly = async enabled => {
    const filePath = filePathRef.current;
    if (
      !filePath ||
      nativeSpreadBusyRef.current ||
      !ReaderPreferencesModule?.configureNativeSpreadReadOnly
    ) {
      return false;
    }
    if (enabled && (directionRef.current !== 'rtl' || !nativeSpreadCompatible)) {
      return false;
    }

    nativeSpreadBusyRef.current = true;
    setNativeSpreadBusy(true);
    setNativeSpreadError(null);
    try {
      await ReaderPreferencesModule.configureNativeSpreadReadOnly(
        filePath,
        enabled,
        coverSeparateRef.current,
      );
      setNativeSpreadConfigured(enabled);
      setNativeSpreadConfiguredEditable(false);
      setNativeSpreadEnabled(enabled);
      setNativeSpreadEditable(false);
      setNativeBackupAvailable(false);
      setNativeBackupOriginalMarkPresent(false);
      setNativeBackupStatus('missing');
      setNativeEditableConfirmOpen(false);
      console.log(
        `RTL_READER_NATIVE_SPREAD enabled=${enabled} editable=false cover=${coverSeparateRef.current}`,
      );
      return true;
    } catch (error) {
      console.error('RTL_READER_NATIVE_SPREAD_CONFIG_FAILED', error);
      setNativeSpreadError(error?.message ?? String(error));
      return false;
    } finally {
      nativeSpreadBusyRef.current = false;
      setNativeSpreadBusy(false);
    }
  };

  const setNativeSpreadEditableMode = async () => {
    const filePath = filePathRef.current;
    if (
      !filePath ||
      nativeSpreadBusyRef.current ||
      directionRef.current !== 'rtl' ||
      !nativeSpreadCompatible ||
      !ReaderPreferencesModule?.configureNativeSpreadEditable
    ) {
      return;
    }

    nativeSpreadBusyRef.current = true;
    setNativeSpreadBusy(true);
    setNativeSpreadError(null);
    try {
      const backup = await ReaderPreferencesModule.configureNativeSpreadEditable(
        filePath,
        coverSeparateRef.current,
      );
      setNativeSpreadConfigured(true);
      setNativeSpreadConfiguredEditable(true);
      setNativeSpreadEnabled(true);
      setNativeSpreadEditable(true);
      setNativeBackupAvailable(backup?.backupAvailable === true);
      setNativeBackupOriginalMarkPresent(
        backup?.backupOriginalMarkPresent === true,
      );
      setNativeBackupStatus(backup?.backupStatus ?? 'verified');
      setNativeEditableConfirmOpen(false);
      console.log(
        `RTL_READER_NATIVE_SPREAD enabled=true editable=true cover=${coverSeparateRef.current} backup=verified`,
      );
    } catch (error) {
      console.error('RTL_READER_NATIVE_EDITABLE_CONFIG_FAILED', error);
      setNativeSpreadError(error?.message ?? String(error));
    } finally {
      nativeSpreadBusyRef.current = false;
      setNativeSpreadBusy(false);
    }
  };

  const restoreNativeBackup = async () => {
    const filePath = filePathRef.current;
    if (
      !filePath ||
      nativeSpreadBusyRef.current ||
      !nativeBackupAvailable ||
      !ReaderPreferencesModule?.restoreNativeAnnotationBackup
    ) {
      return;
    }
    nativeSpreadBusyRef.current = true;
    setNativeSpreadBusy(true);
    setNativeSpreadError(null);
    try {
      await ReaderPreferencesModule.restoreNativeAnnotationBackup(filePath);
      setNativeSpreadConfigured(false);
      setNativeSpreadConfiguredEditable(false);
      setNativeSpreadEnabled(false);
      setNativeSpreadEditable(false);
      setNativeEditableConfirmOpen(false);
      nativeSpreadBusyRef.current = false;
      setNativeSpreadBusy(false);
      await close();
    } catch (error) {
      console.error('RTL_READER_NATIVE_BACKUP_RESTORE_FAILED', error);
      setNativeSpreadError(error?.message ?? String(error));
      nativeSpreadBusyRef.current = false;
      setNativeSpreadBusy(false);
    }
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
    pageIndexRef.current = target;
    console.log(`RTL_READER_JUMP requested=${requested} target=${target + 1}`);
    setPageIndex(target);
    Keyboard.dismiss();
    setJumpOpen(false);
  };

  const footerLabel = (() => {
    if (display.kind !== 'spread') {
      return `${Number.isInteger(pageIndex) ? pageIndex + 1 : '—'}${
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

  const statusLayout =
    viewMode === 'auto'
      ? `Auto → ${viewModeLabel(effectiveMode)}`
      : viewModeLabel(viewMode);
  const statusCover = coverSeparate ? 'Cover separate' : 'Cover paired';

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
          <Pressable
            disabled={nativeSpreadBusy}
            onPress={close}
            style={[
              styles.panelButton,
              nativeSpreadBusy && styles.segmentButtonDisabled,
            ]}>
            <Text style={styles.panelButtonText}>Close</Text>
          </Pressable>
        </View>
      )}

      {chromeVisible && !fatalError && (
        <>
          <View style={styles.header}>
            <View style={styles.statusBlock}>
              <Text style={styles.statusPrimary}>
                {direction.toUpperCase()} · {statusLayout}
              </Text>
              <Text style={styles.statusSecondary}>{statusCover}</Text>
            </View>
            <View style={styles.headerActions}>
              <Pressable
                onPress={() => setSettingsOpen(true)}
                style={styles.headerButton}>
                <Text style={styles.headerButtonText}>Settings</Text>
              </Pressable>
              <Pressable
                disabled={nativeSpreadBusy}
                onPress={close}
                style={[
                  styles.headerButton,
                  nativeSpreadBusy && styles.segmentButtonDisabled,
                ]}>
                <Text style={styles.headerButtonText}>Close</Text>
              </Pressable>
            </View>
          </View>

          <View style={styles.footer}>
            <Pressable
              onPress={direction === 'rtl' ? nextLogicalPage : previousLogicalPage}
              style={styles.navButton}>
              <Text style={styles.navButtonText}>
                {direction === 'rtl' ? 'Next' : 'Prev'}
              </Text>
            </Pressable>
            <Pressable onPress={openJump} style={styles.pageButton}>
              <Text style={styles.pageLabel}>{footerLabel}</Text>
              <Text style={styles.pageHint}>Tap to jump</Text>
            </Pressable>
            <Pressable
              onPress={direction === 'rtl' ? previousLogicalPage : nextLogicalPage}
              style={styles.navButton}>
              <Text style={styles.navButtonText}>
                {direction === 'rtl' ? 'Prev' : 'Next'}
              </Text>
            </Pressable>
          </View>
        </>
      )}

      {settingsOpen && !fatalError && (
        <View style={styles.modalBackdrop}>
          <View style={styles.settingsPanel}>
            <View style={styles.settingsHeader}>
              <View>
                <Text style={styles.settingsTitle}>Reading settings</Text>
                <Text style={styles.settingsSummary}>
                  {direction.toUpperCase()} · {statusLayout}
                </Text>
              </View>
              <Pressable
                disabled={nativeSpreadBusy}
                onPress={closeSettings}
                style={[
                  styles.doneButton,
                  nativeSpreadBusy && styles.segmentButtonDisabled,
                ]}>
                <Text style={styles.doneButtonText}>
                  {nativeSpreadBusy ? 'Applying...' : 'Done'}
                </Text>
              </Pressable>
            </View>

            <ScrollView
              contentContainerStyle={styles.settingsScrollContent}
              keyboardShouldPersistTaps="handled"
              style={styles.settingsScroll}>
            <Text style={styles.settingLabel}>Reading direction</Text>
            <View style={styles.segmentRow}>
              <SegmentedButton
                active={direction === 'rtl'}
                label="RTL"
                onPress={() => setDirectionValue('rtl')}
                style={styles.segmentHalf}
              />
              <SegmentedButton
                active={direction === 'ltr'}
                label="LTR"
                onPress={() => setDirectionValue('ltr')}
                style={styles.segmentHalfLast}
              />
            </View>

            <Text style={styles.settingLabel}>Page layout</Text>
            <View style={styles.segmentRow}>
              <SegmentedButton
                active={viewMode === 'auto'}
                label="Auto"
                onPress={() => setViewModeValue('auto')}
                style={styles.segmentThird}
              />
              <SegmentedButton
                active={viewMode === 'single'}
                label="Single"
                onPress={() => setViewModeValue('single')}
                style={styles.segmentThird}
              />
              <SegmentedButton
                active={viewMode === 'spread'}
                label="Spread"
                onPress={() => setViewModeValue('spread')}
                style={styles.segmentThirdLast}
              />
            </View>
            <Text style={styles.settingHint}>
              Auto uses Single in portrait and Spread in landscape.
            </Text>

            <Text style={styles.settingLabel}>Treat Cover Page Separately</Text>
            <View style={styles.segmentRow}>
              <SegmentedButton
                active={!coverSeparate}
                disabled={
                  nativeSpreadBusy ||
                  (nativeSpreadConfigured && !nativeSpreadCompatible)
                }
                label="Off"
                onPress={() => setCoverSeparateValue(false)}
                style={styles.segmentHalf}
              />
              <SegmentedButton
                active={coverSeparate}
                disabled={
                  nativeSpreadBusy ||
                  (nativeSpreadConfigured && !nativeSpreadCompatible)
                }
                label="On"
                onPress={() => setCoverSeparateValue(true)}
                style={styles.segmentHalfLast}
              />
            </View>
            <Text style={styles.settingHint}>
              On inserts a virtual blank beside the cover; the PDF is not changed.
            </Text>

            <Text style={styles.settingLabel}>Supernote native reader</Text>
            <View style={styles.segmentRow}>
              <SegmentedButton
                active={!nativeSpreadConfigured}
                disabled={nativeSpreadBusy}
                label="Off"
                onPress={() => setNativeSpreadReadOnly(false)}
                style={styles.segmentThird}
              />
              <SegmentedButton
                active={
                  nativeSpreadConfigured && !nativeSpreadConfiguredEditable
                }
                disabled={
                  nativeSpreadBusy ||
                  direction !== 'rtl' ||
                  !nativeSpreadCompatible
                }
                label={nativeSpreadBusy ? 'Applying...' : 'RTL read-only'}
                onPress={() => setNativeSpreadReadOnly(true)}
                style={styles.segmentThird}
              />
              <SegmentedButton
                active={
                  nativeSpreadConfigured && nativeSpreadConfiguredEditable
                }
                disabled={
                  nativeSpreadBusy ||
                  direction !== 'rtl' ||
                  !nativeSpreadCompatible
                }
                label="RTL editable"
                onPress={() => setNativeEditableConfirmOpen(true)}
                style={styles.segmentThirdLast}
              />
            </View>
            <Text style={styles.settingHint}>
              {nativeSpreadConfiguredEditable && nativeSpreadEditable
                ? 'Native writing is enabled for this PDF. A verified recovery snapshot protects the annotation state from before editing.'
                : nativeSpreadConfiguredEditable
                  ? 'RTL editable remains configured, but its verified hooks are inactive. Select Off or restore the annotation snapshot.'
                : nativeSpreadConfigured && !nativeSpreadCompatible
                  ? 'RTL read-only remains configured, but the compatible hooks are inactive. Select Off to remove it.'
                  : !nativeSpreadCompatible
                  ? 'Requires the compatible rooted Native Spread module.'
                  : direction !== 'rtl'
                    ? 'Select RTL direction to enable the native-reader pilot.'
                    : nativeSpreadEnabled
                      ? "Close RTL Reader to reopen this PDF in Supernote's native RTL spread mode. Writing remains disabled for this pilot."
                      : "Read-only preserves annotations. Editable creates and verifies a per-document recovery snapshot before native writing is enabled."}
            </Text>
            {nativeEditableConfirmOpen && (
              <View style={styles.nativeWarningPanel}>
                <Text style={styles.nativeWarningTitle}>
                  Enable native editing for this PDF?
                </Text>
                <Text style={styles.settingHint}>
                  RTL Reader will preserve the current Supernote annotation file byte-for-byte before enabling writing, erasing, lasso, highlighting, and links. This remains an experimental rooted-device feature.
                </Text>
                <View style={styles.nativeWarningActions}>
                  <Pressable
                    disabled={nativeSpreadBusy}
                    onPress={() => setNativeEditableConfirmOpen(false)}
                    style={styles.panelButton}>
                    <Text style={styles.panelButtonText}>Cancel</Text>
                  </Pressable>
                  <Pressable
                    disabled={nativeSpreadBusy}
                    onPress={setNativeSpreadEditableMode}
                    style={styles.panelButton}>
                    <Text style={styles.panelButtonText}>
                      {nativeSpreadBusy ? 'Backing up...' : 'Back up & enable'}
                    </Text>
                  </Pressable>
                </View>
              </View>
            )}
            {nativeBackupAvailable && (
              <View style={styles.nativeRecoveryRow}>
                <Text style={styles.settingHint}>
                  Recovery snapshot verified ({nativeBackupOriginalMarkPresent
                    ? 'existing annotations preserved'
                    : 'originally no annotation file'}).
                </Text>
                <Pressable
                  disabled={nativeSpreadBusy}
                  onPress={restoreNativeBackup}
                  style={styles.recoveryButton}>
                  <Text style={styles.panelButtonText}>Restore snapshot</Text>
                </Pressable>
              </View>
            )}
            {!nativeBackupAvailable && nativeBackupStatus.startsWith('invalid:') && (
              <Text style={styles.settingError}>
                Annotation recovery files need attention: {nativeBackupStatus}
              </Text>
            )}
            {nativeSpreadError && (
              <Text style={styles.settingError}>{nativeSpreadError}</Text>
            )}
            </ScrollView>
          </View>
        </View>
      )}

      {jumpOpen && (
        <View style={styles.modalBackdrop}>
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
    minHeight: 54,
    paddingHorizontal: 10,
    paddingVertical: 5,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    backgroundColor: '#ffffff',
    borderBottomWidth: 1,
    borderBottomColor: '#777777',
  },
  statusBlock: {
    flex: 1,
    paddingRight: 10,
  },
  statusPrimary: {
    fontSize: 16,
    fontWeight: '700',
    color: '#000000',
  },
  statusSecondary: {
    marginTop: 2,
    fontSize: 12,
    color: '#333333',
  },
  headerActions: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  headerButton: {
    minWidth: 76,
    marginLeft: 7,
    paddingHorizontal: 10,
    paddingVertical: 8,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#000000',
    borderRadius: 3,
    backgroundColor: '#ffffff',
  },
  headerButtonText: {
    fontSize: 15,
    color: '#000000',
  },
  footer: {
    position: 'absolute',
    left: 0,
    right: 0,
    bottom: 0,
    minHeight: 54,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#ffffff',
    borderTopWidth: 1,
    borderTopColor: '#777777',
  },
  navButton: {
    minWidth: 76,
    height: 52,
    alignItems: 'center',
    justifyContent: 'center',
  },
  navButtonText: {
    fontSize: 16,
    fontWeight: '600',
    color: '#000000',
  },
  pageButton: {
    minWidth: 210,
    paddingHorizontal: 18,
    paddingVertical: 7,
    alignItems: 'center',
  },
  pageLabel: {
    fontSize: 17,
    fontWeight: '600',
    color: '#000000',
  },
  pageHint: {
    marginTop: 1,
    fontSize: 10,
    color: '#555555',
  },
  renderBadge: {
    position: 'absolute',
    top: 64,
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
    minWidth: 94,
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
  modalBackdrop: {
    position: 'absolute',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: 'rgba(255,255,255,0.9)',
  },
  settingsPanel: {
    width: 520,
    maxWidth: '90%',
    maxHeight: '90%',
    padding: 20,
    borderWidth: 2,
    borderColor: '#000000',
    backgroundColor: '#ffffff',
  },
  settingsHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: 20,
  },
  settingsTitle: {
    fontSize: 22,
    fontWeight: '700',
    color: '#000000',
  },
  settingsSummary: {
    marginTop: 2,
    fontSize: 13,
    color: '#444444',
  },
  doneButton: {
    minWidth: 72,
    paddingHorizontal: 14,
    paddingVertical: 8,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#000000',
    borderRadius: 3,
    backgroundColor: '#000000',
  },
  doneButtonText: {
    fontSize: 15,
    fontWeight: '700',
    color: '#ffffff',
  },
  settingLabel: {
    marginTop: 4,
    marginBottom: 7,
    fontSize: 16,
    fontWeight: '700',
    color: '#000000',
  },
  settingHint: {
    marginTop: 6,
    marginBottom: 16,
    fontSize: 12,
    lineHeight: 16,
    color: '#444444',
  },
  segmentRow: {
    flexDirection: 'row',
    width: '100%',
  },
  segmentButtonDisabled: {
    opacity: 0.35,
  },
  settingError: {
    marginTop: -8,
    marginBottom: 12,
    fontSize: 12,
    lineHeight: 16,
    color: '#000000',
  },
  nativeWarningPanel: {
    marginTop: -6,
    marginBottom: 14,
    padding: 12,
    borderWidth: 1,
    borderColor: '#000000',
    backgroundColor: '#ffffff',
  },
  settingsScroll: {
    flexShrink: 1,
  },
  settingsScrollContent: {
    paddingBottom: 4,
  },
  nativeWarningTitle: {
    fontSize: 16,
    fontWeight: '700',
    color: '#000000',
  },
  nativeWarningActions: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  nativeRecoveryRow: {
    marginTop: -8,
    marginBottom: 12,
  },
  recoveryButton: {
    alignSelf: 'flex-start',
    minWidth: 150,
    paddingHorizontal: 14,
    paddingVertical: 8,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: '#000000',
    borderRadius: 3,
    backgroundColor: '#ffffff',
  },
  segmentButton: {
    minHeight: 42,
    alignItems: 'center',
    justifyContent: 'center',
    borderWidth: 1,
    borderColor: '#000000',
    backgroundColor: '#ffffff',
  },
  segmentButtonActive: {
    backgroundColor: '#000000',
  },
  segmentButtonText: {
    fontSize: 15,
    fontWeight: '600',
    color: '#000000',
  },
  segmentButtonTextActive: {
    color: '#ffffff',
  },
  segmentHalf: {
    flex: 1,
    marginRight: 4,
  },
  segmentHalfLast: {
    flex: 1,
    marginLeft: 4,
  },
  segmentThird: {
    flex: 1,
    marginRight: 4,
  },
  segmentThirdLast: {
    flex: 1,
    marginLeft: 4,
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
