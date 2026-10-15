"""Strict final generated-App integration; legacy canonical sources stay intact."""
from pathlib import Path
import sys


def once(text, old, new, label):
    if text.count(old) != 1:
        raise ValueError(f'PDFium integration: expected one {label}')
    return text.replace(old, new, 1)


def patch_app(text):
    text = once(text, "import ReaderKeyView from './ReaderKeyView';",
        "import ReaderKeyView from './ReaderKeyView';\n"
        "import {useInteractivePdf,InteractivePdfPage,InteractivePdfTools,InteractivePdfBookmarks} from './InteractivePdfReader';\n"
        "import {restoreSourcePreferences} from './interactivePdf';", 'imports')
    text = once(text, "  const [pageAreaLayout, setPageAreaLayout] = useState({width: 0, height: 0});",
        "  const [readerWindowLayout, setReaderWindowLayout] = useState({width: 0, height: 0});\n"
        "  const [pageAreaLayout, setPageAreaLayout] = useState({width: 0, height: 0});", 'window bounds')
    text = once(text, '  const measuredLandscape = pageAreaReady\n'
        '    ? pageAreaLayout.width > pageAreaLayout.height\n    : isLandscape;',
        '  // Docked tools may make portrait content wider than tall. Orientation\n'
        '  // belongs to the measured whole reader window, not the reduced page area.\n'
        '  const measuredLandscape = readerWindowLayout.width > 0 && readerWindowLayout.height > 0\n'
        '    ? readerWindowLayout.width > readerWindowLayout.height\n    : isLandscape;', 'physical orientation')
    text = once(text, '<SafeAreaView style={styles.root}>',
        '<SafeAreaView style={styles.root} onLayout={event => {\n'
        '      const {width,height} = event.nativeEvent.layout;\n'
        '      if (width > 0 && height > 0) setReaderWindowLayout(current =>\n'
        '        current.width === width && current.height === height ? current : {width,height});\n'
        '    }}>','whole-window layout')
    text = once(text, "  const getReaderKeyContext = () => {", '''  const pdfiumSceneRef = useRef(null);
  const pdfium = useInteractivePdf({
    current: () => mountedRef.current && !readerTransitionLocked() && !fatalError,
    canInteract: () => !renderingRef.current && !settingsOpen && !jumpOpen && !editBusy,
    canRecover: () => mountedRef.current && !readerTransitionLocked() && !settingsOpen && !jumpOpen,
    startRender: () => setRendering(true),
    clearError: () => setFatalError(null),
    admit: spec => Boolean(spec && spec.renderToken === nativeRenderRef.current.token &&
      nativeRenderRef.current.expected.has(spec.pageIndex)),
    fence: () => fenceReaderKeys(),
    page: () => pageIndexRef.current,
    navigate: page => setPageIndex(page),
    gesture: event => {
      if (readerTransitionLocked() || renderingRef.current || pdfium.modalRef.current) return;
      const {dx,dy} = event;
      if (Math.abs(dx) > Math.abs(dy) && handlePhysicalSwipe(dx)) return;
      if (Math.abs(dx) > TAP_SLOP || Math.abs(dy) > TAP_SLOP) return;
      const fraction = event.slot === 'left' ? event.fraction / 2 :
        event.slot === 'right' ? .5 + event.fraction / 2 : event.fraction;
      if (fraction <= EDGE_ZONE) {
        if (directionRef.current === 'rtl') previousLogicalPage(); else nextLogicalPage();
      } else if (fraction >= 1-EDGE_ZONE) {
        if (directionRef.current === 'rtl') nextLogicalPage(); else previousLogicalPage();
      } else { setPageIndex(event.pageIndex); setChromeVisible(value => !value); }
    },
  });
  pdfiumInputFenceRef.current = pdfium.fenceInput;
  pdfium.syncInput(rendering || settingsOpen || jumpOpen || editBusy || pdfium.modal);

  const getReaderKeyContext = () => {''', 'controller seam')
    text = once(text, '  const fenceReaderKeys = () => {',
        '  const pdfiumInputFenceRef = useRef(null);\n  const fenceReaderKeys = (fencePdf = true) => {\n'
        '    if (fencePdf) pdfiumInputFenceRef.current?.();', 'synchronous input epoch')
    text = once(text, '    if (next !== previous) fenceReaderKeys();\n', '', 'page fence placement')
    text = once(text, "    if (visiblePages(previous).join(',') !== visiblePages(next).join(',')) invalidateSavedInkPresentation();",
        "    const pairChanged = visiblePages(previous).join(',') !== visiblePages(next).join(',');\n"
        '    if (next !== previous) fenceReaderKeys(pairChanged);\n'
        '    if (pairChanged) invalidateSavedInkPresentation();', 'same-pair input ownership')
    text = once(text, '  const readerKeyGeometry = JSON.stringify([filePathRef.current, pageIndex, effectiveMode,',
        "  const readerKeyPageGeometry = effectiveMode === 'single' ? pageIndex :\n"
        '    getVisualSpread(pageIndex, coverSeparate, totalPagesRef.current, direction);\n'
        '  const readerKeyGeometry = JSON.stringify([filePathRef.current, readerKeyPageGeometry, effectiveMode,',
        'same-pair key settlement')
    text = once(text, "blocked: !mountedRef.current || !ui.preferencesReady || !file || !settled ||",
        "blocked: pdfium.modalRef.current || !pdfium.owner || !mountedRef.current || !ui.preferencesReady || !file || !settled ||", 'key fence')
    text = once(text,
        "  const savedInkProfile = selectSavedInkProfile(documentContext?.filePath, totalPages);",
        "  // Saved ink is deliberately parked in the interactive-reader alpha.\n  const savedInkProfile = null;", 'park ink')
    text = once(text, "        const restored = decodePreferences(rawPreferences, context);",
        "        const openedPdf = await pdfium.open(context);\n"
        "        if (!mountedRef.current) return;\n"
        "        const restored = decodePreferences(restoreSourcePreferences(rawPreferences, openedPdf.sourceSha256), context);", 'read/open admission')
    text = once(text, "      lastPageIndex: editReturnRef.current ? editReturnRef.current.editPage : pageIndex,",
        "      pdfSourceSha256: pdfium.owner?.sourceSha256,\n"
        "      lastPageIndex: editReturnRef.current ? editReturnRef.current.editPage : pageIndex,", 'source preferences')
    marker = '    const token = ++renderTokenRef.current;'
    text = once(text, marker, '''    if (!pdfium.owner || pdfium.isRetired()) return;
    if (readerTransitionLocked()) { pdfiumSceneRef.current = null; return; }
    // Error chrome changes the measured viewport. Do not silently clear a
    // native failure and retry the same rejected pose through that resize.
    if (fatalError) return;
    const preview = effectiveMode === 'single' ? [pageIndex] :
      getVisualSpread(pageIndex, coverSeparate, totalPagesRef.current, direction);
    const scene = JSON.stringify([pdfium.owner.sessionId,preview,effectiveMode,direction,
      coverSeparate,spreadSizing,measuredPageWidth,pageAreaLayout.height,pdfium.revision]);
    if (pdfiumSceneRef.current === scene) return; // Same-pair focus does not destroy selection.
    pdfiumSceneRef.current = scene;
    const token = ++renderTokenRef.current;''', 'scene admission')
    # This dependency tuple belongs to the generated foreground scene only.
    text = once(text, '    measuredPageWidth,\n  ]);\n\n  const handleNativeRendered',
        '    measuredPageWidth,\n    pageAreaLayout.height,\n    spreadSizing,\n    pdfium.owner,\n    pdfium.revision,\n    editBusy,\n    fatalError,\n  ]);\n\n  const handleNativeRendered', 'scene deps')
    text = once(text, '    const finishClose = async () => {', '''    try {
      await pdfium.close(!pdfium.sourceInvalid.current);
      if (pdfium.sourceInvalid.current) transitionTokenRef.current.skipHandoff = true;
    } catch (error) {
      closeInFlightRef.current = false;
      releaseReaderTransition();
      setEditBusy(false);
      setFatalError(error?.message ?? 'PDF cleanup could not be verified.');
      return;
    }
    const finishClose = async () => {''', 'close drain')
    text = once(text, "      await savePreferences('edit', payload);",
        "      await savePreferences('edit', payload);\n      await pdfium.close(true);", 'edit drain')
    text = once(text, "      console.warn('RTL_READER_PREFS_EDIT_SAVE_FAILED', error);",
        "      console.warn('RTL_READER_PREFS_EDIT_SAVE_FAILED', error);\n"
        "      if (error?.code === 'PDFIUM_SOURCE') setFatalError(error.message);", 'replacement failure')
    text = once(text, "        setEditNotice(failure === 'ink_cleanup_failed'",
        "        if (pdfium.isRetired()) {\n"
        "          setFatalError('Edit did not complete. Close and reopen RTL Reader before reading again.');\n"
        "          setRendering(false);\n"
        "        }\n"
        "        setEditNotice(failure === 'ink_cleanup_failed'", 'retired Edit failure')
    text = once(text, '        {...panResponderRef.current.panHandlers}>',
        '        >', 'exclusive touch')
    if text.count('<View style={styles.blankPage} />') != 2:
        raise ValueError('Expected exactly two non-interactive blank spread slots')
    # Blank cover/last-page slots have no PDF hit-test owner. Only those slots
    # retain the proven RN reading gestures; never compete with a PDF surface.
    text = text.replace('<View style={styles.blankPage} />',
        '<View style={styles.blankPage} {...panResponderRef.current.panHandlers} />')
    text = once(text, "                  : savedInkProfile ? `${statusCover} · Ink unavailable for this page/view` : statusCover",
        "                  : savedInkProfile ? `${statusCover} · Ink unavailable for this page/view` : `${statusCover} · Saved ink is available in Edit, not this view`", 'parked ink notice')
    if text.count('<NativePdfPageView') != 3:
        raise ValueError('Expected portrait and exactly two spread view slots')
    text = text.replace('<NativePdfPageView', '<InteractivePdfPage')
    for slot, prop in [('left','leftPageIndex'),('right','rightPageIndex'),('single','singlePageIndex')]:
        text = once(text, f'                  pageIndex={{display.{prop}}}' if slot!='single' else f'            pageIndex={{display.{prop}}}',
            f'                  page={{display.{prop}}}\n                  reader={{pdfium}} slot="{slot}" token={{display.renderToken}}\n'
            '                  width={measuredPageWidth} height={pageAreaLayout.height}\n'
            '                  blocked={false}\n'
            '                  inputBlocked={rendering || settingsOpen || jumpOpen || editBusy || pdfium.modal}', slot+' view')
    text = text.replace('onPdfRendered={event => handleNativeRendered(event, display.renderToken)}',
        'onRendered={event => handleNativeRendered(event, display.renderToken)}')
    text = text.replace('onPdfError={event => handleNativeError(event, display.renderToken)}',
        'onError={event => handleNativeError(event, display.renderToken)}')
    # Preserve existing Edit/Settings/Close and logical footer callbacks, but dock
    # their chrome outside the page viewport so selectable text is not obscured.
    chrome_start=text.index('      {chromeVisible && !fatalError && (')
    header_start=text.index('          <View style={styles.header}>',chrome_start)
    footer_start=text.index('          <View style={[styles.footer,',header_start)
    chrome_end=text.index('      {settingsOpen && !fatalError && (',footer_start)
    tail=text[footer_start:chrome_end]
    fragment_end=tail.rindex('        </>')
    header=text[header_start:footer_start].replace('style={styles.header}',"style={[styles.header,{position:'relative'}]}")
    footer=tail[:fragment_end].replace("style={[styles.footer, {direction: 'ltr'}]}","style={[styles.footer,{direction:'ltr',position:'relative'}]}")
    text=text[:chrome_start]+text[chrome_end:]
    text=once(text,'      <ReaderKeyView',
        '      {chromeVisible && !fatalError && <View>\n'+header+
        '        <InteractivePdfTools reader={pdfium} activePage={pageIndex} disabled={rendering || editBusy || settingsOpen || jumpOpen} />\n'
        '      </View>}\n\n      <ReaderKeyView','docked header')
    text=once(text,'      </ReaderKeyView>', '      </ReaderKeyView>\n'
        '      {chromeVisible && !fatalError && <View>\n'+footer+'      </View>}\n'
        '      <InteractivePdfBookmarks reader={pdfium} />','docked footer/bookmarks')
    text=once(text,'          <Text style={styles.errorText}>{fatalError}</Text>',
        '          <Text style={styles.errorText}>{fatalError}</Text>\n'
        '          {pdfium.owner && !pdfium.isRetired() && !pdfium.sourceInvalid.current && <Pressable onPress={pdfium.recoverFit} style={styles.panelButton}>\n'
        '            <Text style={styles.panelButtonText}>Try Fit</Text>\n'
        '          </Pressable>}', 'explicit safe presentation recovery')
    return text


def patch_index(text):
    if 'globalThis.RTL_PDFIUM_OWNER' in text:
        raise ValueError('PDFium index already integrated')
    return once(text, '  const inkLifecycle = globalThis.RTL_READER_INK_LIFECYCLE;',
        '  const pdfiumOwner = globalThis.RTL_PDFIUM_OWNER;\n'
        '  if (pdfiumOwner) {\n'
        '    await pdfiumOwner.close(!pdfiumOwner.sourceInvalid.current);\n'
        '    if (pdfiumOwner.sourceInvalid.current) handoffAttemptedThisActivation = true;\n'
        '  }\n  const inkLifecycle = globalThis.RTL_READER_INK_LIFECYCLE;', 'outside-App close drain')


if __name__=='__main__':
    if len(sys.argv)!=3: raise SystemExit('usage: patch_pdfium_reader.py <generated-App.js> <generated-index.js>')
    app,index=map(Path,sys.argv[1:])
    # Validate both transforms before changing either generated artifact.
    a=patch_app(app.read_text(encoding='utf-8'));b=patch_index(index.read_text(encoding='utf-8'))
    app.write_text(a,encoding='utf-8');index.write_text(b,encoding='utf-8')
