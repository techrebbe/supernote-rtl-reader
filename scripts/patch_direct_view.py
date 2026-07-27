#!/usr/bin/env python3
"""Patch the generated v0.3.0 reader to use PdfPageView for foreground rendering.

This is intentionally a strict build-time transform for the experimental direct-render
branch. Every replacement asserts the v0.2.1 source marker it expects so an upstream
App.js change fails the build instead of silently producing a partial reader.
"""

from __future__ import annotations

import sys
from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"patch_direct_view.py: expected one {label} marker, found {count}")
    return text.replace(old, new, 1)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: patch_direct_view.py <generated-App.js>")

    path = Path(sys.argv[1])
    text = path.read_text(encoding="utf-8")

    text = replace_once(
        text,
        "  PanResponder,\n  Pressable,",
        "  PanResponder,\n  Pressable,\n  requireNativeComponent,",
        "React Native import",
    )

    text = replace_once(
        text,
        "const {PdfRendererModule, ReaderPreferencesModule} = NativeModules;\n",
        "const {PdfRendererModule, ReaderPreferencesModule} = NativeModules;\n"
        "const NativePdfPageView = requireNativeComponent('PdfPageView');\n",
        "native component declaration",
    )

    text = replace_once(
        text,
        "  const cacheRef = useRef(new Map());\n  const prefetchingRef = useRef(new Set());\n",
        "  const cacheRef = useRef(new Map());\n"
        "  const prefetchingRef = useRef(new Set());\n"
        "  const nativeRenderRef = useRef({token: 0, expected: new Set(), loaded: new Set()});\n",
        "native render ref",
    )

    text = replace_once(
        text,
        "RTL Reader v0.1.0 currently supports PDF documents only.",
        "RTL Reader v0.3.0 currently supports PDF documents only.",
        "PDF-only version string",
    )

    render_start_marker = (
        "  useEffect(() => {\n"
        "    if (!preferencesReady || !documentContext || !Number.isInteger(pageIndex)) return;\n\n"
        "    const token = ++renderTokenRef.current;\n\n"
        "    async function renderCurrentView() {"
    )
    render_start = text.find(render_start_marker)
    if render_start < 0:
        raise SystemExit("patch_direct_view.py: foreground render effect start marker not found")

    close_marker = "\n\n  const close = async () => {"
    render_end = text.find(close_marker, render_start)
    if render_end < 0:
        raise SystemExit("patch_direct_view.py: foreground render effect end marker not found")

    native_render_block = r'''  useEffect(() => {
    if (!preferencesReady || !documentContext || !Number.isInteger(pageIndex)) return;

    const token = ++renderTokenRef.current;
    const pageCount = totalPagesRef.current;

    if (effectiveMode === 'single') {
      nativeRenderRef.current = {
        token,
        expected: new Set([pageIndex]),
        loaded: new Set(),
      };
      setDisplay({kind: 'single', singlePageIndex: pageIndex});
      setFatalError(null);
      setRendering(true);
      console.log(`RTL_READER_NATIVE_VIEW_REQUEST mode=single page=${pageIndex + 1}`);
      return;
    }

    const visual = getVisualSpread(
      pageIndex,
      coverSeparate,
      pageCount,
      direction,
    );
    const expected = [visual.left, visual.right].filter(Number.isInteger);
    nativeRenderRef.current = {
      token,
      expected: new Set(expected),
      loaded: new Set(),
    };
    setDisplay({
      kind: 'spread',
      leftPageIndex: visual.left,
      rightPageIndex: visual.right,
    });
    setFatalError(null);
    setRendering(expected.length > 0);
    console.log(
      `RTL_READER_NATIVE_VIEW_REQUEST mode=spread left=${
        visual.left === null ? 'blank' : visual.left + 1
      } right=${visual.right === null ? 'blank' : visual.right + 1}`,
    );
  }, [
    preferencesReady,
    documentContext,
    pageIndex,
    effectiveMode,
    direction,
    coverSeparate,
    window.width,
  ]);

  const handleNativeRendered = event => {
    const nativeEvent = event?.nativeEvent;
    const renderedPage = nativeEvent?.pageIndex;
    if (!Number.isInteger(renderedPage)) return;

    const pending = nativeRenderRef.current;
    if (!pending.expected.has(renderedPage)) return;

    pending.loaded.add(renderedPage);
    if (Number.isInteger(nativeEvent?.pageCount)) {
      totalPagesRef.current = nativeEvent.pageCount;
      setTotalPages(nativeEvent.pageCount);
    }

    const complete = [...pending.expected].every(candidate =>
      pending.loaded.has(candidate),
    );
    if (complete) {
      setRendering(false);
      console.log(
        `RTL_READER_NATIVE_VIEW_READY token=${pending.token} pages=${[
          ...pending.loaded,
        ]
          .map(candidate => candidate + 1)
          .join(',')}`,
      );
    }
  };

  const handleNativeError = event => {
    const nativeEvent = event?.nativeEvent;
    const failedPage = nativeEvent?.pageIndex;
    const pending = nativeRenderRef.current;
    if (Number.isInteger(failedPage) && !pending.expected.has(failedPage)) return;

    const message = nativeEvent?.message ?? 'Native PDF view could not render this page.';
    console.error('RTL_READER_NATIVE_VIEW_ERROR', message);
    setFatalError(message);
    setRendering(false);
  };'''

    text = text[:render_start] + native_render_block + text[render_end:]

    old_view_block = r'''        {display.kind === 'spread' ? (
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
        )}'''

    new_view_block = r'''        {display.kind === 'spread' ? (
          <View style={styles.spread}>
            <View style={styles.spreadPage}>
              {Number.isInteger(display.leftPageIndex) ? (
                <NativePdfPageView
                  filePath={documentContext?.filePath ?? ''}
                  pageIndex={display.leftPageIndex}
                  requestedWidth={Math.max(360, Math.floor(window.width / 2))}
                  onPdfRendered={handleNativeRendered}
                  onPdfError={handleNativeError}
                  style={styles.pageImage}
                />
              ) : (
                <View style={styles.blankPage} />
              )}
            </View>
            <View style={styles.spreadDivider} />
            <View style={styles.spreadPage}>
              {Number.isInteger(display.rightPageIndex) ? (
                <NativePdfPageView
                  filePath={documentContext?.filePath ?? ''}
                  pageIndex={display.rightPageIndex}
                  requestedWidth={Math.max(360, Math.floor(window.width / 2))}
                  onPdfRendered={handleNativeRendered}
                  onPdfError={handleNativeError}
                  style={styles.pageImage}
                />
              ) : (
                <View style={styles.blankPage} />
              )}
            </View>
          </View>
        ) : Number.isInteger(display.singlePageIndex) ? (
          <NativePdfPageView
            filePath={documentContext?.filePath ?? ''}
            pageIndex={display.singlePageIndex}
            requestedWidth={Math.max(600, Math.round(window.width))}
            onPdfRendered={handleNativeRendered}
            onPdfError={handleNativeError}
            style={styles.pageImage}
          />
        ) : (
          <View style={styles.center} />
        )}'''

    text = replace_once(text, old_view_block, new_view_block, "page view JSX")

    path.write_text(text, encoding="utf-8")
    print("Patched generated App.js for direct native PDF foreground rendering")


if __name__ == "__main__":
    main()
