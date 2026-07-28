#!/usr/bin/env python3
"""Patch the generated v0.4.0 reader to use direct native rendering + bitmap prefetch.

This remains a strict build-time transform. Every replacement asserts the stable App.js
source marker it expects so a baseline change fails CI instead of silently producing a
partial reader.
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
        "  const nativeRenderRef = useRef({token: 0, expected: new Set(), loaded: new Set()});\n"
        "  const interactionTimingRef = useRef({pageIndex: null, startedAtMs: 0});\n"
        "  const lastNavigationDeltaRef = useRef(1);\n",
        "native render refs",
    )

    text = replace_once(
        text,
        "RTL Reader v0.1.0 currently supports PDF documents only.",
        "RTL Reader v0.4.0 currently supports PDF documents only.",
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
    const interaction = interactionTimingRef.current;
    const requestStartedAtMs =
      interaction.pageIndex === pageIndex ? interaction.startedAtMs : 0;
    const movingForward = lastNavigationDeltaRef.current >= 0;

    if (effectiveMode === 'single') {
      const forward = normalizePage(pageIndex + 1, pageCount);
      const backward = normalizePage(pageIndex - 1, pageCount);
      const prefetchPageIndexes = (movingForward
        ? [forward, backward]
        : [backward, forward]
      ).filter(Number.isInteger);

      nativeRenderRef.current = {
        token,
        expected: new Set([pageIndex]),
        loaded: new Set(),
        interactionLatencies: [],
        requestStartedAtMs,
      };
      setDisplay({
        kind: 'single',
        singlePageIndex: pageIndex,
        prefetchPageIndexes,
        requestStartedAtMs,
      });
      setFatalError(null);
      setRendering(true);
      console.log(
        `RTL_READER_NATIVE_VIEW_REQUEST mode=single page=${pageIndex + 1} prefetch=${prefetchPageIndexes
          .map(candidate => candidate + 1)
          .join(',')}`,
      );
      return;
    }

    const visual = getVisualSpread(
      pageIndex,
      coverSeparate,
      pageCount,
      direction,
    );
    const expected = [visual.left, visual.right].filter(Number.isInteger);
    const nextPair = getSpreadPair(pageIndex + 2, coverSeparate, pageCount);
    const previousPair = getSpreadPair(pageIndex - 2, coverSeparate, pageCount);
    const forwardCandidates = [nextPair.earlier, nextPair.later].filter(Number.isInteger);
    const backwardCandidates = [previousPair.earlier, previousPair.later].filter(
      Number.isInteger,
    );
    const prefetchPageIndexes = (movingForward
      ? [...forwardCandidates, ...backwardCandidates]
      : [...backwardCandidates, ...forwardCandidates]
    ).filter((candidate, index, all) =>
      !expected.includes(candidate) && all.indexOf(candidate) === index,
    );

    nativeRenderRef.current = {
      token,
      expected: new Set(expected),
      loaded: new Set(),
      interactionLatencies: [],
      requestStartedAtMs,
    };
    setDisplay({
      kind: 'spread',
      leftPageIndex: visual.left,
      rightPageIndex: visual.right,
      prefetchPageIndexes,
      requestStartedAtMs,
    });
    setFatalError(null);
    setRendering(expected.length > 0);
    console.log(
      `RTL_READER_NATIVE_VIEW_REQUEST mode=spread left=${
        visual.left === null ? 'blank' : visual.left + 1
      } right=${
        visual.right === null ? 'blank' : visual.right + 1
      } prefetch=${prefetchPageIndexes.map(candidate => candidate + 1).join(',')}`,
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
    if (Number.isFinite(nativeEvent?.interactionMs) && nativeEvent.interactionMs >= 0) {
      pending.interactionLatencies.push(nativeEvent.interactionMs);
    }
    if (Number.isInteger(nativeEvent?.pageCount)) {
      totalPagesRef.current = nativeEvent.pageCount;
      setTotalPages(nativeEvent.pageCount);
    }

    const complete = [...pending.expected].every(candidate =>
      pending.loaded.has(candidate),
    );
    if (complete) {
      setRendering(false);
      const interactionLatency = pending.interactionLatencies.length
        ? Math.max(...pending.interactionLatencies)
        : null;
      console.log(
        `RTL_READER_NATIVE_VIEW_READY token=${pending.token} pages=${[
          ...pending.loaded,
        ]
          .map(candidate => candidate + 1)
          .join(',')}${
          interactionLatency === null ? '' : ` interactionMs=${interactionLatency}`
        }`,
      );
      if (pending.requestStartedAtMs > 0) {
        interactionTimingRef.current = {pageIndex: null, startedAtMs: 0};
      }
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

    old_go_by = r'''  const goBy = delta => {
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
  };'''
    new_go_by = r'''  const goBy = delta => {
    setPageIndex(current => {
      if (!Number.isInteger(current)) return current;
      const next = clampPage(current + delta, totalPagesRef.current);
      if (next !== current) {
        const startedAtMs = Date.now();
        interactionTimingRef.current = {pageIndex: next, startedAtMs};
        lastNavigationDeltaRef.current = delta;
        pageIndexRef.current = next;
        console.log(
          `RTL_READER_NAV from=${current + 1} to=${next + 1} direction=${directionRef.current} mode=${effectiveModeRef.current} startedAtMs=${startedAtMs}`,
        );
      }
      return next;
    });
  };'''
    text = replace_once(text, old_go_by, new_go_by, "navigation timing")

    old_submit_jump = r'''  const submitJump = () => {
    const requested = Number.parseInt(jumpText, 10);
    if (!Number.isFinite(requested)) return;
    const target = clampPage(requested - 1, totalPagesRef.current);
    pageIndexRef.current = target;
    console.log(`RTL_READER_JUMP requested=${requested} target=${target + 1}`);
    setPageIndex(target);
    Keyboard.dismiss();
    setJumpOpen(false);
  };'''
    new_submit_jump = r'''  const submitJump = () => {
    const requested = Number.parseInt(jumpText, 10);
    if (!Number.isFinite(requested)) return;
    const target = clampPage(requested - 1, totalPagesRef.current);
    const current = pageIndexRef.current;
    if (Number.isInteger(current) && target !== current) {
      const startedAtMs = Date.now();
      interactionTimingRef.current = {pageIndex: target, startedAtMs};
      lastNavigationDeltaRef.current = target - current;
    }
    pageIndexRef.current = target;
    console.log(`RTL_READER_JUMP requested=${requested} target=${target + 1}`);
    setPageIndex(target);
    Keyboard.dismiss();
    setJumpOpen(false);
  };'''
    text = replace_once(text, old_submit_jump, new_submit_jump, "jump timing")

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
                  prefetchPageIndexes={display.prefetchPageIndexes ?? []}
                  requestStartedAtMs={display.requestStartedAtMs ?? 0}
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
                  prefetchPageIndexes={display.prefetchPageIndexes ?? []}
                  requestStartedAtMs={display.requestStartedAtMs ?? 0}
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
            prefetchPageIndexes={display.prefetchPageIndexes ?? []}
            requestStartedAtMs={display.requestStartedAtMs ?? 0}
            onPdfRendered={handleNativeRendered}
            onPdfError={handleNativeError}
            style={styles.pageImage}
          />
        ) : (
          <View style={styles.center} />
        )}'''

    text = replace_once(text, old_view_block, new_view_block, "page view JSX")

    path.write_text(text, encoding="utf-8")
    print("Patched generated App.js for native bitmap prefetch + display latency timing")


if __name__ == "__main__":
    main()
