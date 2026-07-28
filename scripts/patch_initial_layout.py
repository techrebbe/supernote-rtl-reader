#!/usr/bin/env python3
"""Make the first native page request wait for the measured plugin content area.

PluginHost can initially report stale portrait window dimensions when the plugin is
opened while the device is already in landscape.  Mounting PdfPageView before the
page area has completed its first layout can leave the initial spread blank until a
later prop change.  This strict transform makes layout measurement the source of
truth for initial mode selection and render width.
"""

from __future__ import annotations

import sys
from pathlib import Path


def fail(message: str) -> None:
    raise SystemExit(f"patch_initial_layout.py: {message}")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        fail(f"expected one {label} marker, found {count}")
    return text.replace(old, new, 1)


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: patch_initial_layout.py <generated-App.js>")

    path = Path(sys.argv[1]).resolve()
    text = path.read_text(encoding="utf-8")

    text = replace_once(
        text,
        "  const [jumpText, setJumpText] = useState('');\n\n"
        "  const effectiveMode =\n"
        "    viewMode === 'auto' ? (isLandscape ? 'spread' : 'single') : viewMode;",
        "  const [jumpText, setJumpText] = useState('');\n"
        "  const [pageAreaLayout, setPageAreaLayout] = useState({width: 0, height: 0});\n\n"
        "  const pageAreaReady = pageAreaLayout.width > 0 && pageAreaLayout.height > 0;\n"
        "  const measuredPageWidth = pageAreaReady\n"
        "    ? Math.max(1, Math.round(pageAreaLayout.width))\n"
        "    : 0;\n"
        "  const measuredLandscape = pageAreaReady\n"
        "    ? pageAreaLayout.width > pageAreaLayout.height\n"
        "    : isLandscape;\n\n"
        "  const effectiveMode =\n"
        "    viewMode === 'auto' ? (measuredLandscape ? 'spread' : 'single') : viewMode;",
        "measured page-area state",
    )

    text = replace_once(
        text,
        "  pageAreaWidthRef.current = Math.max(1, window.width);",
        "  pageAreaWidthRef.current = Math.max(\n"
        "    1,\n"
        "    pageAreaReady ? measuredPageWidth : window.width,\n"
        "  );",
        "page-area width ref",
    )

    text = replace_once(
        text,
        "  useEffect(() => {\n"
        "    if (!preferencesReady || !documentContext || !Number.isInteger(pageIndex)) return;\n\n"
        "    const token = ++renderTokenRef.current;",
        "  useEffect(() => {\n"
        "    if (\n"
        "      !preferencesReady ||\n"
        "      !documentContext ||\n"
        "      !Number.isInteger(pageIndex) ||\n"
        "      !pageAreaReady\n"
        "    ) {\n"
        "      return;\n"
        "    }\n\n"
        "    const token = ++renderTokenRef.current;",
        "layout-ready native render gate",
    )

    spread_width = "requestedWidth={Math.max(360, Math.floor(window.width / 2))}"
    spread_count = text.count(spread_width)
    if spread_count != 2:
        fail(f"expected two spread requestedWidth markers, found {spread_count}")
    text = text.replace(
        spread_width,
        "requestedWidth={Math.max(360, Math.floor(measuredPageWidth / 2))}",
    )

    text = replace_once(
        text,
        "requestedWidth={Math.max(600, Math.round(window.width))}",
        "requestedWidth={Math.max(600, measuredPageWidth)}",
        "single requestedWidth",
    )

    text = replace_once(
        text,
        "    coverSeparate,\n"
        "    window.width,\n"
        "  ]);",
        "    coverSeparate,\n"
        "    pageAreaReady,\n"
        "    measuredPageWidth,\n"
        "  ]);",
        "native render layout dependencies",
    )

    text = replace_once(
        text,
        "        onLayout={event => {\n"
        "          pageAreaWidthRef.current = Math.max(1, event.nativeEvent.layout.width);\n"
        "          pageAreaLeftRef.current = event.nativeEvent.layout.x ?? 0;\n"
        "        }}",
        "        onLayout={event => {\n"
        "          const layout = event.nativeEvent.layout;\n"
        "          const width = Math.max(1, Math.round(layout.width));\n"
        "          const height = Math.max(1, Math.round(layout.height));\n"
        "          pageAreaWidthRef.current = width;\n"
        "          pageAreaLeftRef.current = layout.x ?? 0;\n"
        "          setPageAreaLayout(current =>\n"
        "            current.width === width && current.height === height\n"
        "              ? current\n"
        "              : {width, height},\n"
        "          );\n"
        "        }}",
        "page-area onLayout measurement",
    )

    path.write_text(text, encoding="utf-8")
    print("Patched generated App.js to wait for measured page-area layout")


if __name__ == "__main__":
    main()
