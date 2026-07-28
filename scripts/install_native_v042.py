#!/usr/bin/env python3
"""Run the v0.4.2 native installer with one explicitly first-match foreground patch.

The source template contains the same renderLocked call in foreground and prefetch code.
The v0.4.2 cancellation guard belongs only before the first (foreground) occurrence;
all other strict install_native.py assertions remain unchanged.
"""

from __future__ import annotations

import install_native


_original_replace_once = install_native.replace_once


def _replace_once(text: str, old: str, new: str, label: str) -> str:
    if label == "pre-render cancellation":
        count = text.count(old)
        if count < 1:
            install_native.fail("expected a pre-render cancellation marker, found 0")
        return text.replace(old, new, 1)
    return _original_replace_once(text, old, new, label)


install_native.replace_once = _replace_once
install_native.main()
