#!/usr/bin/env python3
"""Verify the RTL Reader Edit/Return wiring across overlay, build, and native layers.

Text-level checks only; behavior is covered by scripts/test_edit_return.js.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# The three pre-existing SIGKILL sites in ReaderPreferencesModule (handoff
# restart, restore-race guard, backup-restore guard). Edit/Return must reuse
# the handoff path and never add another way to kill the stock reader.
EXPECTED_OS_KILL_SITES = 3
EDIT_NAMES = (
    "EDIT_BLOCKED_MESSAGES",
    "buildEditPayload",
    "buildEditReturnRecord",
    "chooseInitialPage",
    "editAvailability",
    "evaluateHandoff",
    "listEditTargets",
)


def fail(message: str) -> None:
    print(f"Edit/Return invariants: FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def between(text: str, start: str, end: str, label: str) -> str:
    s = text.find(start)
    require(s >= 0, f"missing {label} start marker")
    e = text.find(end, s)
    require(e > s, f"missing {label} end marker")
    return text[s:e]


def main(root: Path) -> None:
    module = (root / "overlay/editReturn.js").read_text(encoding="utf-8")
    app = (root / "overlay/App.js").read_text(encoding="utf-8")
    index = (root / "overlay/index.js").read_text(encoding="utf-8")
    build = (root / "build.sh").read_text(encoding="utf-8")
    kotlin = (root / "native/ReaderPreferencesModule.kt.template").read_text(
        encoding="utf-8"
    )
    workflow = (root / ".github/workflows/build.yml").read_text(encoding="utf-8")

    # 1. The logic module stays pure and host-testable.
    for forbidden in ("require(", "import ", "react-native", "NativeModules", "Date.now("):
        require(forbidden not in module, f"editReturn.js must stay pure: found {forbidden!r}")
    require("module.exports" in module, "editReturn.js must be CommonJS (host tests)")

    # 2. App.js uses the module and no longer duplicates page selection.
    match = re.search(r"import \{([^}]*)\} from './editReturn';", app)
    require(match is not None, "App.js does not import ./editReturn")
    imported = {name.strip() for name in match.group(1).split(",") if name.strip()}
    require(imported == set(EDIT_NAMES), f"unexpected editReturn imports: {sorted(imported)}")
    require("chooseInitialPage(saved, context, now)" in app, "decodePreferences must call chooseInitialPage")
    require("useSavedPage" not in app, "page selection logic must live only in editReturn.js")
    require("editReturn: editReturnRef.current" in app, "prefs payload must carry editReturn while pending")
    require("editReturnRef.current = null;" in app, "an Edit return must be consumed on open")

    # 3. The build ships the new overlay file.
    for name in ("App.js", "index.js", "editReturn.js"):
        require(
            f'cp "$ROOT/overlay/{name}" "$PROJECT/{name}"' in build,
            f"build.sh does not copy overlay/{name}",
        )

    # 4. Edit is Close-with-a-page: gated, saved, then the ordinary close path.
    edit = between(app, "const editPage = async page => {", "const closeSettings", "editPage")
    order = [edit.find(marker) for marker in (
        "editAvailability({", "buildEditPayload(", "editInFlightRef.current = true;",
        "await savePreferences('edit', payload)",
        "evaluateHandoff(",
        "await ReaderPreferencesModule.handoffLastSavedPage()", "globalThis.RTL_READER_EDIT_HANDOFF_DONE = true",
        "PluginManager.closePluginView()",
    )]
    require(all(i >= 0 for i in order) and order == sorted(order), "editPage steps out of order")
    require(edit.count("await rollback(") == 2 and "rollback('handoff_failed')" in edit
            and "rollback('save_failed')" in edit, "editPage must roll back on save and handoff failure")
    require("await savePreferences('edit-rollback', previous.payload)" in edit
            and "editReturnRef.current = previous.editReturn;" in edit
            and "latestPreferencesRef.current = previous.payload;" in edit,
            "rollback must restore memory and disk state")
    for forbidden in ("NativeModules", "kill", "startActivity"):
        require(forbidden not in edit, f"editPage must not add another restart path, found {forbidden!r}")
    require(edit.count("handoffLastSavedPage") == 2, "editPage must call handoffLastSavedPage exactly once")
    require(
        app.count("const editPage = async page =>") == 1 and app.count("editPage(") == 1,
        "editPage must be declared once and called only from the Edit buttons",
    )
    # Exclusivity: nothing else may write prefs or move pages while an Edit is in flight.
    for marker in (
        "if (editInFlightRef.current && !reason.startsWith('edit')) return;",
        "const close = async () => {\n    if (editInFlightRef.current) return;",
        "const setPageIndex = value => {\n    if (editInFlightRef.current) return;\n    setPageIndexRaw(value);",
    ):
        require(marker in app, f"missing Edit exclusivity guard: {marker!r}")
    # The close wrapper must not run a second handoff after Edit already did.
    require("globalThis.RTL_READER_EDIT_HANDOFF_DONE === true" in index
            and "globalThis.RTL_READER_EDIT_HANDOFF_DONE = false" in index,
            "index.js must skip the wrapper handoff when Edit already ran it")
    require("disabled={nativeSpreadBusy || editBusy || !editSettled}\n                  onPress={() => editPage(target.page)}" in app,
            "Edit buttons must be disabled while busy, editing, or before the render settles")

    # 5. No new kill site; the single existing handoff path stays intact.
    kills = kotlin.count("Os.kill(")
    require(kills == EXPECTED_OS_KILL_SITES, f"Os.kill sites changed: {kills} != {EXPECTED_OS_KILL_SITES}")
    require(index.count("ReaderPreferencesModule.handoffLastSavedPage()") == 1, "index.js handoff call changed")
    require("handoffAttemptedThisActivation" in index, "index.js once-per-activation guard missing")

    # 6. CI runs the tests and this invariant.
    require("node scripts/test_edit_return.js" in workflow, "CI does not run the Edit/Return host tests")
    require("scripts/check_edit_return_invariants.py" in workflow, "CI does not run the Edit/Return invariants")

    print("Edit/Return invariants: PASS")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        fail("usage: check_edit_return_invariants.py <repo-root>")
    main(Path(sys.argv[1]))
