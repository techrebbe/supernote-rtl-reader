#!/usr/bin/env python3
"""Make the generated Supernote packager fail closed for this native plugin."""

from __future__ import annotations

import sys
from pathlib import Path


EXPECTED_PACKAGE = "com.supernotertlreader.PdfRendererPackage"
EXPECTED_SOURCE = (
    "android/app/src/main/java/com/supernotertlreader/PdfRendererPackage.kt"
)
EXPECTED_APPLICATION = (
    "android/app/src/main/java/com/supernotertlreader/MainApplication.kt"
)

UPSTREAM_PACKAGE_SCAN = '''    local project_react_pkgs
    project_react_pkgs="$(find_manual_react_packages_from_application "$project_root" || true)"
'''
STRICT_PACKAGE = f'''    # RTL Reader always requires its reviewed native bridge. Do not infer this
    # security boundary from a best-effort source scanner: verify the exact
    # generated source and registration, then publish the exact package name.
    local expected_react_package="{EXPECTED_PACKAGE}"
    local expected_react_source="$project_root/{EXPECTED_SOURCE}"
    local expected_application="$project_root/{EXPECTED_APPLICATION}"
    if [[ ! -f "$expected_react_source" ]]; then
        write_color_output "Required RTL Reader native package source is missing" "Red"
        return 1
    fi
    if [[ ! -f "$expected_application" ]] || \\
       ! grep -Fq 'add(PdfRendererPackage())' "$expected_application"; then
        write_color_output "Required RTL Reader native package registration is missing" "Red"
        return 1
    fi
    local project_react_pkgs="$expected_react_package"
'''
UPSTREAM_PACKAGE_UPDATE = '''        local all_pkgs
        all_pkgs="$(printf "%s\\n%s\\n" "$project_react_pkgs" "$autolink_pkgs" | awk 'NF' | sort -u)"
        update_plugin_config_packages "$project_root" "$gen_dir" "$all_pkgs"
'''
STRICT_PACKAGE_UPDATE = '''        local all_pkgs
        all_pkgs="$(printf "%s\\n%s\\n" "$project_react_pkgs" "$autolink_pkgs" | awk 'NF' | sort -u)"
        if [[ "$all_pkgs" != "$expected_react_package" ]]; then
            write_color_output "Unexpected ReactPackage set: $all_pkgs" "Red"
            return 1
        fi
        update_plugin_config_packages "$project_root" "$gen_dir" "$all_pkgs"
'''
UPSTREAM_SOFT_NATIVE_BUILD = '''        if build_android_apk "$project_root" "$gen_cfg"; then
            copy_apk_and_update_config "$project_root" "$gen_dir" "$gen_cfg" || true
        else
            write_color_output "APK build failed" "Red"
        fi
    else
        write_color_output "Build conditions not met; skipping native build and reactPackages update" "Yellow"
    fi
'''
STRICT_NATIVE_BUILD = '''        if ! build_android_apk "$project_root" "$gen_cfg"; then
            write_color_output "Required RTL Reader native APK build failed" "Red"
            return 1
        fi
        if ! copy_apk_and_update_config "$project_root" "$gen_dir" "$gen_cfg"; then
            write_color_output "Required RTL Reader native APK packaging failed" "Red"
            return 1
        fi
    else
        write_color_output "Required RTL Reader native build was not selected" "Red"
        return 1
    fi
'''


def fail(message: str) -> None:
    raise SystemExit(f"patch_plugin_packager.py: {message}")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        fail(f"expected one {label} marker, found {count}")
    return text.replace(old, new, 1)


def patch_text(text: str) -> str:
    text = replace_once(
        text,
        UPSTREAM_PACKAGE_SCAN,
        STRICT_PACKAGE,
        "best-effort native-package scan",
    )

    text = replace_once(
        text,
        UPSTREAM_PACKAGE_UPDATE,
        STRICT_PACKAGE_UPDATE,
        "ReactPackage publication",
    )

    return replace_once(
        text,
        UPSTREAM_SOFT_NATIVE_BUILD,
        STRICT_NATIVE_BUILD,
        "soft native-build fallback",
    )


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: patch_plugin_packager.py <generated-buildPlugin.sh>")

    path = Path(sys.argv[1]).resolve()
    if not path.is_file():
        fail(f"packager not found: {path}")
    original = path.read_text(encoding="utf-8")
    patched = patch_text(original)
    path.write_text(patched, encoding="utf-8", newline="\n")
    print(f"Hardened generated native plugin packager: {path}")


if __name__ == "__main__":
    main()
