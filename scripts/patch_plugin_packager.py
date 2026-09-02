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
EXPECTED_PLUGIN_APK_SIGNER_SHA256 = (
    "fac61745dc0903786fb9ede62a962b399f7348f0bb6f899b8332667591033b9c"
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

APK_COPY_FUNCTION_MARKER = '''# =========================================================
# Function: copy_apk_and_update_config
'''
STRICT_APK_RESIGNING = '''# =========================================================
# Function: sign_compacted_apk
# Purpose: The upstream custom task rewrites a signed APK while removing
#          unused native libraries. Re-align and re-sign those final bytes.
# =========================================================
sign_compacted_apk() {
    local project_root="$1"
    local apk_path="$2"
    local sdk_root="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}"
    if [[ -z "$sdk_root" ]]; then
        write_color_output "Android SDK root is unavailable for final APK signing" "Red"
        return 1
    fi
    if command -v cygpath >/dev/null 2>&1 && [[ "$sdk_root" =~ ^[A-Za-z]:[\\/] ]]; then
        sdk_root="$(cygpath -u "$sdk_root")"
    fi
    local build_tools_root="$sdk_root/build-tools"
    [[ -d "$build_tools_root" ]] || {
        write_color_output "Android build-tools directory is unavailable" "Red"
        return 1
    }
    local build_tools
    build_tools="$(find "$build_tools_root" -mindepth 1 -maxdepth 1 -type d -print | sort -V | tail -n 1)"
    [[ -n "$build_tools" ]] || {
        write_color_output "No Android build-tools version is installed" "Red"
        return 1
    }
    local zipalign="$build_tools/zipalign"
    local apksigner="$build_tools/apksigner"
    if [[ -f "${zipalign}.exe" ]]; then zipalign="${zipalign}.exe"; fi
    if [[ -f "${apksigner}.bat" ]]; then apksigner="${apksigner}.bat"; fi
    [[ -f "$zipalign" && -f "$apksigner" ]] || {
        write_color_output "zipalign/apksigner is unavailable" "Red"
        return 1
    }
    local keystore="$project_root/android/app/debug.keystore"
    [[ -f "$keystore" ]] || {
        write_color_output "Generated Android signing keystore is missing" "Red"
        return 1
    }
    local aligned="${apk_path%.apk}-aligned.apk"
    local signed="${apk_path%.apk}-signed.apk"
    rm -f "$aligned" "$signed"
    "$zipalign" -f 4 "$apk_path" "$aligned" || return 1
    "$apksigner" sign \\
        --ks "$keystore" \\
        --ks-pass pass:android \\
        --key-pass pass:android \\
        --ks-key-alias androiddebugkey \\
        --out "$signed" \\
        "$aligned" || return 1
    local verification_output
    if ! verification_output="$(
        "$apksigner" verify --verbose --print-certs "$signed" 2>&1
    )"; then
        write_color_output "Final compacted APK signature verification failed" "Red"
        return 1
    fi
    local expected_signer_sha256="__EXPECTED_PLUGIN_APK_SIGNER_SHA256__"
    local actual_signer_sha256
    actual_signer_sha256="$(
        printf '%s\\n' "$verification_output" |
        sed -n 's/^Signer #1 certificate SHA-256 digest: //p' |
        tr -d ':\\r' |
        tr '[:upper:]' '[:lower:]'
    )"
    if [[ "$(printf '%s\\n' "$verification_output" | tr -d '\\r' | grep -Fxc 'Number of signers: 1')" -ne 1 ]] || \
       [[ "$actual_signer_sha256" != "$expected_signer_sha256" ]]; then
        write_color_output "Final compacted APK signer is not the reviewed identity" "Red"
        return 1
    fi
    printf '%s\\n' "$signed"
}

'''
STRICT_APK_RESIGNING = STRICT_APK_RESIGNING.replace(
    "__EXPECTED_PLUGIN_APK_SIGNER_SHA256__",
    EXPECTED_PLUGIN_APK_SIGNER_SHA256,
)

UPSTREAM_APK_SELECTION = '''    [[ -z "$apk_path" ]] && { write_color_output "Generated APK not found" "Red"; return 1; }

    local new_apk="app.npk"
'''
STRICT_APK_SELECTION = '''    [[ -z "$apk_path" ]] && { write_color_output "Generated APK not found" "Red"; return 1; }

    local signed_apk
    if ! signed_apk="$(sign_compacted_apk "$project_root" "$apk_path")"; then
        write_color_output "Final compacted APK signing failed" "Red"
        return 1
    fi
    apk_path="$signed_apk"

    local new_apk="app.npk"
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
        APK_COPY_FUNCTION_MARKER,
        STRICT_APK_RESIGNING + APK_COPY_FUNCTION_MARKER,
        "APK copy function",
    )
    text = replace_once(
        text,
        UPSTREAM_APK_SELECTION,
        STRICT_APK_SELECTION,
        "final compacted APK selection",
    )
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
