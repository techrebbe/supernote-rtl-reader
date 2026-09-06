#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_ROOT="$(mktemp -d)"
trap 'rm -rf "$WORK_ROOT"' EXIT
TEMPLATE_PACKAGE="@supernote-plugin/sn-plugin-template"
TEMPLATE_VERSION="1.0.12"
TEMPLATE_LOCK="$ROOT/provenance/plugin-template-package-lock.json.gz.b64"

if [[ -n "${PYTHON_BIN:-}" ]]; then
  if command -v cygpath >/dev/null 2>&1 && [[ "$PYTHON_BIN" =~ ^[A-Za-z]:[\\/] ]]; then
    PYTHON_BIN="$(cygpath -u "$PYTHON_BIN")"
  fi
  PYTHON_CMD=("$PYTHON_BIN")
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_CMD=(python3)
elif command -v python >/dev/null 2>&1; then
  PYTHON_CMD=(python)
elif command -v py >/dev/null 2>&1; then
  PYTHON_CMD=(py -3)
else
  echo "Python 3 is required; set PYTHON_BIN to its executable path." >&2
  exit 1
fi

"${PYTHON_CMD[@]}" "$ROOT/scripts/check_native_reader_v2_invariants.py" "$ROOT"
"${PYTHON_CMD[@]}" "$ROOT/scripts/check_native_spread_invariants.py" "$ROOT"

PROJECT="$WORK_ROOT/SupernoteRtlReader"
TEMPLATE_DOWNLOAD="$WORK_ROOT/template-download"
mkdir -p "$TEMPLATE_DOWNLOAD"
pushd "$WORK_ROOT" >/dev/null
npm pack --ignore-scripts --silent \
  --pack-destination "$TEMPLATE_DOWNLOAD" \
  "$TEMPLATE_PACKAGE@$TEMPLATE_VERSION"
popd >/dev/null
mapfile -t TEMPLATE_ARCHIVES < <(
  find "$TEMPLATE_DOWNLOAD" -maxdepth 1 -type f -name '*.tgz' -print
)
if [[ "${#TEMPLATE_ARCHIVES[@]}" -ne 1 ]]; then
  echo "Expected exactly one downloaded template archive, found ${#TEMPLATE_ARCHIVES[@]}." >&2
  exit 1
fi
"${PYTHON_CMD[@]}" "$ROOT/scripts/materialize_plugin_template.py" \
  "${TEMPLATE_ARCHIVES[0]}" "$TEMPLATE_LOCK" "$PROJECT"
pushd "$PROJECT" >/dev/null
npm ci --ignore-scripts --no-audit --no-fund
popd >/dev/null

cp "$ROOT/overlay/App.js" "$PROJECT/App.js"
cp "$ROOT/overlay/index.js" "$PROJECT/index.js"
cp "$ROOT/overlay/app.json" "$PROJECT/app.json"
cp "$ROOT/PluginConfig.json" "$PROJECT/PluginConfig.json"

# Keep the footer's visual slots tied to physical screen left/right even when
# PluginHost/Android inherits an RTL UI layout direction. The button labels and
# actions are still selected dynamically by App.js according to reader direction.
"${PYTHON_CMD[@]}" - "$PROJECT/App.js" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
old = "<View style={styles.footer}>"
new = "<View style={[styles.footer, {direction: 'ltr'}]}>"
if old not in text:
    raise SystemExit("Footer layout marker not found in App.js")
path.write_text(text.replace(old, new, 1), encoding="utf-8")
PY

# Direct native foreground rendering plus the current bitmap prefetch/cache path.
# Strict patch scripts fail CI if their expected stable source markers drift.
"${PYTHON_CMD[@]}" "$ROOT/scripts/patch_direct_view.py" "$PROJECT/App.js"
"${PYTHON_CMD[@]}" "$ROOT/scripts/install_native.py" "$PROJECT" "$ROOT"
"${PYTHON_CMD[@]}" "$ROOT/scripts/patch_transient_detach.py" "$PROJECT"
"${PYTHON_CMD[@]}" "$ROOT/scripts/patch_initial_layout.py" "$PROJECT/App.js"
"${PYTHON_CMD[@]}" "$ROOT/scripts/patch_plugin_packager.py" "$PROJECT/buildPlugin.sh"

mkdir -p "$PROJECT/assets"
cat > "$PROJECT/assets/icon.png.b64" <<'B64'
iVBORw0KGgoAAAANSUhEUgAAAGAAAABgCAYAAADimHc4AAACbklEQVR4nO2dy3LDIBAEW6n8/y+TgysHO7YEYsXsRtN3yzAt3qVia61hdHypC3B3LECMBYixADEWIMYCxFiAmO+Ih2zbdtvFRGttm/n9NrMQu3Pwr5wVcUqAg//MqIjhMcDh7zOaz5AAh9/HSE7dAhz+GL15hcyCAO64q7ptUxOgxzN6gtuzecfgX9kTcTQoTy3EHP6DmRwOBbjvn+Mov9MtwG//M2fz8F6QGAsQYwFiLECMBYixADEWIMYCxFiAGAsQYwFiLEBM2IHML+/2xitv3F1dn9AW8OlgIuLkSMGK+oQJOCpUNQmr6hMioLcwVSSsrI8HYTEWIMYCxFiAmBABlef5M0TUO6wF9BYm+0yot3xRL11oF1RdwurwYdEY8K7A2SSotlCWDcKZJSj3r5bOgjJKUG8eLp+GZpKgDh9E64AMEjKED8KFmFJClvBBvBJWSMgUPiTYilgpIVv4kEAArJGQMXxIIgCulZA1fEgkAK6RkDl8SCYAYiVkDx8SCoAYCRXCh6QCYE5ClfAhsQA4J6FS+JBcAIxJqBY+FBAAfRIqhg9FBMC+hKrhQyEB0N8dVQkfigmA43ArhQ8FBcDnkKuFDxd8H7AqhNbaU/dz1f9eXZ9wASup+Ma/UrIL+k9YgBgLEGMBYixAjAWIsQAxFiDGAsRYgBgLEGMBYixAjAWIOS1A/WlRNs7mcShg9p6su3PpBQ5uBQ9mcui+R+zoIoL/cDo1ylHwPb1H2JGkW8M5ursgjwVj9OY1NAZYQh8jOQ0Pwpawz2g+vk01iKW3qf55yI1FSO8TNvN4L0iMBYixADEWIMYCxFiAmB+dpA7CEfRVbgAAAABJRU5ErkJggg==
B64
base64 --decode "$PROJECT/assets/icon.png.b64" > "$PROJECT/assets/icon.png"
rm "$PROJECT/assets/icon.png.b64"

pushd "$PROJECT" >/dev/null
chmod +x buildPlugin.sh
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    # Preserve package-internal absolute paths passed through Windows jq.
    export MSYS2_ARG_CONV_EXCL="${MSYS2_ARG_CONV_EXCL:+$MSYS2_ARG_CONV_EXCL;}/icon.png;/app.npk"
    ;;
esac
./buildPlugin.sh
popd >/dev/null

mapfile -t PACKAGES < <(find "$PROJECT/build/outputs" -maxdepth 1 -type f -name '*.snplg' -print)
if [[ "${#PACKAGES[@]}" -ne 1 ]]; then
  echo "Expected exactly one generated .snplg, found ${#PACKAGES[@]}." >&2
  exit 1
fi
EXPECTED_BUNDLE="$PROJECT/build/generated/SupernoteRtlReader.bundle"
EXPECTED_NATIVE_APK="$PROJECT/build/generated/app.npk"
if [[ ! -f "$EXPECTED_BUNDLE" || ! -f "$EXPECTED_NATIVE_APK" ]]; then
  echo "Generated bundle/native APK provenance inputs are missing." >&2
  exit 1
fi
"${PYTHON_CMD[@]}" "$ROOT/scripts/verify_plugin_package.py" \
  "${PACKAGES[0]}" "$ROOT" "$EXPECTED_BUNDLE" "$EXPECTED_NATIVE_APK"

mkdir -p "$ROOT/out"
rm -f "$ROOT/out"/*.snplg
cp "${PACKAGES[0]}" "$ROOT/out/"
PROVENANCE_OUTPUT="$ROOT/out/build-provenance"
rm -rf "$PROVENANCE_OUTPUT"
mkdir -p "$PROVENANCE_OUTPUT"
cp "$EXPECTED_BUNDLE" "$PROVENANCE_OUTPUT/SupernoteRtlReader.bundle"
cp "$EXPECTED_NATIVE_APK" "$PROVENANCE_OUTPUT/app.npk"

echo "Built Supernote RTL Reader plugin:"
ls -lh "$ROOT/out"/*.snplg
