#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_ROOT="$(mktemp -d)"
trap 'rm -rf "$WORK_ROOT"' EXIT

pushd "$WORK_ROOT" >/dev/null
npx --yes @react-native-community/cli@18.0.0 init SupernoteRtlReader \
  --template @supernote-plugin/sn-plugin-template \
  --version 0.79.2
popd >/dev/null

PROJECT="$WORK_ROOT/SupernoteRtlReader"
cp "$ROOT/overlay/App.js" "$PROJECT/App.js"
cp "$ROOT/overlay/index.js" "$PROJECT/index.js"
cp "$ROOT/overlay/app.json" "$PROJECT/app.json"
cp "$ROOT/PluginConfig.json" "$PROJECT/PluginConfig.json"

# Keep the footer's visual slots tied to physical screen left/right even when
# PluginHost/Android inherits an RTL UI layout direction. The button labels and
# actions are still selected dynamically by App.js according to reader direction.
python3 - "$PROJECT/App.js" <<'PY'
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
python3 "$ROOT/scripts/patch_direct_view.py" "$PROJECT/App.js"
python3 "$ROOT/scripts/install_native.py" "$PROJECT" "$ROOT"
python3 "$ROOT/scripts/patch_transient_detach.py" "$PROJECT"
python3 "$ROOT/scripts/patch_initial_layout.py" "$PROJECT/App.js"

mkdir -p "$PROJECT/assets"
cat > "$PROJECT/assets/icon.png.b64" <<'B64'
iVBORw0KGgoAAAANSUhEUgAAAGAAAABgCAYAAADimHc4AAACbklEQVR4nO2dy3LDIBAEW6n8/y+TgysHO7YEYsXsRtN3yzAt3qVia61hdHypC3B3LECMBYixADEWIMYCxFiAmO+Ih2zbdtvFRGttm/n9NrMQu3Pwr5wVcUqAg//MqIjhMcDh7zOaz5AAh9/HSE7dAhz+GL15hcyCAO64q7ptUxOgxzN6gtuzecfgX9kTcTQoTy3EHP6DmRwOBbjvn+Mov9MtwG//M2fz8F6QGAsQYwFiLECMBYixADEWIMYCxFiAGAsQYwFiLEBM2IHML+/2xitv3F1dn9AW8OlgIuLkSMGK+oQJOCpUNQmr6hMioLcwVSSsrI8HYTEWIMYCxFiAmBABlef5M0TUO6wF9BYm+0yot3xRL11oF1RdwurwYdEY8K7A2SSotlCWDcKZJSj3r5bOgjJKUG8eLp+GZpKgDh9E64AMEjKED8KFmFJClvBBvBJWSMgUPiTYilgpIVv4kEAArJGQMXxIIgCulZA1fEgkAK6RkDl8SCYAYiVkDx8SCoAYCRXCh6QCYE5ClfAhsQA4J6FS+JBcAIxJqBY+FBAAfRIqhg9FBMC+hKrhQyEB0N8dVQkfigmA43ArhQ8FBcDnkKuFDxd8H7AqhNbaU/dz1f9eXZ9wASup+Ma/UrIL+k9YgBgLEGMBYixAjAWIsQAxFiDGAsRYgBgLEGMBYixAjAWIOS1A/WlRNs7mcShg9p6su3PpBQ5uBQ9mcui+R+zoIoL/cDo1ylHwPb1H2JGkW8M5ursgjwVj9OY1NAZYQh8jOQ0Pwpawz2g+vk01iKW3qf55yI1FSO8TNvN4L0iMBYixADEWIMYCxFiAmB+dpA7CEfRVbgAAAABJRU5ErkJggg==
B64
base64 --decode "$PROJECT/assets/icon.png.b64" > "$PROJECT/assets/icon.png"
rm "$PROJECT/assets/icon.png.b64"

pushd "$PROJECT" >/dev/null
chmod +x buildPlugin.sh
./buildPlugin.sh
popd >/dev/null

mkdir -p "$ROOT/out"
rm -f "$ROOT/out"/*.snplg
cp "$PROJECT"/build/outputs/*.snplg "$ROOT/out/"

echo "Built Supernote RTL Reader plugin:"
ls -lh "$ROOT/out"/*.snplg
