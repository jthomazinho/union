#!/bin/sh
# CFBundleExecutable wrapper for Union.app.
# Seeds the per-user config directory on first launch, then execs union-gui.
set -e

BUNDLE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
RES="$BUNDLE_DIR/Resources"
MACOS="$BUNDLE_DIR/MacOS"

SUPPORT="${HOME}/Library/Application Support/Union"
mkdir -p "$SUPPORT"

if [ ! -f "$SUPPORT/server.toml" ] && [ -f "$RES/server.toml.example" ]; then
    cp "$RES/server.toml.example" "$SUPPORT/server.toml"
    chmod 600 "$SUPPORT/server.toml"
fi

if [ ! -f "$SUPPORT/client.toml" ] && [ -f "$RES/client.toml.example" ]; then
    cp "$RES/client.toml.example" "$SUPPORT/client.toml"
    chmod 600 "$SUPPORT/client.toml"
fi

# Expose the bundled daemons via PATH so the GUI can spawn them by name.
export PATH="$MACOS:$PATH"
export UNION_CONFIG_DIR="$SUPPORT"

exec "$MACOS/union-gui" "$@"
