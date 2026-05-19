#!/bin/sh
# Install one of the bundled LaunchAgent templates under ~/Library/LaunchAgents
# and load it.  Usage: install-launchagent.sh server | client
set -e

ROLE="${1:-}"
case "$ROLE" in
    server|client) ;;
    *) echo "usage: $0 server|client" >&2; exit 64 ;;
esac

BUNDLE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="$BUNDLE_DIR/Resources/dev.union.${ROLE}.plist"
if [ ! -f "$TEMPLATE" ]; then
    echo "Template not found: $TEMPLATE" >&2
    exit 1
fi

mkdir -p "${HOME}/Library/LaunchAgents" "${HOME}/Library/Logs/Union"
TARGET="${HOME}/Library/LaunchAgents/dev.union.${ROLE}.plist"

# Substitute __HOME__ tokens before installing.
sed "s|__HOME__|${HOME}|g" "$TEMPLATE" > "$TARGET"
chmod 644 "$TARGET"

# Reload if already loaded; ignore errors when not yet loaded.
launchctl unload "$TARGET" 2>/dev/null || true
launchctl load "$TARGET"

echo "Installed and loaded: $TARGET"
