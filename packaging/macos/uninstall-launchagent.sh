#!/bin/sh
set -e
ROLE="${1:-}"
case "$ROLE" in
    server|client) ;;
    *) echo "usage: $0 server|client" >&2; exit 64 ;;
esac

TARGET="${HOME}/Library/LaunchAgents/dev.union.${ROLE}.plist"
if [ -f "$TARGET" ]; then
    launchctl unload "$TARGET" 2>/dev/null || true
    rm -f "$TARGET"
    echo "Removed: $TARGET"
else
    echo "Not installed: $TARGET"
fi
