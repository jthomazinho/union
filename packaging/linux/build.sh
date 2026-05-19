#!/usr/bin/env bash
# Build .deb packages for union-server, union-client and union-gui.
# Run from the repo root or from anywhere — uses git/script location for paths.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if ! command -v cargo-deb >/dev/null 2>&1; then
    echo "cargo-deb not found. Install with: cargo install cargo-deb" >&2
    exit 1
fi

echo "==> building release binaries"
cargo build --release \
    --package union-server \
    --package union-client \
    --package union-gui

OUT_DIR="$ROOT/target/debian"
mkdir -p "$OUT_DIR"

for pkg in union-server union-client union-gui; do
    echo "==> packaging $pkg"
    cargo deb --package "$pkg" --no-build --no-strip
done

echo
echo "Generated packages:"
ls -1 "$OUT_DIR"/*.deb
