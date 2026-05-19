#!/usr/bin/env bash
# Build Union.app and Union-<version>.dmg on macOS.
# Honours optional environment variables:
#   CODESIGN_IDENTITY  - Developer ID Application identity; if unset, the bundle is left unsigned
#   NOTARIZE_PROFILE   - notarytool keychain profile name; if unset, no notarisation
#   TARGET             - cargo target triple; default = host
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

VERSION="$(awk -F\" '/^version[[:space:]]*=/ {print $2; exit}' Cargo.toml)"
if [[ -z "$VERSION" ]]; then
    echo "Could not read version from workspace Cargo.toml" >&2
    exit 1
fi

TARGET_FLAG=()
if [[ -n "${TARGET:-}" ]]; then
    TARGET_FLAG=(--target "$TARGET")
    BIN_DIR="$ROOT/target/$TARGET/release"
else
    BIN_DIR="$ROOT/target/release"
fi

echo "==> building release binaries (version $VERSION)"
cargo build --release "${TARGET_FLAG[@]}" \
    --package union-server \
    --package union-client \
    --package union-gui

STAGE="$ROOT/target/macos-stage"
APP="$STAGE/Union.app"
rm -rf "$STAGE"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

echo "==> assembling Union.app"
cp "$BIN_DIR/union-gui"    "$APP/Contents/MacOS/union-gui"
cp "$BIN_DIR/union-server" "$APP/Contents/MacOS/union-server"
cp "$BIN_DIR/union-client" "$APP/Contents/MacOS/union-client"
install -m 755 "$ROOT/packaging/macos/launcher.sh" "$APP/Contents/MacOS/union"
chmod +x "$APP/Contents/MacOS/"*

cp "$ROOT/examples/server.toml"                       "$APP/Contents/Resources/server.toml.example"
cp "$ROOT/examples/client.toml"                       "$APP/Contents/Resources/client.toml.example"
cp "$ROOT/README.md"                                  "$APP/Contents/Resources/README.md"
cp "$ROOT/LICENSE"                                    "$APP/Contents/Resources/LICENSE"
cp "$ROOT/packaging/macos/dev.union.server.plist"     "$APP/Contents/Resources/dev.union.server.plist"
cp "$ROOT/packaging/macos/dev.union.client.plist"     "$APP/Contents/Resources/dev.union.client.plist"
install -m 755 "$ROOT/packaging/macos/install-launchagent.sh"   "$APP/Contents/Resources/install-launchagent.sh"
install -m 755 "$ROOT/packaging/macos/uninstall-launchagent.sh" "$APP/Contents/Resources/uninstall-launchagent.sh"

echo "==> generating icon set"
ICONSET="$STAGE/union.iconset"
mkdir -p "$ICONSET"
SRC_PNG="$ROOT/packaging/macos/icon-1024.png"
for size in 16 32 64 128 256 512 1024; do
    sips -z "$size" "$size" "$SRC_PNG" --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
done
# Retina variants: name "@2x" of the smaller size.
cp "$ICONSET/icon_32x32.png"    "$ICONSET/icon_16x16@2x.png"
cp "$ICONSET/icon_64x64.png"    "$ICONSET/icon_32x32@2x.png"
cp "$ICONSET/icon_256x256.png"  "$ICONSET/icon_128x128@2x.png"
cp "$ICONSET/icon_512x512.png"  "$ICONSET/icon_256x256@2x.png"
cp "$ICONSET/icon_1024x1024.png" "$ICONSET/icon_512x512@2x.png"
rm "$ICONSET/icon_64x64.png" "$ICONSET/icon_1024x1024.png"
iconutil -c icns -o "$APP/Contents/Resources/union.icns" "$ICONSET"

sed "s/__VERSION__/$VERSION/g" \
    "$ROOT/packaging/macos/Info.plist" > "$APP/Contents/Info.plist"

if [[ -n "${CODESIGN_IDENTITY:-}" ]]; then
    echo "==> codesigning with identity: $CODESIGN_IDENTITY"
    for bin in union union-gui union-server union-client; do
        codesign --force --options runtime --timestamp \
            --sign "$CODESIGN_IDENTITY" "$APP/Contents/MacOS/$bin"
    done
    codesign --force --options runtime --timestamp \
        --sign "$CODESIGN_IDENTITY" "$APP"
    codesign --verify --deep --strict --verbose=2 "$APP"
else
    echo "==> CODESIGN_IDENTITY unset — leaving bundle unsigned (Gatekeeper will warn)"
fi

DMG="$ROOT/target/Union-$VERSION.dmg"
rm -f "$DMG"
echo "==> creating $DMG"
hdiutil create \
    -volname "Union $VERSION" \
    -srcfolder "$APP" \
    -ov -format UDZO "$DMG"

if [[ -n "${CODESIGN_IDENTITY:-}" ]]; then
    codesign --force --sign "$CODESIGN_IDENTITY" --timestamp "$DMG"
fi

if [[ -n "${NOTARIZE_PROFILE:-}" ]]; then
    echo "==> submitting to notarytool (profile: $NOTARIZE_PROFILE)"
    xcrun notarytool submit "$DMG" --keychain-profile "$NOTARIZE_PROFILE" --wait
    xcrun stapler staple "$DMG"
fi

echo
echo "Generated: $DMG"
