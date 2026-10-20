#!/usr/bin/env bash
# Builds TwoFA.app into ./build. Pass --install to copy it into /Applications and launch it.
set -euo pipefail

cd "$(dirname "$0")"
APP="build/TwoFA.app"

swift build -c release --arch arm64

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$(swift build -c release --arch arm64 --show-bin-path)/TwoFA" "$APP/Contents/MacOS/TwoFA"
cp Resources/Info.plist "$APP/Contents/Info.plist"
cp Resources/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
codesign --force --sign - "$APP"

(cd build && rm -f TwoFA.zip && ditto -c -k --keepParent TwoFA.app TwoFA.zip)
echo "Built $APP and build/TwoFA.zip"

if [[ "${1:-}" == "--install" ]]; then
    pkill -x TwoFA || true
    rm -rf /Applications/TwoFA.app
    cp -R "$APP" /Applications/
    open /Applications/TwoFA.app
    echo "Installed to /Applications/TwoFA.app"
fi
