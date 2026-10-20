#!/usr/bin/env bash
# Builds a universal (Apple Silicon + Intel) TwoFA.app into ./build.
# Pass --install to copy it into /Applications and launch it.
# Set VERSION=1.2.3 to stamp the version into Info.plist (the release workflow does this).
set -euo pipefail

cd "$(dirname "$0")"
APP="build/TwoFA.app"

for arch in arm64 x86_64; do
    swift build -c release --arch "$arch"
done

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
lipo -create -output "$APP/Contents/MacOS/TwoFA" \
    .build/arm64-apple-macosx/release/TwoFA \
    .build/x86_64-apple-macosx/release/TwoFA
cp Resources/Info.plist "$APP/Contents/Info.plist"
cp Resources/AppIcon.icns "$APP/Contents/Resources/AppIcon.icns"
if [[ -n "${VERSION:-}" ]]; then
    /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$APP/Contents/Info.plist"
    /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $VERSION" "$APP/Contents/Info.plist"
fi
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
