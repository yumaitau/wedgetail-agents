#!/bin/bash
# Build the macOS installer package.
#
#   packaging/macos/build-pkg.sh <version> <binary> [<binary> ...] <output.pkg>
#
# With two binaries (aarch64 and x86_64) a universal binary is made with lipo.
#
# Signing and notarisation run only when their secrets are set (none are required for an
# unsigned CI build):
#   APPLE_APP_IDENTITY        "Developer ID Application: ..." identity in the keychain
#   APPLE_INSTALLER_IDENTITY  "Developer ID Installer: ..." identity in the keychain
#   APPLE_NOTARY_APPLE_ID, APPLE_NOTARY_TEAM_ID, APPLE_NOTARY_PASSWORD
#                             notarytool credentials (app-specific password)
set -euo pipefail

if [ "$#" -lt 3 ]; then
    echo "usage: $0 <version> <binary> [<binary>...] <output.pkg>" >&2
    exit 2
fi
VERSION=$1
shift
OUTPUT=${*: -1}
BINARIES=("${@:1:$#-1}")
IDENTIFIER=au.com.yumait.wedgetail-agent
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

ROOT="$WORK/root"
install -d "$ROOT/usr/local/bin" "$ROOT/Library/LaunchDaemons" "$ROOT/Library/Application Support/Wedgetail"
if [ "${#BINARIES[@]}" -gt 1 ]; then
    lipo -create -output "$ROOT/usr/local/bin/wedgetail-agent" "${BINARIES[@]}"
else
    cp "${BINARIES[0]}" "$ROOT/usr/local/bin/wedgetail-agent"
fi
chmod 755 "$ROOT/usr/local/bin/wedgetail-agent"
install -m 644 "$HERE/$IDENTIFIER.plist" "$ROOT/Library/LaunchDaemons/$IDENTIFIER.plist"
install -m 644 "$HERE/../common/agent.toml" "$ROOT/Library/Application Support/Wedgetail/agent.toml.example"

if [ -n "${APPLE_APP_IDENTITY:-}" ]; then
    # A fixed signing identifier keeps the code requirement in MDM PPPC profiles stable
    # (wedgetail-agent-pppc.mobileconfig).
    codesign --force --options runtime --timestamp --identifier "$IDENTIFIER" \
        --sign "$APPLE_APP_IDENTITY" "$ROOT/usr/local/bin/wedgetail-agent"
else
    echo "APPLE_APP_IDENTITY not set: binary is not signed"
fi

# No extended attributes or AppleDouble files in the payload.
export COPYFILE_DISABLE=1
xattr -cr "$ROOT" 2>/dev/null || true

pkgbuild --root "$ROOT" --scripts "$HERE/scripts" --identifier "$IDENTIFIER" --version "$VERSION" \
    --install-location / --ownership recommended "$WORK/component.pkg"

SIGN_ARGS=()
if [ -n "${APPLE_INSTALLER_IDENTITY:-}" ]; then
    SIGN_ARGS=(--sign "$APPLE_INSTALLER_IDENTITY" --timestamp)
else
    echo "APPLE_INSTALLER_IDENTITY not set: package is not signed"
fi
productbuild --identifier "$IDENTIFIER" --version "$VERSION" --package "$WORK/component.pkg" \
    ${SIGN_ARGS[@]+"${SIGN_ARGS[@]}"} "$OUTPUT"

if [ -n "${APPLE_NOTARY_APPLE_ID:-}" ] && [ -n "${APPLE_INSTALLER_IDENTITY:-}" ]; then
    xcrun notarytool submit "$OUTPUT" --apple-id "$APPLE_NOTARY_APPLE_ID" \
        --team-id "$APPLE_NOTARY_TEAM_ID" --password "$APPLE_NOTARY_PASSWORD" --wait
    xcrun stapler staple "$OUTPUT"
else
    echo "notarisation skipped (needs APPLE_NOTARY_* and a signed package)"
fi
echo "built $OUTPUT"
