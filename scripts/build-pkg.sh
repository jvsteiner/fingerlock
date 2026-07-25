#!/bin/bash
# Build a signed, notarized installer.
#
#   scripts/build-pkg.sh 0.1.0
#
# The app is notarized and stapled first, then packaged, then the package is
# notarized and stapled too. Stapling the app matters: a ticket on the installer
# alone leaves the installed app depending on a network check at launch.
#
# Needs notarization credentials in the keychain. One-time setup, by you, so the
# secret never passes through a script:
#
#   xcrun notarytool store-credentials fingerlock-notary \
#       --key AuthKey_XXXX.p8 --key-id <KEY_ID> --issuer <ISSUER_ID>
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
	echo "usage: $0 <version>   e.g. $0 0.1.0" >&2
	exit 1
fi

APP_IDENTITY="${APP_IDENTITY:-Developer ID Application: Jamie Steiner (X3U2KY97YV)}"
INSTALLER_IDENTITY="${INSTALLER_IDENTITY:-Developer ID Installer: Jamie Steiner (X3U2KY97YV)}"
NOTARY_PROFILE="${NOTARY_PROFILE:-fingerlock-notary}"
SKIP_NOTARIZE="${SKIP_NOTARIZE:-0}"

APP=".build/xcode/Build/Products/Release/fingerlock.app"
OUT=".build/pkg"
STAGE="$OUT/root"

rm -rf "$OUT"
mkdir -p "$OUT" "$STAGE/Applications" "$OUT/resources"

say() { printf '\n==> %s\n' "$1"; }

say "Building the app"
make app

say "Checking the app is signed the way the installer will claim"
codesign -v --deep --strict "$APP"
codesign -d --entitlements - "$APP" 2>/dev/null | grep -q keychain-access-groups \
	|| { echo "app is missing the keychain entitlement — the Enclave will not work" >&2; exit 1; }
codesign -d --entitlements - "$APP" 2>/dev/null | grep -q get-task-allow \
	&& { echo "app has get-task-allow — refusing to ship a debuggable build" >&2; exit 1; }

notarize() { # $1 = path to submit
	if [ "$SKIP_NOTARIZE" = "1" ]; then
		echo "SKIP_NOTARIZE=1 — not submitting $1"
		return 0
	fi
	xcrun notarytool submit "$1" --keychain-profile "$NOTARY_PROFILE" --wait
}

say "Notarizing the app"
ditto -c -k --keepParent "$APP" "$OUT/fingerlock.zip"
notarize "$OUT/fingerlock.zip"
if [ "$SKIP_NOTARIZE" != "1" ]; then
	xcrun stapler staple "$APP"
fi

say "Staging"
ditto "$APP" "$STAGE/Applications/fingerlock.app"

say "Building the component package"
pkgbuild \
	--root "$STAGE" \
	--identifier com.jvs.fingerlock \
	--version "$VERSION" \
	--scripts packaging/scripts \
	--install-location / \
	"$OUT/fingerlock-component.pkg"

say "Building the installer"
cp LICENSE "$OUT/resources/LICENSE.txt"
{
	echo "<html><body style=\"font-family:-apple-system;font-size:13px\">"
	echo "<p>Fingerlock installs to /Applications and turns on its Finder extension"
	echo "for the current user.</p>"
	echo "<p>After installing, open Terminal and run <code>fingerlock init</code> to"
	echo "create your keys and choose a recovery passphrase.</p>"
	echo "</body></html>"
} > "$OUT/resources/README.html"

productbuild \
	--distribution packaging/Distribution.xml \
	--package-path "$OUT" \
	--resources "$OUT/resources" \
	--version "$VERSION" \
	"$OUT/fingerlock-$VERSION-unsigned.pkg"

say "Signing the installer"
productsign \
	--sign "$INSTALLER_IDENTITY" \
	"$OUT/fingerlock-$VERSION-unsigned.pkg" \
	"$OUT/fingerlock-$VERSION.pkg"

say "Notarizing the installer"
notarize "$OUT/fingerlock-$VERSION.pkg"
if [ "$SKIP_NOTARIZE" != "1" ]; then
	xcrun stapler staple "$OUT/fingerlock-$VERSION.pkg"
	say "Gatekeeper verdict"
	spctl -a -vvv -t install "$OUT/fingerlock-$VERSION.pkg" 2>&1 | sed 's/^/    /'
fi

say "Done"
shasum -a 256 "$OUT/fingerlock-$VERSION.pkg"
