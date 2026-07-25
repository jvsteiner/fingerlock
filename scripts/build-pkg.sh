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

DERIVED="${DERIVED:-.build/xcode}"
APP="$DERIVED/Build/Products/Release/fingerlock.app"
OUT=".build/pkg"
STAGE="$OUT/root"

rm -rf "$OUT"
mkdir -p "$OUT" "$STAGE/Applications" "$OUT/resources"

say() { printf '\n==> %s\n' "$1"; }

# Check the credentials before spending a couple of minutes building something we
# then can't notarize.
if [ "$SKIP_NOTARIZE" != "1" ]; then
	if ! xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1; then
		cat >&2 <<EOF
No notarization credentials stored under the profile "$NOTARY_PROFILE".

Set them up once, either with an app-specific password from appleid.apple.com:

    xcrun notarytool store-credentials $NOTARY_PROFILE \\
        --apple-id <your-apple-id> --team-id X3U2KY97YV

or with an App Store Connect API key:

    xcrun notarytool store-credentials $NOTARY_PROFILE \\
        --key AuthKey_XXXX.p8 --key-id <KEY_ID> --issuer <ISSUER_ID>

Leave the password off the command line and it will prompt, which keeps it out
of your shell history.

To build an unnotarized package for local testing instead:

    make pkg VERSION=$VERSION SKIP_NOTARIZE=1
EOF
		exit 1
	fi
fi

say "Building the app"
# So the installed app reports the release version rather than whatever is pinned
# in the project file.
make app DERIVED="$DERIVED" MARKETING_VERSION="$VERSION"

say "Checking the app is signed the way the installer will claim"
codesign -v --deep --strict "$APP"

# Deliberately no pipes here. `codesign | grep -q` looks fine and is a trap: grep
# closes the pipe on its first match, codesign dies of SIGPIPE, and pipefail then
# reports the whole check as failed — so a correctly signed app looks broken.
entitlements=$(codesign -d --entitlements - "$APP" 2>/dev/null || true)
case "$entitlements" in
	*keychain-access-groups*) ;;
	*) echo "app is missing the keychain entitlement — the Enclave will not work" >&2; exit 1 ;;
esac
case "$entitlements" in
	*get-task-allow*) echo "app has get-task-allow — refusing to ship a debuggable build" >&2; exit 1 ;;
esac

# Xcode's `build` action signs with --timestamp=none, which notarization rejects.
# OTHER_CODE_SIGN_FLAGS overrides it, but that is easy to lose in a project edit and
# the failure otherwise surfaces minutes later as an Apple rejection.
for binary in "$APP" "$APP/Contents/PlugIns/FingerlockFinder.appex"; do
	sig=$(codesign -dvv "$binary" 2>&1 || true)
	case $'\n'"$sig" in
		*$'\n'Timestamp=*) ;;
		*) echo "$(basename "$binary") has no secure timestamp — notarization would reject it. Check OTHER_CODE_SIGN_FLAGS = --timestamp." >&2; exit 1 ;;
	esac
done

notarize() { # $1 = path to submit
	if [ "$SKIP_NOTARIZE" = "1" ]; then
		echo "SKIP_NOTARIZE=1 — not submitting $1"
		return 0
	fi

	# `notarytool submit --wait` exits 0 even when Apple rejects the submission,
	# so the status has to be read out of the output. Otherwise the build sails on
	# and fails later at stapling, which says nothing about what was wrong.
	local out id status
	out=$(xcrun notarytool submit "$1" --keychain-profile "$NOTARY_PROFILE" --wait 2>&1)
	echo "$out"

	status=$(printf '%s\n' "$out" | awk '/^ *status:/ {print $2; exit}')
	if [ "$status" != "Accepted" ]; then
		id=$(printf '%s\n' "$out" | awk '/^ *id:/ {print $2; exit}')
		echo "" >&2
		echo "Notarization failed (status: ${status:-unknown}). Apple's reasons:" >&2
		if [ -n "$id" ]; then
			xcrun notarytool log "$id" --keychain-profile "$NOTARY_PROFILE" >&2 || true
		fi
		return 1
	fi
}

say "Notarizing the app"
ditto -c -k --keepParent "$APP" "$OUT/fingerlock.zip"
notarize "$OUT/fingerlock.zip"
if [ "$SKIP_NOTARIZE" != "1" ]; then
	xcrun stapler staple "$APP"
fi

say "Staging"
ditto "$APP" "$STAGE/Applications/fingerlock.app"

# The CLI is not optional. Shipping it as a payload symlink rather than something
# the postinstall script conjures keeps it under pkgutil's accounting, so an
# uninstall can find it. Entitlements survive the symlink — the kernel resolves it
# and the real path is still inside the signed bundle.
mkdir -p "$STAGE/usr/local/bin"
ln -sf "/Applications/fingerlock.app/Contents/MacOS/fingerlock" "$STAGE/usr/local/bin/fingerlock"

say "Building the component package"

# pkgbuild marks app bundles relocatable by default, which means the Installer asks
# LaunchServices where com.jvs.fingerlock already lives and installs *there* instead
# of /Applications. A stray copy in a build directory is enough to hijack the
# install — it lands in the build tree, owned by root, while /usr/local/bin points
# at an /Applications that never receives anything.
pkgbuild --analyze --root "$STAGE" "$OUT/component.plist"
count=$(plutil -convert json -o - "$OUT/component.plist" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
[ "$count" -ge 1 ] || { echo "component plist came back empty — staging is wrong" >&2; exit 1; }
for i in $(seq 0 $((count - 1))); do
	plutil -replace "$i.BundleIsRelocatable" -bool NO "$OUT/component.plist"
done
plutil -convert json -o - "$OUT/component.plist" \
	| python3 -c 'import json,sys; [print("    not relocatable:", c["RootRelativeBundlePath"]) for c in json.load(sys.stdin)]'

pkgbuild \
	--root "$STAGE" \
	--component-plist "$OUT/component.plist" \
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

# Everything above works in .build alongside the intermediates. The finished
# installer belongs somewhere you can actually find it.
mkdir -p dist
cp "$OUT/fingerlock-$VERSION.pkg" "dist/fingerlock-$VERSION.pkg"

say "Done"
echo
echo "    $(pwd)/dist/fingerlock-$VERSION.pkg"
echo "    $(shasum -a 256 "dist/fingerlock-$VERSION.pkg" | awk '{print $1}')"
echo
