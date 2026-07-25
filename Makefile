# fingerlock is built as an app bundle, not a bare CLI, because the Secure Enclave
# needs a `keychain-access-groups` entitlement and that entitlement needs a
# provisioning profile to authorize it. A bare Mach-O has nowhere to carry one —
# a binary that claims the entitlement without a profile does not even reach main().
# See README, "Signing".

TEAM     ?= X3U2KY97YV
PROFILE  ?= FingerlockProfile
APPS     ?= $(HOME)/Applications
PREFIX   ?= $(HOME)/.local/bin

DERIVED ?= .build/xcode
APP      = $(DERIVED)/Build/Products/Release/fingerlock.app

.PHONY: all app install quick-actions check-profile test uninstall clean

all: app

check-profile:
	@ls "$(HOME)/Library/Developer/Xcode/UserData/Provisioning Profiles/"*.provisionprofile \
		>/dev/null 2>&1 || { \
		echo "No macOS provisioning profile installed."; \
		echo "See README, 'Signing' — you need one for com.jvs.fingerlock with Keychain Sharing."; \
		exit 1; }

app: check-profile
	xcodebuild -project fingerlock.xcodeproj -scheme fingerlock \
		-configuration Release -derivedDataPath $(DERIVED) build
	@codesign -d --entitlements - $(APP) 2>/dev/null | grep -q keychain-access-groups \
		&& echo "built and signed: $(APP)" \
		|| (echo "entitlements did not stick" && exit 1)

install: app
	@mkdir -p $(APPS) $(PREFIX)
	rm -rf "$(APPS)/fingerlock.app"
	cp -R $(APP) "$(APPS)/fingerlock.app"
	ln -sf "$(APPS)/fingerlock.app/Contents/MacOS/fingerlock" $(PREFIX)/fingerlock
	@echo "installed: $(APPS)/fingerlock.app  (cli: $(PREFIX)/fingerlock)"

quick-actions: install
	FINGERLOCK=$(PREFIX)/fingerlock ./scripts/install-quick-actions.sh

# Crypto round-trip, no Enclave and no signing involved. Fast inner loop.
test:
	swift build
	./scripts/test-crypto.sh

# Signed, notarized installer. VERSION is required; see scripts/build-pkg.sh for
# the one-time notarytool credential setup.
#   make pkg VERSION=0.1.0
#   make pkg VERSION=0.1.0 SKIP_NOTARIZE=1   # local check, no Apple round-trip
pkg:
	@test -n "$(VERSION)" || { echo "usage: make pkg VERSION=0.1.0"; exit 1; }
	SKIP_NOTARIZE=$(SKIP_NOTARIZE) DERIVED=$(DERIVED) ./scripts/build-pkg.sh $(VERSION)

uninstall:
	rm -f $(PREFIX)/fingerlock
	rm -rf "$(APPS)/fingerlock.app"
	rm -rf "$(HOME)/Library/Services/Fingerlock.workflow"

clean:
	rm -rf .build
