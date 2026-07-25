#!/bin/bash
# Exercises the envelope and recovery layers with no Secure Enclave and no
# signing, so it runs anywhere and stays fast.
set -euo pipefail
cd "$(dirname "$0")/.."

OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

swiftc -O \
	Tests/crypto-roundtrip/main.swift \
	Sources/fingerlock/Envelope.swift \
	Sources/fingerlock/Recovery.swift \
	-o "$OUT/roundtrip"

FINGERLOCK_CONFIG="$OUT/config.json" "$OUT/roundtrip"
