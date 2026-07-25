# fingerlock

Seal a file from Finder's right-click menu; open it with a fingerprint.

The file key is random per file and wrapped twice — once by a Secure Enclave key
that only a live Touch ID match can use, once by a recovery key you hold a
passphrase for. Sealing needs no fingerprint (it's a public-key operation, so it's
instant and silent). Unsealing does.

## Status

Built, signed, installed, and launching. Run `fingerlock init` to create your keys.

| Piece | State |
|---|---|
| Envelope format, AES-GCM, tamper detection | done — `make test`, 12/12 |
| Recovery key + passphrase escrow | done — covered by the same tests |
| CLI | done |
| Finder Quick Action | done — registers and runs |
| Signing, profile, entitlements | done — see [Signing](#signing) |
| Double-click a sealed file to unseal | done |
| Top-level Finder menu item (FinderSync) | built, enabled, loads — menu click not yet exercised |
| Touch ID seal/unseal from the CLI | working |

## Signing

A bare, ad-hoc-signed binary cannot use the Secure Enclave or a biometry-gated
keychain item — it fails with `-34018`. Reaching them needs a `keychain-access-groups`
entitlement, and that entitlement needs a provisioning profile to authorize it.
Measured on macOS 15.7.7:

| Signing | Result |
|---|---|
| ad-hoc (`codesign -s -`) | runs; Enclave calls fail `-34018` |
| Developer ID, no entitlements | runs; Enclave calls fail `-34018` |
| Developer ID + `keychain-access-groups`, no profile | **process never reaches `main`** |
| same, wrapped in an `.app` bundle, no profile | **process never reaches `main`** |

That last state is a stuck exec, not a crash — `ps` shows `UE` with zero bytes of
output. The kernel refuses to launch a binary claiming a restricted entitlement it
cannot validate. This is also why the project builds an `.app` and not a bare CLI:
a plain Mach-O has nowhere to carry `embedded.provisionprofile`.

### The one-time setup

At [developer.apple.com/account](https://developer.apple.com/account):

1. **Identifiers → + → App IDs → App**, platform **macOS**
   - Description: `Fingerlock`
   - Bundle ID, explicit: `com.jvs.fingerlock`
   - Tick nothing under Capabilities. There is no Keychain Sharing capability on
     the portal and you don't need one: every App ID carries keychain access
     already, and `keychain-access-groups` is authorized by the App ID prefix in
     the profile. Xcode's "Keychain Sharing" checkbox only edits a local
     entitlements file — which this repo already has.
2. **Profiles → + → Developer ID** (under Distribution)
   - App ID: the `Fingerlock` one
   - Certificate: `Developer ID Application: Jamie Steiner (X3U2KY97YV)`
   - Name it **`FingerlockProfile`** — the project looks it up by name, so a
     different name means passing `PROFILE="…"` to make
3. Download and double-click to install.

Then:

```
make install          # build the app, sign it, put a cli shim on PATH
make quick-actions    # add the Finder right-click item
fingerlock init       # create the Enclave key, choose a recovery passphrase
```

If you name the profile something else, pass it through: `make install PROFILE="…"`.

## Use

```
fingerlock seal secrets.json                  # -> secrets.json.fingerlock
fingerlock unseal secrets.json.fingerlock     # Touch ID
fingerlock toggle <file>                      # what the Finder item calls
fingerlock recover <file>                     # passphrase instead of a fingerprint
fingerlock status
```

`--keep` leaves the input file in place instead of removing it.

## From Finder

Three ways in, all ending at the same place:

- **Right-click a file** → the item sits at the top level of the menu, next to
  *Compress*. That's the `FingerlockFinder` extension inside the app bundle.
- **Double-click a `.fingerlock` file** → unseals it.
- **Right-click → Quick Actions → Fingerlock** → the older Automator route, still
  installed by `make quick-actions`. Redundant now; remove it with
  `rm -rf ~/Library/Services/Fingerlock.workflow` if you'd rather not have both.

The extension is sandboxed and cannot reach the Secure Enclave, so it does nothing
but collect the selected paths and open a `fingerlock://toggle?path=…` URL. The main
app does the work. That means the sandboxed process never touches key material.

It's enabled with `pluginkit -e use -i com.jvs.fingerlock.FingerlockFinder`, and
appears in System Settings → General → Login Items & Extensions → Finder Extensions.
`pluginkit -e ignore -i com.jvs.fingerlock.FingerlockFinder` turns it off.

A FinderSync extension only offers a menu inside directories it registers an
interest in, so this one registers every browsable mounted volume. That is the
price of having the item appear everywhere.

## File format

```
"FLK1"          4 bytes   magic
header length   4 bytes   big-endian uint32
header          JSON — original filename, both wrapped copies of the file key
body            AES-GCM sealed box (nonce ‖ ciphertext ‖ tag)
```

Whole files are read into memory. Fine for documents and exports; don't point it
at a disk image.

## The recovery key matters

`.biometryCurrentSet` means the Enclave key dies the moment fingerprints are added
or removed on this Mac. The key is also bound to this machine — a Time Machine
restore to new hardware brings back the ciphertext and not the key.

`fingerlock init` therefore makes an X25519 recovery keypair and wraps the private
half under a passphrase (PBKDF2-SHA256, 600k iterations) in
`~/.config/fingerlock/config.json`. Every sealed file carries a copy of its file key
wrapped to that recovery key, so `fingerlock recover` always works.

Put the passphrase in your password manager. Without it, a re-enrolled fingerprint
is unrecoverable data loss.

## Development

```
make test    # envelope + recovery crypto; no Enclave, no signing, fast
```

`FINGERLOCK_CONFIG` overrides the config path, which is how the tests stay out of
your real `~/.config`.

## Not claimed

- Deleting the plaintext is `unlink`, not erasure. On APFS the old blocks may be
  recoverable.
- The plaintext is in this process's memory while sealing and unsealing.
- Folders aren't supported. Compress first, seal the archive.
