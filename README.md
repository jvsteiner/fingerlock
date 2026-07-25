# fingerlock

Seal a file from Finder's right-click menu. Open it with your fingerprint.

macOS has no built-in way to encrypt a single file. Disk images work but are
passphrase-based and clumsy for one document. Fingerlock adds a right-click item that
encrypts a file in place, and gives it back when the Secure Enclave sees your finger.

Early days — it works, and the file format may still change before 1.0.

## How it works

Each file gets its own random AES-256-GCM key. That key is wrapped twice:

- **To a Secure Enclave key**, created with `.biometryCurrentSet` and
  `.privateKeyUsage`. The private half is generated inside the Enclave and never
  leaves it. Using it requires a live Touch ID match — the check is enforced by the
  hardware, not by this code.
- **To an X25519 recovery key**, whose private half is encrypted under a passphrase
  you choose (PBKDF2-SHA256, 600,000 iterations) in `~/.config/fingerlock/config.json`.

Sealing only needs the Enclave's *public* key, so it's instant and asks for nothing.
Unsealing goes through the Enclave, so it prompts.

```
"FLK1"          4 bytes   magic
header length   4 bytes   big-endian uint32
header          JSON — original filename, both wrapped copies of the file key
body            AES-GCM sealed box (nonce ‖ ciphertext ‖ tag)
```

## Using it

From Finder:

- **Right-click a file** — the item is at the top level of the context menu
- **Double-click a `.fingerlock` file** — unseals it
- Both routes go through the same code as the CLI

From a shell:

```
fingerlock init                               # create the keys, choose a passphrase
fingerlock seal secrets.json                  # -> secrets.json.fingerlock
fingerlock unseal secrets.json.fingerlock     # Touch ID
fingerlock toggle <file>                      # seal or unseal, whichever applies
fingerlock recover <file>                     # passphrase instead of a fingerprint
fingerlock status
```

`--keep` leaves the input file in place instead of removing it.

## Recovery

The Enclave key is bound to one Mac and to the fingerprints currently enrolled on it.
Re-enrolling fingerprints invalidates it, and it does not survive a restore to new
hardware. That is the property that makes a sealed file useless to someone who adds
their own finger to your Mac.

`fingerlock recover` is the other way in, using the passphrase from `fingerlock init`.
Every sealed file carries a copy of its key wrapped to the recovery key, so this works
for any file regardless of what happened to the Enclave.

## Building

Requires Xcode and an Apple Developer ID certificate. You do not need to build it to
use it — releases carry a signed, notarized DMG. The source is here so you can read
it.

```
make test             # crypto round-trip; no Enclave, no signing
make install          # build, sign, install to ~/Applications
```

Signing is not optional, and not a formality. The Secure Enclave requires a
`keychain-access-groups` entitlement, and that entitlement requires a provisioning
profile to authorize it. Measured on macOS 15.7.7:

| Signing | Result |
|---|---|
| ad-hoc (`codesign -s -`) | runs; Enclave calls fail `-34018` |
| Developer ID, no entitlements | runs; Enclave calls fail `-34018` |
| Developer ID + `keychain-access-groups`, no profile | **process never reaches `main`** |
| same, wrapped in an `.app` bundle, no profile | **process never reaches `main`** |

That last state is a stuck exec rather than a crash — `ps` shows `UE`, zero bytes of
output. The kernel refuses to launch a binary claiming a restricted entitlement it
cannot validate. It is also why this is an app bundle and not a bare CLI: a plain
Mach-O has nowhere to carry `embedded.provisionprofile`.

To build it yourself you need your own App ID and a Developer ID provisioning profile
for it, then `make install PROFILE="<your profile name>"`.

## The Finder extension

`FingerlockFinder.appex` lives inside the app bundle. It is sandboxed and asks for
nothing but the sandbox: it never opens a file and never touches key material. It
reads the selected paths from Finder and opens a `fingerlock://toggle?path=…` URL,
and the main app does the work.

macOS does not auto-enable third-party Finder extensions. It appears in System
Settings → General → Login Items & Extensions → Finder Extensions, or:

```
pluginkit -e use -i com.jvs.fingerlock.FingerlockFinder      # enable
pluginkit -e ignore -i com.jvs.fingerlock.FingerlockFinder   # disable
```

A FinderSync extension only offers a menu inside directories it registers an interest
in, so this one registers every browsable mounted volume.

## Limitations

- Files are read into memory whole. Fine for documents; don't point it at a disk image.
- Folders aren't supported — compress first, seal the archive.
- Removing the plaintext is `unlink`, not erasure. On APFS the old blocks may be
  recoverable.
- Plaintext and key material are in the process's memory while sealing and unsealing.
- Release builds are signed without `get-task-allow`, so a debugger can't attach.

## Licence

MIT. See [LICENSE](LICENSE).
