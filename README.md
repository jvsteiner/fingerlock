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
"FLK2"          4 bytes   magic
header length   4 bytes   big-endian uint32
header          JSON — original name, folder flag, both wrapped copies of the key
chunks          repeated: [4-byte BE length][AES-GCM ciphertext ‖ tag]
```

The body is chunked, so neither sealing nor unsealing holds more than one chunk in
memory — an 800 MB file peaks around 13 MB.

Chunking an AEAD needs care: a per-chunk tag proves each chunk is intact but says
nothing about its position or whether any are missing. Every chunk therefore
authenticates, as additional data, a SHA-256 of the header, its own index, and
whether it is the last chunk. Reordering, duplication, truncation and edits to the
filename all fail to open rather than producing something plausible. Nonces are a
counter rather than random, which is safe because the file key is fresh per file.

Files written by v0.1.0 (`FLK1`) still open.

## Folders

Folders are archived with `ditto -c -k --sequesterRsrc --keepParent` before sealing
and expanded after, so resource forks, extended attributes, permissions and symlinks
survive the round trip. The header records that the payload was a folder; unsealing
puts it back where it was.

## Installing

Download the `.pkg` from [Releases](https://github.com/jvsteiner/fingerlock/releases).
It installs the app to `/Applications`, puts `fingerlock` on your `PATH` at
`/usr/local/bin`, turns on the Finder extension, and opens setup so you can choose a
recovery passphrase. Signed and notarized.

`fingerlock init` does the same setup from a terminal if you'd rather.

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
fingerlock reseal <file>                      # re-wrap to this Mac — see Moving below
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

## Moving to a new Mac

**The Secure Enclave key cannot be moved.** It is generated inside the Enclave and
the private half never leaves the chip — there is no export, and adding one would
defeat the point. A new Mac always means a new key, and files sealed on the old one
cannot be opened with a fingerprint on the new one.

**The recovery key is the migration path.** `~/.config/fingerlock/config.json` holds
your X25519 public key plus the private half wrapped under a passphrase. That file
and the passphrase together open any sealed file on any Mac.

So: **back up `config.json`.** Without it, sealed files die with the machine. It is
useless to anyone who doesn't know the passphrase, so keeping a copy alongside the
passphrase in your password manager is reasonable.

### The move

```
# 1. Install fingerlock on the new Mac, but don't run setup yet.

# 2. Copy the recovery key across first.
mkdir -p ~/.config/fingerlock
cp /wherever/config.json ~/.config/fingerlock/config.json

# 3. Setup finds it, asks for its passphrase to confirm, and creates a Secure
#    Enclave key for this Mac. Your existing recovery key is left alone.
fingerlock init

# 4. Bring your sealed files over, then re-wrap them to this Mac's Enclave key.
fingerlock reseal *.fingerlock
```

`reseal` asks for the recovery passphrase, then decrypts and re-encrypts a chunk at
a time straight from the old file to the new one. The plaintext is never written to
disk — which matters, because step 4 is the moment everything you own would
otherwise be sitting in a folder in the clear.

If you skip step 4, `fingerlock recover` still opens individual files with the
passphrase. You just won't get Touch ID until they've been resealed.

### Order matters

Copy `config.json` **before** first running setup. If you set up first, you get a
fresh recovery key, and files sealed on the old Mac won't match it. Nothing is lost —
drop the old `config.json` in, run `fingerlock reseal`, and everything sealed with
the old key comes back.

## Building

Requires Xcode and an Apple Developer ID certificate. You do not need to build it to
use it — the releases carry a signed, notarized installer. The source is here so you
can read it.

```
make test                    # crypto round-trip; no Enclave, no signing
make install                 # build, sign, install to ~/Applications
make pkg VERSION=0.1.0       # signed, notarized installer
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

- Removing the plaintext is `unlink`, not erasure. On APFS the old blocks may be
  recoverable.
- Plaintext and key material are in the process's memory while sealing and unsealing.
- Release builds are signed without `get-task-allow`, so a debugger can't attach.

## Licence

MIT. See [LICENSE](LICENSE).
