import CryptoKit
import Foundation

// Compiled against the real Envelope.swift and Recovery.swift by
// scripts/test-crypto.sh. The Enclave blob is stood in for, since reaching the
// Secure Enclave needs a signed, provisioned build.

struct FLError: Error, CustomStringConvertible {
    let description: String
    init(_ m: String) { description = m }
}

var failures = 0
func check(_ ok: Bool, _ what: String) {
    print("\(ok ? "PASS" : "FAIL") — \(what)")
    if !ok { failures += 1 }
}

let passphrase = "correct horse battery staple"

// recovery config
let cfg = try! Recovery.create(passphrase: passphrase)
check(cfg.publicKey.count == 32, "recovery config created with a 32-byte X25519 public key")

do {
    _ = try Recovery.privateKey(from: cfg, passphrase: "wrong")
    check(false, "wrong passphrase should have thrown")
} catch {
    check(true, "wrong passphrase rejected")
}

let priv = try! Recovery.privateKey(from: cfg, passphrase: passphrase)
check(priv.publicKey.rawRepresentation == cfg.publicKey,
      "passphrase recovers the matching private key")

// full envelope round-trip
var payload = Data()
for i in 0..<300_000 { payload.append(UInt8(i % 251)) }

let fileKey = SymmetricKey(size: .bits256)
let keyBytes = fileKey.withUnsafeBytes { Data($0) }
let rec = try! Recovery.wrap(keyBytes, to: cfg.publicKey)
let header = Header(
    version: 1,
    originalName: "secrets.json",
    enclaveWrapped: Data("stand-in for the Enclave blob".utf8),
    recoveryEPK: rec.epk,
    recoveryWrapped: rec.ct
)
let body = try! Envelope.sealBody(payload, fileKey: fileKey)
let file = try! Envelope.encode(header: header, body: body)

check(file.prefix(4) == Envelope.magic, "sealed file carries the FLK1 magic")
check(file.range(of: payload.prefix(64)) == nil, "plaintext does not appear in the sealed file")

let (h2, b2) = try! Envelope.decode(file)
check(h2.originalName == "secrets.json", "original filename survives the round-trip")

let unwrapped = try! Recovery.unwrap(epk: h2.recoveryEPK, ct: h2.recoveryWrapped, with: priv)
check(unwrapped == keyBytes, "recovery path unwraps the file key")
check(try! Envelope.openBody(b2, fileKey: SymmetricKey(data: unwrapped)) == payload,
      "plaintext round-trips byte-for-byte (\(payload.count) bytes)")

// a flipped bit anywhere in the body must be fatal, not silent
var tampered = file
tampered[tampered.count - 20] ^= 0xFF
let (h3, b3) = try! Envelope.decode(tampered)
do {
    _ = try Envelope.openBody(b3, fileKey: SymmetricKey(data:
        try Recovery.unwrap(epk: h3.recoveryEPK, ct: h3.recoveryWrapped, with: priv)))
    check(false, "tampered ciphertext should not decrypt")
} catch {
    check(true, "tampered ciphertext rejected by AES-GCM")
}

// truncation and junk must be rejected by name, not by crash
do {
    _ = try Envelope.decode(Data("not a sealed file at all".utf8))
    check(false, "junk should not decode")
} catch {
    check(true, "junk input rejected")
}
do {
    _ = try Envelope.decode(file.prefix(20))
    check(false, "truncated file should not decode")
} catch {
    check(true, "truncated file rejected")
}

// two seals of the same key must not share a wrap key
let a = try! Recovery.wrap(keyBytes, to: cfg.publicKey)
let b = try! Recovery.wrap(keyBytes, to: cfg.publicKey)
check(a.ct != b.ct && a.epk != b.epk, "each seal uses a fresh ephemeral key")

print(failures == 0 ? "\nall checks passed" : "\n\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
