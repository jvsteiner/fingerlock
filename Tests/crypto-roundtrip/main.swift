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
let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
    .appendingPathComponent("fl-tests-\(getpid())", isDirectory: true)
try! FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: tmp) }

func path(_ name: String) -> URL { tmp.appendingPathComponent(name) }

// MARK: - recovery

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

// MARK: - sealing helpers

/// Small chunks so the multi-chunk paths are exercised without large test data.
let chunk = 64 * 1024

func makeHeader(_ name: String, directory: Bool = false) -> (Header, SymmetricKey) {
    let fileKey = SymmetricKey(size: .bits256)
    let keyBytes = fileKey.withUnsafeBytes { Data($0) }
    let rec = try! Recovery.wrap(keyBytes, to: cfg.publicKey)
    let header = Header(
        version: 2,
        originalName: name,
        isDirectory: directory,
        chunkSize: chunk,
        enclaveWrapped: Data("stand-in for the Enclave blob".utf8),
        recoveryEPK: rec.epk,
        recoveryWrapped: rec.ct
    )
    return (header, fileKey)
}

func sealed(_ payload: Data, name: String = "secrets.json") -> (URL, SymmetricKey) {
    let input = path("in-\(UUID().uuidString)")
    try! payload.write(to: input)
    let output = path("out-\(UUID().uuidString).fingerlock")
    let (header, key) = makeHeader(name)
    try! Envelope.seal(input: input, output: output, header: header, fileKey: key)
    return (output, key)
}

func opened(_ url: URL, _ key: SymmetricKey) throws -> Data {
    let out = path("plain-\(UUID().uuidString)")
    _ = try Envelope.open(input: url, output: out) { _ in key }
    return try Data(contentsOf: out)
}

// MARK: - round trips

var multi = Data()
for i in 0..<300_000 { multi.append(UInt8(i % 251)) }

let (file, key) = sealed(multi)
check(try! Data(contentsOf: file).prefix(4) == Envelope.magicV2, "sealed file carries the FLK2 magic")
check(try! Data(contentsOf: file).range(of: multi.prefix(64)) == nil,
      "plaintext does not appear in the sealed file")
check(try! opened(file, key) == multi,
      "multi-chunk payload round-trips byte-for-byte (\(multi.count) bytes over \(chunk)-byte chunks)")

let header = try! Envelope.readHeader(file)
check(header.originalName == "secrets.json" && header.version == 2,
      "header reads back without decrypting the body")

for (label, payload) in [
    ("empty file", Data()),
    ("single byte", Data([42])),
    ("exactly one chunk", Data(repeating: 7, count: chunk)),
    ("one chunk plus one byte", Data(repeating: 7, count: chunk + 1)),
    ("exactly two chunks", Data(repeating: 9, count: chunk * 2)),
] {
    let (f, k) = sealed(payload)
    check((try? opened(f, k)) == payload, "\(label) round-trips")
}

// MARK: - tampering

func frames(of url: URL) -> (prefixEnd: Int, sizes: [Int]) {
    let data = try! Data(contentsOf: url)
    let hlen = Int(data.subdata(in: 4..<8).withUnsafeBytes {
        UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self))
    })
    var offset = 8 + hlen
    let start = offset
    var sizes: [Int] = []
    while offset + 4 <= data.count {
        let len = Int(data.subdata(in: offset..<(offset + 4)).withUnsafeBytes {
            UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self))
        })
        sizes.append(len)
        offset += 4 + len
    }
    return (start, sizes)
}

let (tamperFile, tamperKey) = sealed(multi)
var bytes = try! Data(contentsOf: tamperFile)
bytes[bytes.count - 20] ^= 0xFF
let flipped = path("flipped.fingerlock")
try! bytes.write(to: flipped)
check((try? opened(flipped, tamperKey)) == nil, "a flipped bit in the body is rejected")

// Drop the final chunk cleanly, leaving a file that is structurally valid. This is
// what the is-final flag in the AAD exists to catch — v1 could not.
let (truncFile, truncKey) = sealed(multi)
let f = frames(of: truncFile)
check(f.sizes.count > 1, "multi-chunk payload really produced \(f.sizes.count) chunks")
var whole = try! Data(contentsOf: truncFile)
let lastFrameSize = 4 + f.sizes.last!
whole.removeSubrange((whole.count - lastFrameSize)..<whole.count)
let truncated = path("truncated.fingerlock")
try! whole.write(to: truncated)
check((try? opened(truncated, truncKey)) == nil, "dropping the final chunk is rejected")

// Swap two whole chunks. Each is individually intact, so only the index in the AAD
// catches this.
let (swapFile, swapKey) = sealed(multi)
let s = frames(of: swapFile)
var swapped = try! Data(contentsOf: swapFile)
if s.sizes.count >= 2, s.sizes[0] == s.sizes[1] {
    let size = 4 + s.sizes[0]
    let a = s.prefixEnd..<(s.prefixEnd + size)
    let b = (s.prefixEnd + size)..<(s.prefixEnd + 2 * size)
    let chunkA = swapped.subdata(in: a), chunkB = swapped.subdata(in: b)
    swapped.replaceSubrange(b, with: chunkA)
    swapped.replaceSubrange(a, with: chunkB)
    let reordered = path("reordered.fingerlock")
    try! swapped.write(to: reordered)
    check((try? opened(reordered, swapKey)) == nil, "reordering two chunks is rejected")
} else {
    check(false, "expected at least two equal-sized chunks to swap")
}

// Rewrite the filename in the header. v1 left this malleable; v2 binds a hash of
// the header into every chunk's AAD.
let (hdrFile, hdrKey) = sealed(multi, name: "secrets.json")
var hdrBytes = try! Data(contentsOf: hdrFile)
if let range = hdrBytes.range(of: Data("secrets.json".utf8)) {
    hdrBytes.replaceSubrange(range, with: Data("passwords.txt".utf8))
    let renamed = path("renamed.fingerlock")
    try! hdrBytes.write(to: renamed)
    check((try? opened(renamed, hdrKey)) == nil, "editing the filename in the header is rejected")
} else {
    check(false, "expected to find the filename in the header")
}

// MARK: - reading what v0.1.0 wrote

/// Held outside the block so the reseal tests can upgrade the same fixture.
let legacyKey = SymmetricKey(size: .bits256)

do {
    // Hand-build a format 1 file: magic, header with no isDirectory or chunkSize,
    // then one sealed box over the whole body.
    let legacyPayload = Data("sealed by the first release".utf8)
    let keyData = legacyKey.withUnsafeBytes { Data($0) }
    let rec = try Recovery.wrap(keyData, to: cfg.publicKey)
    let legacyHeader = Header(
        version: 1,
        originalName: "old.txt",
        isDirectory: nil,
        chunkSize: nil,
        enclaveWrapped: Data("stand-in".utf8),
        recoveryEPK: rec.epk,
        recoveryWrapped: rec.ct
    )
    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys
    let headerBytes = try encoder.encode(legacyHeader)

    var file = Envelope.magicV1
    var len = UInt32(headerBytes.count).bigEndian
    withUnsafeBytes(of: &len) { file.append(contentsOf: $0) }
    file.append(headerBytes)
    file.append(try AES.GCM.seal(legacyPayload, using: legacyKey).combined!)

    let legacyURL = path("legacy.fingerlock")
    try file.write(to: legacyURL)

    let h = try Envelope.readHeader(legacyURL)
    check(h.version == 1 && !h.directory, "a format 1 header still parses")
    check(try opened(legacyURL, legacyKey) == legacyPayload,
          "a file sealed by v0.1.0 still opens")
} catch {
    check(false, "format 1 compatibility threw: \(error)")
}

// MARK: - folders

do {
    let work = path("folderwork")
    let folder = work.appendingPathComponent("project")
    try FileManager.default.createDirectory(
        at: folder.appendingPathComponent("nested"), withIntermediateDirectories: true)
    try Data("top level".utf8).write(to: folder.appendingPathComponent("a.txt"))
    try Data(repeating: 3, count: chunk * 2 + 17)
        .write(to: folder.appendingPathComponent("nested/big.bin"))
    // Path-based, not URL-based: URL(fileURLWithPath:) would resolve "a.txt"
    // against the working directory and store an absolute target.
    try FileManager.default.createSymbolicLink(
        atPath: folder.appendingPathComponent("link.txt").path, withDestinationPath: "a.txt")
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o750], ofItemAtPath: folder.appendingPathComponent("nested").path)

    // Archive -> seal -> open -> expand, the same sequence cmdSeal and cmdOpen use.
    let archive = path("folder.zip")
    try Archive.create(folder: folder, output: archive)

    let sealedFolder = path("project.fingerlock")
    let (h, k) = makeHeader("project", directory: true)
    try Envelope.seal(input: archive, output: sealedFolder, header: h, fileKey: k)

    let readBack = try Envelope.readHeader(sealedFolder)
    check(readBack.directory, "header records that the payload was a folder")

    let restoredArchive = path("restored.zip")
    _ = try Envelope.open(input: sealedFolder, output: restoredArchive) { _ in k }

    let destination = path("restored")
    try FileManager.default.createDirectory(at: destination, withIntermediateDirectories: true)
    try Archive.expand(archive: restoredArchive, into: destination)

    let out = destination.appendingPathComponent("project")
    check(FileManager.default.fileExists(atPath: out.path), "folder is recreated by name")
    check(try Data(contentsOf: out.appendingPathComponent("a.txt")) == Data("top level".utf8),
          "top-level file survives the round trip")
    check(try Data(contentsOf: out.appendingPathComponent("nested/big.bin")).count == chunk * 2 + 17,
          "nested multi-chunk file survives the round trip")
    let linkTarget = try FileManager.default.destinationOfSymbolicLink(
        atPath: out.appendingPathComponent("link.txt").path)
    check(linkTarget == "a.txt", "symlink survives as a symlink rather than a copy")
    let perms = try FileManager.default.attributesOfItem(
        atPath: out.appendingPathComponent("nested").path)[.posixPermissions] as? NSNumber
    check(perms?.int16Value == 0o750, "directory permissions survive the round trip")
} catch {
    check(false, "folder round trip threw: \(error)")
}

// MARK: - reseal

do {
    let (original, oldKey) = sealed(multi, name: "migrated.bin")
    let before = try Data(contentsOf: original)

    let newKey = SymmetricKey(size: .bits256)
    let resealed = path("resealed.fingerlock")
    try Envelope.reseal(input: original, output: resealed, oldKey: { _ in oldKey }) { old in
        (Header(version: 2, originalName: old.originalName, isDirectory: old.directory,
                chunkSize: chunk,
                enclaveWrapped: Data("new Enclave blob".utf8),
                recoveryEPK: old.recoveryEPK, recoveryWrapped: old.recoveryWrapped), newKey)
    }

    check(try opened(resealed, newKey) == multi, "resealed file opens under the new key")
    check((try? opened(resealed, oldKey)) == nil, "the old key no longer opens it")
    check(try Data(contentsOf: resealed) != before, "ciphertext actually changed")
    check(try Envelope.readHeader(resealed).originalName == "migrated.bin",
          "reseal preserves the original name")

    // A folder-flagged file must stay folder-flagged, or unsealing would write the
    // archive out instead of expanding it.
    let (dirFile, dirKey) = { () -> (URL, SymmetricKey) in
        let input = path("dirpayload")
        try! Data("archive bytes".utf8).write(to: input)
        let out = path("dir.fingerlock")
        let (h, k) = makeHeader("somefolder", directory: true)
        try! Envelope.seal(input: input, output: out, header: h, fileKey: k)
        return (out, k)
    }()
    let dirResealed = path("dir-resealed.fingerlock")
    let dirNewKey = SymmetricKey(size: .bits256)
    try Envelope.reseal(input: dirFile, output: dirResealed, oldKey: { _ in dirKey }) { old in
        (Header(version: 2, originalName: old.originalName, isDirectory: old.directory,
                chunkSize: chunk, enclaveWrapped: Data("new".utf8),
                recoveryEPK: old.recoveryEPK, recoveryWrapped: old.recoveryWrapped), dirNewKey)
    }
    check(try Envelope.readHeader(dirResealed).directory, "reseal preserves the folder flag")

    // Format 1 in, format 2 out.
    let legacyURL = path("legacy.fingerlock")
    if FileManager.default.fileExists(atPath: legacyURL.path) {
        let upgraded = path("upgraded.fingerlock")
        let k2 = SymmetricKey(size: .bits256)
        try Envelope.reseal(input: legacyURL, output: upgraded, oldKey: { _ in legacyKey }) { old in
            (Header(version: 2, originalName: old.originalName, isDirectory: false,
                    chunkSize: chunk, enclaveWrapped: Data("new".utf8),
                    recoveryEPK: old.recoveryEPK, recoveryWrapped: old.recoveryWrapped), k2)
        }
        check(try Data(contentsOf: upgraded).prefix(4) == Envelope.magicV2,
              "reseal upgrades a format 1 file to format 2")
        check(try opened(upgraded, k2) == Data("sealed by the first release".utf8),
              "the upgraded file still holds the same bytes")
    } else {
        check(false, "expected the legacy fixture to exist")
    }
} catch {
    check(false, "reseal threw: \(error)")
}

// MARK: - key wrapping

let keyBytes = key.withUnsafeBytes { Data($0) }
let a = try! Recovery.wrap(keyBytes, to: cfg.publicKey)
let b = try! Recovery.wrap(keyBytes, to: cfg.publicKey)
check(a.ct != b.ct && a.epk != b.epk, "each seal uses a fresh ephemeral key")
check(try! Recovery.unwrap(epk: a.epk, ct: a.ct, with: priv) == keyBytes,
      "recovery path unwraps the file key")

print(failures == 0 ? "\nall checks passed" : "\n\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
