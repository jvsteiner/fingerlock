import CryptoKit
import Foundation

/// On-disk layout of a `.fingerlock` file (format 2):
///
///     "FLK2"            4 bytes   magic
///     header length     4 bytes   big-endian UInt32
///     header            JSON, see `Header`
///     chunks            repeated: [4-byte BE length][AES-GCM ciphertext ‖ tag]
///
/// The body is chunked so neither sealing nor unsealing has to hold the whole
/// thing in memory — a folder full of video is as cheap as a text file.
///
/// Chunking an AEAD needs care, since a per-chunk tag proves each chunk is intact
/// but says nothing about its position or whether any are missing. So every chunk
/// authenticates, as additional data:
///
///   - a SHA-256 of the header, which pins the filename and the directory flag
///     that v1 left malleable
///   - its own index, so chunks cannot be reordered or duplicated
///   - whether it is the last chunk, so truncation fails instead of returning a
///     shorter file that looks valid
///
/// Nonces are a counter rather than random. The file key is fresh per file, so a
/// counter cannot collide, and it saves 12 bytes a chunk.
struct Header: Codable {
    var version: Int
    var originalName: String
    /// Whether `originalName` was a folder, archived before sealing. Absent in v1.
    var isDirectory: Bool?
    /// Plaintext bytes per chunk. Absent in v1, which had no chunks.
    var chunkSize: Int?
    /// File key wrapped to the Secure Enclave public key (ECIES).
    var enclaveWrapped: Data
    /// File key wrapped to the recovery public key.
    var recoveryEPK: Data
    var recoveryWrapped: Data

    var directory: Bool { isDirectory ?? false }
}

enum Envelope {
    static let magicV1 = Data("FLK1".utf8)
    static let magicV2 = Data("FLK2".utf8)
    static let ext = "fingerlock"
    static let defaultChunkSize = 1 << 20  // 1 MiB
    private static let tagSize = 16

    // MARK: - framing helpers

    private static func be32(_ v: Int) -> Data {
        var b = UInt32(v).bigEndian
        return withUnsafeBytes(of: &b) { Data($0) }
    }

    private static func readBE32(_ fh: FileHandle) throws -> Int? {
        guard let d = try fh.read(upToCount: 4), !d.isEmpty else { return nil }
        guard d.count == 4 else { throw FLError("truncated file.") }
        return Int(d.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) })
    }

    private static func nonce(_ index: UInt64) throws -> AES.GCM.Nonce {
        var bytes = Data(repeating: 0, count: 4)
        var be = index.bigEndian
        withUnsafeBytes(of: &be) { bytes.append(contentsOf: $0) }
        return try AES.GCM.Nonce(data: bytes)
    }

    private static func aad(_ headerHash: Data, _ index: UInt64, _ isFinal: Bool) -> Data {
        var d = headerHash
        var be = index.bigEndian
        withUnsafeBytes(of: &be) { d.append(contentsOf: $0) }
        d.append(isFinal ? 1 : 0)
        return d
    }

    private static func encodeHeader(_ header: Header) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        return try encoder.encode(header)
    }

    // MARK: - sealing

    /// Streams `input` into a sealed file at `output`.
    static func seal(input: URL, output: URL, header: Header, fileKey: SymmetricKey) throws {
        let headerBytes = try encodeHeader(header)
        let headerHash = Data(SHA256.hash(data: headerBytes))
        let chunkSize = header.chunkSize ?? defaultChunkSize

        let inFH = try FileHandle(forReadingFrom: input)
        defer { try? inFH.close() }

        FileManager.default.createFile(atPath: output.path, contents: nil,
                                       attributes: [.posixPermissions: 0o600])
        let outFH = try FileHandle(forWritingTo: output)
        defer { try? outFH.close() }

        try outFH.write(contentsOf: magicV2)
        try outFH.write(contentsOf: be32(headerBytes.count))
        try outFH.write(contentsOf: headerBytes)

        // Finality comes from the byte count rather than from reading ahead, so no
        // iteration has to hold two chunks at once.
        let total = try inFH.seekToEnd()
        try inFH.seek(toOffset: 0)

        var consumed: UInt64 = 0
        var index: UInt64 = 0
        repeat {
            // Without this the loop peaks at the size of the whole input: Data
            // coming back from FileHandle is autoreleased, and nothing drains the
            // pool until the function returns.
            try autoreleasepool {
                let plain = try inFH.read(upToCount: chunkSize) ?? Data()
                consumed += UInt64(plain.count)
                let isFinal = consumed >= total

                let box = try AES.GCM.seal(plain, using: fileKey,
                                           nonce: nonce(index),
                                           authenticating: aad(headerHash, index, isFinal))
                var frame = be32(box.ciphertext.count + box.tag.count)
                frame.append(box.ciphertext)
                frame.append(box.tag)
                try outFH.write(contentsOf: frame)
                index += 1
            }
        } while consumed < total
        try outFH.synchronize()
    }

    // MARK: - opening

    /// Reads just the header, so the caller can unwrap the file key before we
    /// commit to decrypting anything.
    static func readHeader(_ url: URL) throws -> Header {
        let fh = try FileHandle(forReadingFrom: url)
        defer { try? fh.close() }
        return try readHeader(fh).0
    }

    private static func readHeader(_ fh: FileHandle) throws -> (Header, Data, Bool) {
        guard let magic = try fh.read(upToCount: 4), magic.count == 4 else {
            throw FLError("not a fingerlock file.")
        }
        let isV2: Bool
        switch magic {
        case magicV2: isV2 = true
        case magicV1: isV2 = false
        default: throw FLError("not a fingerlock file (bad magic).")
        }

        guard let len = try readBE32(fh) else { throw FLError("truncated file.") }
        guard let headerBytes = try fh.read(upToCount: len), headerBytes.count == len else {
            throw FLError("truncated file.")
        }
        let header = try JSONDecoder().decode(Header.self, from: headerBytes)
        guard header.version <= 2 else {
            throw FLError("file version \(header.version) is newer than this build understands.")
        }
        return (header, headerBytes, isV2)
    }

    /// Streams the plaintext of `input` into `output`.
    static func open(input: URL, output: URL,
                     fileKey: (Header) throws -> SymmetricKey) throws -> Header {
        let inFH = try FileHandle(forReadingFrom: input)
        defer { try? inFH.close() }

        let (header, headerBytes, isV2) = try readHeader(inFH)
        let key = try fileKey(header)

        FileManager.default.createFile(atPath: output.path, contents: nil,
                                       attributes: [.posixPermissions: 0o600])
        let outFH = try FileHandle(forWritingTo: output)
        defer { try? outFH.close() }

        if isV2 {
            try openChunked(inFH, outFH, key: key,
                            headerHash: Data(SHA256.hash(data: headerBytes)),
                            bodyStart: try inFH.offset())
        } else {
            try openLegacy(inFH, outFH, key: key)
        }
        try outFH.synchronize()
        return header
    }

    private static func openChunked(_ inFH: FileHandle, _ outFH: FileHandle,
                                    key: SymmetricKey, headerHash: Data,
                                    bodyStart: UInt64) throws {
        let total = try inFH.seekToEnd()
        try inFH.seek(toOffset: bodyStart)

        var index: UInt64 = 0
        repeat {
            // Same reason as sealing: one chunk resident at a time, not all of them.
            try autoreleasepool {
                guard let len = try readBE32(inFH), len >= tagSize,
                      let frame = try inFH.read(upToCount: len), frame.count == len else {
                    throw FLError("truncated file.")
                }
                let isFinal = try inFH.offset() >= total

                let box = try AES.GCM.SealedBox(nonce: nonce(index),
                                                ciphertext: frame.prefix(frame.count - tagSize),
                                                tag: frame.suffix(tagSize))
                guard let plain = try? AES.GCM.open(box, using: key,
                                                    authenticating: aad(headerHash, index, isFinal)) else {
                    throw FLError("decryption failed — the file has been modified or truncated.")
                }
                try outFH.write(contentsOf: plain)
                index += 1
            }
        } while try inFH.offset() < total
    }

    /// Format 1: one sealed box covering the whole body. Kept so files sealed by
    /// v0.1.0 still open. Nothing writes this any more.
    private static func openLegacy(_ inFH: FileHandle, _ outFH: FileHandle,
                                   key: SymmetricKey) throws {
        let body = try inFH.readToEnd() ?? Data()
        let box = try AES.GCM.SealedBox(combined: body)
        guard let plain = try? AES.GCM.open(box, using: key) else {
            throw FLError("decryption failed — the file has been modified or the key is wrong.")
        }
        try outFH.write(contentsOf: plain)
    }
}
