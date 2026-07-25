import CryptoKit
import Foundation

/// On-disk layout of a `.fingerlock` file:
///
///     "FLK1"            4 bytes  magic
///     header length     4 bytes  big-endian UInt32
///     header            JSON, see `Header`
///     body              AES-GCM sealed box (nonce ‖ ciphertext ‖ tag)
///
/// The file key is random per file and appears twice in the header, wrapped once
/// under the Secure Enclave key and once under the recovery key. Either opens it.
struct Header: Codable {
    var version: Int
    var originalName: String
    /// File key wrapped to the Secure Enclave public key (ECIES).
    var enclaveWrapped: Data
    /// File key wrapped to the recovery public key.
    var recoveryEPK: Data
    var recoveryWrapped: Data
}

enum Envelope {
    static let magic = Data("FLK1".utf8)
    static let ext = "fingerlock"

    static func encode(header: Header, body: Data) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let h = try encoder.encode(header)
        guard h.count <= UInt32.max else { throw FLError("header too large") }

        var out = Data()
        out.append(magic)
        var len = UInt32(h.count).bigEndian
        withUnsafeBytes(of: &len) { out.append(contentsOf: $0) }
        out.append(h)
        out.append(body)
        return out
    }

    static func decode(_ data: Data) throws -> (Header, Data) {
        guard data.count > 8, data.prefix(4) == magic else {
            throw FLError("not a fingerlock file (bad magic).")
        }
        let len = data.subdata(in: 4..<8).withUnsafeBytes {
            UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self))
        }
        let headerEnd = 8 + Int(len)
        guard data.count >= headerEnd else { throw FLError("truncated file.") }

        let header = try JSONDecoder().decode(Header.self, from: data.subdata(in: 8..<headerEnd))
        guard header.version == 1 else {
            throw FLError("file version \(header.version) is newer than this build understands.")
        }
        return (header, data.subdata(in: headerEnd..<data.count))
    }

    static func sealBody(_ plaintext: Data, fileKey: SymmetricKey) throws -> Data {
        guard let combined = try AES.GCM.seal(plaintext, using: fileKey).combined else {
            throw FLError("could not seal body")
        }
        return combined
    }

    static func openBody(_ body: Data, fileKey: SymmetricKey) throws -> Data {
        let box = try AES.GCM.SealedBox(combined: body)
        guard let pt = try? AES.GCM.open(box, using: fileKey) else {
            throw FLError("decryption failed — the file has been modified or the key is wrong.")
        }
        return pt
    }
}
