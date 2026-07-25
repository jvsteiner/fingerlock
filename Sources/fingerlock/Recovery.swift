import CommonCrypto
import CryptoKit
import Foundation

/// The escape hatch.
///
/// A Secure Enclave key dies with the machine, and `.biometryCurrentSet` kills it
/// the moment fingerprints are re-enrolled. Without a second way in, either event
/// destroys every sealed file. So `init` also makes an X25519 recovery keypair:
///
///   - the public half sits in the config in the clear, so sealing needs no passphrase
///   - the private half is encrypted under a passphrase you choose, and is the only
///     thing standing between a dead Enclave and permanent data loss
struct RecoveryConfig: Codable {
    var version: Int
    var publicKey: Data
    /// PBKDF2(passphrase) -> AES-GCM over the X25519 private key.
    var salt: Data
    var iterations: Int
    var wrappedPrivateKey: Data
}

enum Recovery {
    static let iterations = 600_000

    static var configURL: URL {
        if let override = ProcessInfo.processInfo.environment["FINGERLOCK_CONFIG"] {
            return URL(fileURLWithPath: override)
        }
        let base = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".config/fingerlock", isDirectory: true)
        return base.appendingPathComponent("config.json")
    }

    static func load() throws -> RecoveryConfig {
        guard let data = try? Data(contentsOf: configURL) else {
            throw FLError("no config at \(configURL.path) — run `fingerlock init` first.")
        }
        return try JSONDecoder().decode(RecoveryConfig.self, from: data)
    }

    static func exists() -> Bool {
        FileManager.default.fileExists(atPath: configURL.path)
    }

    static func create(passphrase: String) throws -> RecoveryConfig {
        let priv = Curve25519.KeyAgreement.PrivateKey()
        var salt = Data(count: 32)
        salt.withUnsafeMutableBytes { _ = SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }

        let kek = try derive(passphrase: passphrase, salt: salt, iterations: iterations)
        let wrapped = try AES.GCM.seal(priv.rawRepresentation, using: kek).combined!

        let cfg = RecoveryConfig(
            version: 1,
            publicKey: priv.publicKey.rawRepresentation,
            salt: salt,
            iterations: iterations,
            wrappedPrivateKey: wrapped
        )

        try FileManager.default.createDirectory(
            at: configURL.deletingLastPathComponent(),
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(cfg).write(to: configURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: configURL.path)
        return cfg
    }

    static func privateKey(
        from cfg: RecoveryConfig, passphrase: String
    ) throws -> Curve25519.KeyAgreement.PrivateKey {
        let kek = try derive(passphrase: passphrase, salt: cfg.salt, iterations: cfg.iterations)
        let box = try AES.GCM.SealedBox(combined: cfg.wrappedPrivateKey)
        guard let raw = try? AES.GCM.open(box, using: kek) else {
            throw FLError("wrong recovery passphrase.")
        }
        return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw)
    }

    // MARK: - key wrapping used by the envelope

    private static let info = "fingerlock-recovery-v1".data(using: .utf8)!

    /// ECIES-style: fresh ephemeral key per file, so two files never share a wrap key.
    static func wrap(_ fileKey: Data, to publicKeyRaw: Data) throws -> (epk: Data, ct: Data) {
        let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKeyRaw)
        let eph = Curve25519.KeyAgreement.PrivateKey()
        let shared = try eph.sharedSecretFromKeyAgreement(with: pub)
        let kek = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: eph.publicKey.rawRepresentation + publicKeyRaw,
            sharedInfo: info,
            outputByteCount: 32
        )
        let ct = try AES.GCM.seal(fileKey, using: kek).combined!
        return (eph.publicKey.rawRepresentation, ct)
    }

    static func unwrap(
        epk: Data, ct: Data, with priv: Curve25519.KeyAgreement.PrivateKey
    ) throws -> Data {
        let ephPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: epk)
        let shared = try priv.sharedSecretFromKeyAgreement(with: ephPub)
        let kek = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: epk + priv.publicKey.rawRepresentation,
            sharedInfo: info,
            outputByteCount: 32
        )
        let box = try AES.GCM.SealedBox(combined: ct)
        return try AES.GCM.open(box, using: kek)
    }

    // MARK: - PBKDF2

    private static func derive(
        passphrase: String, salt: Data, iterations: Int
    ) throws -> SymmetricKey {
        var out = Data(count: 32)
        let pw = Array(passphrase.utf8)
        let status = out.withUnsafeMutableBytes { outBuf in
            salt.withUnsafeBytes { saltBuf in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    pw, pw.count,
                    saltBuf.baseAddress!.assumingMemoryBound(to: UInt8.self), salt.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    UInt32(iterations),
                    outBuf.baseAddress!.assumingMemoryBound(to: UInt8.self), 32
                )
            }
        }
        guard status == kCCSuccess else { throw FLError("key derivation failed") }
        return SymmetricKey(data: out)
    }
}
