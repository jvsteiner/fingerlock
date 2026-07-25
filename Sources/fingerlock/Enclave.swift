import Foundation
import LocalAuthentication
import Security

/// The Secure Enclave key that wraps every file key.
///
/// The private half is generated inside the Enclave and never leaves it. Sealing
/// only needs the public half, so it runs without a fingerprint; unsealing calls
/// into the Enclave, which refuses without a live biometric match.
enum Enclave {
    static let tag = "com.jvs.fingerlock.sek".data(using: .utf8)!

    /// `.biometryCurrentSet` invalidates the key whenever the enrolled fingerprint
    /// set changes. That is deliberate — it is the property that makes a sealed file
    /// unreadable to someone who adds their own finger to this Mac. It is also why
    /// every sealed file carries a recovery blob (see `Recovery`).
    private static func accessControl() throws -> SecAccessControl {
        var err: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &err
        ) else {
            throw FLError("could not build access control: \(err!.takeRetainedValue())")
        }
        return ac
    }

    static func create() throws -> SecKey {
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecUseDataProtectionKeychain as String: true,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: try accessControl(),
            ],
        ]
        var err: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else {
            let e = err!.takeRetainedValue()
            throw FLError("""
                could not create the Secure Enclave key: \(e)

                A -34018 here means the binary is not signed with the entitlements it \
                needs. Run `make sign`.
                """)
        }
        return key
    }

    /// Fetches the existing private key. `prompt` is what Touch ID shows the user.
    static func privateKey(prompt: String) throws -> SecKey {
        let ctx = LAContext()
        ctx.localizedReason = prompt

        let q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationContext as String: ctx,
            kSecReturnRef as String: true,
        ]

        var out: CFTypeRef?
        let st = SecItemCopyMatching(q as CFDictionary, &out)
        if st == errSecItemNotFound {
            throw FLError("no Secure Enclave key found — run `fingerlock init` first.")
        }
        guard st == errSecSuccess, let key = out else {
            throw FLError("could not read the Secure Enclave key: \(message(st))")
        }
        return (key as! SecKey)
    }

    static func publicKey() throws -> SecKey {
        // Fetching the *reference* never prompts; only using the private key does.
        let priv = try privateKey(prompt: "")
        guard let pub = SecKeyCopyPublicKey(priv) else {
            throw FLError("could not derive the public key")
        }
        return pub
    }

    /// Must never block. `kSecUseAuthenticationUIFail` keeps the keychain from putting
    /// up any dialog; if the key is there but needs a fingerprint we get
    /// `errSecInteractionNotAllowed`, which answers the question just as well.
    static func exists() -> Bool {
        let q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationUI as String: kSecUseAuthenticationUIFail,
        ]
        let st = SecItemCopyMatching(q as CFDictionary, nil)
        return st == errSecSuccess || st == errSecInteractionNotAllowed
    }

    static func delete() throws {
        let q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecUseDataProtectionKeychain as String: true,
        ]
        let st = SecItemDelete(q as CFDictionary)
        guard st == errSecSuccess || st == errSecItemNotFound else {
            throw FLError("could not delete the Secure Enclave key: \(message(st))")
        }
    }

    private static let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorX963SHA256AESGCM

    static func wrap(_ data: Data, to pub: SecKey) throws -> Data {
        var err: Unmanaged<CFError>?
        guard let ct = SecKeyCreateEncryptedData(pub, algorithm, data as CFData, &err) else {
            throw FLError("Enclave wrap failed: \(err!.takeRetainedValue())")
        }
        return ct as Data
    }

    static func unwrap(_ data: Data, with priv: SecKey) throws -> Data {
        var err: Unmanaged<CFError>?
        guard let pt = SecKeyCreateDecryptedData(priv, algorithm, data as CFData, &err) else {
            throw FLError("Enclave unwrap failed: \(err!.takeRetainedValue())")
        }
        return pt as Data
    }

    private static func message(_ st: OSStatus) -> String {
        (SecCopyErrorMessageString(st, nil) as String?) ?? "OSStatus \(st)"
    }
}
