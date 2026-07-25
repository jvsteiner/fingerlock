import CryptoKit
import Foundation

struct FLError: Error, CustomStringConvertible {
    let description: String
    init(_ m: String) { description = m }
}

let usage = """
fingerlock — seal files behind Touch ID

USAGE
  fingerlock init                 create the Secure Enclave key and recovery key
  fingerlock seal <file>...       encrypt (no fingerprint needed)
  fingerlock unseal <file>...     decrypt with Touch ID
  fingerlock toggle <file>...     seal or unseal, whichever applies
  fingerlock recover <file>...    decrypt with the recovery passphrase instead
  fingerlock status               show what is set up
  fingerlock reset-key            destroy the Enclave key (recovery only, after this)

OPTIONS
  --keep      leave the input file in place instead of removing it
"""

// MARK: - helpers

func prompt(_ text: String) -> String {
    guard let raw = getpass(text) else { return "" }
    return String(cString: raw)
}

/// Write next to the target, fsync, then rename. A crash mid-seal must never be
/// able to leave you with neither the plaintext nor a complete sealed file.
func writeAtomically(_ data: Data, to url: URL) throws {
    let tmp = url.deletingLastPathComponent()
        .appendingPathComponent(".\(url.lastPathComponent).fltmp")
    FileManager.default.createFile(atPath: tmp.path, contents: nil,
                                   attributes: [.posixPermissions: 0o600])
    let fh = try FileHandle(forWritingTo: tmp)
    try fh.write(contentsOf: data)
    try fh.synchronize()
    try fh.close()
    _ = try FileManager.default.replaceItemAt(url, withItemAt: tmp)
}

func checkRegularFile(_ url: URL) throws {
    var isDir: ObjCBool = false
    guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir) else {
        throw FLError("no such file: \(url.path)")
    }
    if isDir.boolValue {
        throw FLError("\(url.lastPathComponent) is a folder — compress it first, then seal the archive.")
    }
}

func refuseOverwrite(_ url: URL) throws {
    if FileManager.default.fileExists(atPath: url.path) {
        throw FLError("\(url.lastPathComponent) already exists — moving it aside is your call, not mine.")
    }
}

// MARK: - commands

func cmdInit() throws {
    if Enclave.exists() && Recovery.exists() {
        print("Already set up. `fingerlock status` for details.")
        return
    }

    if !Recovery.exists() {
        print("""
            Choose a recovery passphrase.

            This is the only way back in if your fingerprints are re-enrolled, this Mac \
            dies, or you restore to new hardware. Losing it means losing every sealed file. \
            Put it in your password manager now.
            """)
        let a = prompt("Recovery passphrase: ")
        guard a.count >= 8 else { throw FLError("too short — use at least 8 characters.") }
        let b = prompt("Again: ")
        guard a == b else { throw FLError("passphrases did not match.") }
        _ = try Recovery.create(passphrase: a)
        print("Recovery key written to \(Recovery.configURL.path)")
    }

    if !Enclave.exists() {
        _ = try Enclave.create()
        print("Secure Enclave key created.")
    }
    print("Ready. Seal something with `fingerlock seal <file>`.")
}

func cmdSeal(_ paths: [String], keep: Bool) throws {
    let cfg = try Recovery.load()
    let pub = try Enclave.publicKey()

    for path in paths {
        let url = URL(fileURLWithPath: path)
        try checkRegularFile(url)
        if url.pathExtension == Envelope.ext {
            print("skip: \(url.lastPathComponent) is already sealed")
            continue
        }
        let out = url.appendingPathExtension(Envelope.ext)
        try refuseOverwrite(out)

        let plaintext = try Data(contentsOf: url)
        let fileKey = SymmetricKey(size: .bits256)
        let keyBytes = fileKey.withUnsafeBytes { Data($0) }

        let rec = try Recovery.wrap(keyBytes, to: cfg.publicKey)
        let header = Header(
            version: 1,
            originalName: url.lastPathComponent,
            enclaveWrapped: try Enclave.wrap(keyBytes, to: pub),
            recoveryEPK: rec.epk,
            recoveryWrapped: rec.ct
        )
        let body = try Envelope.sealBody(plaintext, fileKey: fileKey)
        try writeAtomically(try Envelope.encode(header: header, body: body), to: out)

        if !keep { try FileManager.default.removeItem(at: url) }
        print("sealed: \(out.lastPathComponent)")
    }
}

/// `openKey` is the difference between `unseal` (Enclave, Touch ID) and
/// `recover` (passphrase). Everything else about the two paths is identical.
func cmdOpen(_ paths: [String], keep: Bool, label: String,
             openKey: (Header, URL) throws -> Data) throws {
    for path in paths {
        let url = URL(fileURLWithPath: path)
        try checkRegularFile(url)

        let (header, body) = try Envelope.decode(try Data(contentsOf: url))
        let out = url.deletingLastPathComponent()
            .appendingPathComponent(header.originalName)
        try refuseOverwrite(out)

        let fileKey = SymmetricKey(data: try openKey(header, url))
        let plaintext = try Envelope.openBody(body, fileKey: fileKey)
        try writeAtomically(plaintext, to: out)

        if !keep { try FileManager.default.removeItem(at: url) }
        print("\(label): \(out.lastPathComponent)")
    }
}

func cmdUnseal(_ paths: [String], keep: Bool) throws {
    try cmdOpen(paths, keep: keep, label: "unsealed") { header, url in
        let priv = try Enclave.privateKey(prompt: "unseal \(url.lastPathComponent)")
        return try Enclave.unwrap(header.enclaveWrapped, with: priv)
    }
}

func cmdRecover(_ paths: [String], keep: Bool) throws {
    let cfg = try Recovery.load()
    let priv = try Recovery.privateKey(from: cfg, passphrase: prompt("Recovery passphrase: "))
    try cmdOpen(paths, keep: keep, label: "recovered") { header, _ in
        try Recovery.unwrap(epk: header.recoveryEPK, ct: header.recoveryWrapped, with: priv)
    }
}

func cmdToggle(_ paths: [String], keep: Bool) throws {
    let sealed = paths.filter { URL(fileURLWithPath: $0).pathExtension == Envelope.ext }
    let plain = paths.filter { URL(fileURLWithPath: $0).pathExtension != Envelope.ext }
    if !plain.isEmpty { try cmdSeal(plain, keep: keep) }
    if !sealed.isEmpty { try cmdUnseal(sealed, keep: keep) }
}

func cmdStatus() {
    print("Secure Enclave key: \(Enclave.exists() ? "present" : "missing — run `fingerlock init`")")
    print("Recovery key:       \(Recovery.exists() ? Recovery.configURL.path : "missing — run `fingerlock init`")")
}

func cmdResetKey() throws {
    print("""
        This destroys the Secure Enclave key. Files already sealed will only open \
        with `fingerlock recover` and your passphrase.
        """)
    guard prompt("Type 'destroy' to confirm: ") == "destroy" else {
        print("Cancelled.")
        return
    }
    try Enclave.delete()
    print("Enclave key destroyed. `fingerlock init` makes a new one.")
}

// MARK: - entry

var args = Array(CommandLine.arguments.dropFirst())
let keep = args.contains("--keep")
args.removeAll { $0 == "--keep" }

guard let command = args.first else {
    print(usage)
    exit(1)
}
let rest = Array(args.dropFirst())

func requireFiles() throws -> [String] {
    guard !rest.isEmpty else { throw FLError("\(command) needs at least one file.") }
    return rest
}

do {
    switch command {
    case "init": try cmdInit()
    case "seal": try cmdSeal(try requireFiles(), keep: keep)
    case "unseal": try cmdUnseal(try requireFiles(), keep: keep)
    case "toggle": try cmdToggle(try requireFiles(), keep: keep)
    case "recover": try cmdRecover(try requireFiles(), keep: keep)
    case "status": cmdStatus()
    case "reset-key": try cmdResetKey()
    case "-h", "--help", "help": print(usage)
    default:
        print(usage)
        exit(1)
    }
} catch {
    FileHandle.standardError.write(Data("fingerlock: \(error)\n".utf8))
    exit(1)
}
