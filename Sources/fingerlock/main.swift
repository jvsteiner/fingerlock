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
  fingerlock seal <path>...       encrypt a file or folder (no fingerprint needed)
  fingerlock unseal <path>...     decrypt with Touch ID
  fingerlock toggle <path>...     seal or unseal, whichever applies
  fingerlock recover <path>...    decrypt with the recovery passphrase instead
  fingerlock reseal <path>...     re-wrap to this Mac's Enclave key, after moving
                                  machines — never writes the plaintext out
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

/// A scratch path beside the target, so the rename that publishes it stays on the
/// same filesystem. A crash mid-seal must never leave you with neither the
/// plaintext nor a complete sealed file.
func scratchSibling(of url: URL) -> URL {
    url.deletingLastPathComponent()
        .appendingPathComponent(".\(url.lastPathComponent).fltmp")
}

func publish(_ tmp: URL, as url: URL) throws {
    _ = try FileManager.default.replaceItemAt(url, withItemAt: tmp)
}

/// Returns whether the path is a directory, throwing if it isn't there at all.
func checkExists(_ url: URL) throws -> Bool {
    var isDir: ObjCBool = false
    guard FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir) else {
        throw FLError("no such file: \(url.path)")
    }
    return isDir.boolValue
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

    if Recovery.exists() {
        // A recovery key copied from another Mac. Check the passphrase rather than
        // accepting one we have no use for — otherwise the prompt is theatre.
        print("Recovery key found at \(Recovery.configURL.path).")
        _ = try Recovery.privateKey(from: try Recovery.load(),
                                    passphrase: prompt("Its passphrase: "))
        print("Passphrase confirmed.")
    } else {
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
    print("Ready. Seal something with `fingerlock seal <path>`.")
}

func cmdSeal(_ paths: [String], keep: Bool) throws {
    let cfg = try Recovery.load()
    let pub = try Enclave.publicKey()

    for path in paths {
        let url = URL(fileURLWithPath: path)
        let isDirectory = try checkExists(url)
        if url.pathExtension == Envelope.ext {
            print("skip: \(url.lastPathComponent) is already sealed")
            continue
        }
        let out = url.appendingPathExtension(Envelope.ext)
        try refuseOverwrite(out)

        // A folder is archived first and the archive is what gets sealed. The
        // scratch directory takes the archive with it when it goes out of scope.
        let scratch = isDirectory ? try Scratch() : nil
        var source = url
        if let scratch {
            source = scratch.file("payload.zip")
            try Archive.create(folder: url, output: source)
        }

        let fileKey = SymmetricKey(size: .bits256)
        let keyBytes = fileKey.withUnsafeBytes { Data($0) }
        let rec = try Recovery.wrap(keyBytes, to: cfg.publicKey)
        let header = Header(
            version: 2,
            originalName: url.lastPathComponent,
            isDirectory: isDirectory,
            chunkSize: Envelope.defaultChunkSize,
            enclaveWrapped: try Enclave.wrap(keyBytes, to: pub),
            recoveryEPK: rec.epk,
            recoveryWrapped: rec.ct
        )

        let tmp = scratchSibling(of: out)
        try? FileManager.default.removeItem(at: tmp)
        try Envelope.seal(input: source, output: tmp, header: header, fileKey: fileKey)
        try publish(tmp, as: out)

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
        _ = try checkExists(url)

        let parent = url.deletingLastPathComponent()
        let peek = try Envelope.readHeader(url)
        let out = parent.appendingPathComponent(peek.originalName)
        try refuseOverwrite(out)

        // Folders are decrypted to a scratch archive and expanded from there, so a
        // failure part way through cannot leave a half-written folder in place.
        let scratch = peek.directory ? try Scratch() : nil
        let destination = scratch?.file("payload.zip") ?? scratchSibling(of: out)
        try? FileManager.default.removeItem(at: destination)

        let header = try Envelope.open(input: url, output: destination) { header in
            SymmetricKey(data: try openKey(header, url))
        }

        if header.directory {
            try Archive.expand(archive: destination, into: parent)
        } else {
            try publish(destination, as: out)
        }

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

/// Re-wrap sealed files to this Mac's Enclave key, using the recovery passphrase to
/// get in. What you run after moving to a new machine, where the old Enclave key no
/// longer exists and never will again.
func cmdReseal(_ paths: [String]) throws {
    let cfg = try Recovery.load()
    let priv = try Recovery.privateKey(from: cfg, passphrase: prompt("Recovery passphrase: "))
    let pub = try Enclave.publicKey()

    for path in paths {
        let url = URL(fileURLWithPath: path)
        _ = try checkExists(url)
        guard url.pathExtension == Envelope.ext else {
            throw FLError("\(url.lastPathComponent) is not a sealed file.")
        }

        let tmp = scratchSibling(of: url)
        try? FileManager.default.removeItem(at: tmp)
        try Envelope.reseal(
            input: url,
            output: tmp,
            oldKey: { header in
                SymmetricKey(data: try Recovery.unwrap(epk: header.recoveryEPK,
                                                       ct: header.recoveryWrapped, with: priv))
            },
            makeHeader: { old in
                let fileKey = SymmetricKey(size: .bits256)
                let keyBytes = fileKey.withUnsafeBytes { Data($0) }
                let rec = try Recovery.wrap(keyBytes, to: cfg.publicKey)
                return (Header(
                    version: 2,
                    originalName: old.originalName,
                    isDirectory: old.directory,
                    chunkSize: Envelope.defaultChunkSize,
                    enclaveWrapped: try Enclave.wrap(keyBytes, to: pub),
                    recoveryEPK: rec.epk,
                    recoveryWrapped: rec.ct
                ), fileKey)
            }
        )
        try publish(tmp, as: url)
        print("resealed: \(url.lastPathComponent)")
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
// LaunchServices sometimes tacks a process-serial-number argument on.
args.removeAll { $0.hasPrefix("-psn_") }

// No arguments and no terminal means Finder launched us — double-clicked a sealed
// file, or the Finder extension opened a fingerlock:// URL. Hand over to AppKit so
// the open-documents event can arrive. From a shell, keep printing usage.
if args.isEmpty && isatty(STDIN_FILENO) == 0 {
    runAsApp()
}

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
    case "reseal": try cmdReseal(try requireFiles())
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
