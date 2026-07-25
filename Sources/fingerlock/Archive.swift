import Foundation

/// Folders get archived before sealing and expanded after.
///
/// `ditto` rather than `tar` or a Swift zip: it is the macOS-native path and keeps
/// resource forks, extended attributes and permissions intact, so a folder that
/// goes through a seal/unseal round trip comes back the same rather than quietly
/// stripped.
enum Archive {
    /// Archives `folder` to `output`. `--keepParent` puts the folder itself inside
    /// the archive, so expanding into the parent directory recreates it.
    static func create(folder: URL, output: URL) throws {
        try run("/usr/bin/ditto", [
            "-c", "-k", "--sequesterRsrc", "--keepParent",
            folder.path, output.path,
        ], failure: "could not archive \(folder.lastPathComponent)")
    }

    /// Expands `archive` into `directory`, recreating the original folder inside it.
    static func expand(archive: URL, into directory: URL) throws {
        try run("/usr/bin/ditto", [
            "-x", "-k", archive.path, directory.path,
        ], failure: "could not expand the archive")
    }

    private static func run(_ tool: String, _ args: [String], failure: String) throws {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = args

        let errPipe = Pipe()
        process.standardError = errPipe
        process.standardOutput = FileHandle.nullDevice

        try process.run()
        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        guard process.terminationStatus == 0 else {
            let detail = String(data: errData, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            throw FLError(detail.isEmpty ? failure : "\(failure): \(detail)")
        }
    }
}

/// A directory that cleans itself up, for the archive that only exists between
/// `ditto` and the sealed file.
final class Scratch {
    let url: URL

    init() throws {
        url = FileManager.default.temporaryDirectory
            .appendingPathComponent("fingerlock-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
    }

    func file(_ name: String) -> URL { url.appendingPathComponent(name) }

    deinit { try? FileManager.default.removeItem(at: url) }
}
