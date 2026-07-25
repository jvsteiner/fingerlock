import Cocoa
import FinderSync

/// The top-level Finder context menu item.
///
/// This runs sandboxed, so it can reach neither the Secure Enclave nor the CLI. It
/// does one thing: collect the selected paths and hand them to the main app through
/// the fingerlock:// scheme, which is the same entry point a double-click uses.
class FinderSyncExtension: FIFinderSync {
    override init() {
        super.init()
        // A FinderSync extension only offers a menu inside directories it declares
        // an interest in. Anything narrower than the mounted volumes would mean the
        // item silently missing wherever you happened not to have listed.
        FIFinderSyncController.default().directoryURLs = Self.volumes()
    }

    private static func volumes() -> Set<URL> {
        let keys: [URLResourceKey] = [.volumeIsBrowsableKey]
        let mounted = FileManager.default.mountedVolumeURLs(
            includingResourceValuesForKeys: keys, options: []
        ) ?? []
        let browsable = mounted.filter {
            (try? $0.resourceValues(forKeys: [.volumeIsBrowsableKey]))?.volumeIsBrowsable ?? false
        }
        return Set(browsable.isEmpty ? [URL(fileURLWithPath: "/")] : browsable)
    }

    override func menu(for menuKind: FIMenuKind) -> NSMenu? {
        guard menuKind == .contextualMenuForItems else { return nil }
        guard let selected = FIFinderSyncController.default().selectedItemURLs(),
              !selected.isEmpty else { return nil }

        // Say which way it will go, rather than making the user infer it.
        let sealed = selected.allSatisfy { $0.pathExtension == "fingerlock" }
        let title = sealed
            ? (selected.count == 1 ? "Unseal with Touch ID" : "Unseal \(selected.count) items with Touch ID")
            : (selected.count == 1 ? "Seal with Fingerlock" : "Seal \(selected.count) items with Fingerlock")

        let menu = NSMenu(title: "")
        let item = menu.addItem(withTitle: title, action: #selector(toggle(_:)), keyEquivalent: "")
        item.target = self
        return menu
    }

    @objc func toggle(_ sender: AnyObject?) {
        guard let selected = FIFinderSyncController.default().selectedItemURLs(),
              !selected.isEmpty else { return }

        var components = URLComponents()
        components.scheme = "fingerlock"
        components.host = "toggle"
        components.queryItems = selected.map { URLQueryItem(name: "path", value: $0.path) }

        guard let url = components.url else { return }
        NSWorkspace.shared.open(url)
    }
}
