import AppKit
import Foundation

/// GUI mode: what runs when Finder hands us files rather than a shell handing us
/// arguments. Double-clicking a sealed file lands here, and so does the Finder
/// extension — it can't reach the Secure Enclave from its sandbox, so it opens a
/// `fingerlock://toggle?path=…` URL and this does the work.
///
/// There is no window. The only UI is the Touch ID prompt the Enclave puts up and
/// an alert if something goes wrong; then the process quits.
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var handledSomething = false

    func application(_ application: NSApplication, open urls: [URL]) {
        handledSomething = true
        var files: [String] = []
        for url in urls {
            if url.isFileURL {
                files.append(url.path)
            } else if url.scheme == "fingerlock" {
                files.append(contentsOf: Self.paths(fromCommandURL: url))
            }
        }
        run(files)
    }

    /// Nothing arrived — launched directly from Finder or the Dock. Say what this
    /// is rather than quitting silently, which reads as a crash.
    func applicationDidFinishLaunching(_ notification: Notification) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [self] in
            guard !handledSomething else { return }
            let a = NSAlert()
            a.messageText = "Fingerlock"
            a.informativeText = """
                Nothing to do. Double-click a .fingerlock file to unseal it, or \
                right-click any file in Finder and choose Fingerlock.
                """
            a.runModal()
            NSApp.terminate(nil)
        }
    }

    /// `fingerlock://toggle?path=/a&path=/b`
    static func paths(fromCommandURL url: URL) -> [String] {
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        return items.filter { $0.name == "path" }.compactMap { $0.value }
    }

    private func run(_ files: [String]) {
        guard !files.isEmpty else { NSApp.terminate(nil); return }
        do {
            try cmdToggle(files, keep: false)
        } catch {
            let a = NSAlert()
            a.alertStyle = .critical
            a.messageText = "Fingerlock"
            a.informativeText = "\(error)"
            a.runModal()
            NSApp.terminate(nil)
            return
        }
        NSApp.terminate(nil)
    }
}

func runAsApp() -> Never {
    let app = NSApplication.shared
    let delegate = AppDelegate()
    app.delegate = delegate
    app.setActivationPolicy(.accessory)
    app.run()
    exit(0)
}
