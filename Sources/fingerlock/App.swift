import AppKit
import Foundation

/// GUI mode: what runs when Finder hands us files rather than a shell handing us
/// arguments. Double-clicking a sealed file lands here, and so does the Finder
/// extension — it can't reach the Secure Enclave from its sandbox, so it opens a
/// `fingerlock://toggle?path=…` URL and this does the work.
///
/// Beyond first-run setup there is no interface. The only UI is the Touch ID prompt
/// the Enclave puts up, and an alert if something goes wrong.
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var pending: [String] = []
    private var launched = false
    private var setup: SetupWindow?

    /// Can arrive before or after `applicationDidFinishLaunching`, so it only
    /// collects paths — `start()` decides what to do with them.
    func application(_ application: NSApplication, open urls: [URL]) {
        for url in urls {
            if url.isFileURL {
                pending.append(url.path)
            } else if url.scheme == "fingerlock" {
                pending.append(contentsOf: Self.paths(fromCommandURL: url))
            }
        }
        if launched { start() }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        launched = true
        // Give an open-documents event that is already in flight a chance to land,
        // so a double-click doesn't get treated as a bare launch.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { [self] in start() }
    }

    private func start() {
        guard setup == nil else { return }

        if !setupComplete() {
            let window = SetupWindow()
            setup = window
            window.run { [self] ok in
                setup = nil
                guard ok else { NSApp.terminate(nil); return }
                if pending.isEmpty {
                    note("Fingerlock is ready.", "Right-click any file in Finder to seal it.")
                }
                handlePending()
            }
            return
        }
        handlePending()
    }

    private func handlePending() {
        let files = pending
        pending = []

        guard !files.isEmpty else {
            note("Fingerlock", """
                Nothing to do. Double-click a .fingerlock file to unseal it, or \
                right-click any file in Finder and choose Fingerlock.
                """)
            NSApp.terminate(nil)
            return
        }

        do {
            try cmdToggle(files, keep: false)
        } catch {
            let a = NSAlert()
            a.alertStyle = .critical
            a.messageText = "Fingerlock"
            a.informativeText = "\(error)"
            a.runModal()
        }
        NSApp.terminate(nil)
    }

    private func note(_ title: String, _ body: String) {
        let a = NSAlert()
        a.messageText = title
        a.informativeText = body
        a.runModal()
    }

    /// `fingerlock://toggle?path=/a&path=/b`
    static func paths(fromCommandURL url: URL) -> [String] {
        let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
        return items.filter { $0.name == "path" }.compactMap { $0.value }
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
