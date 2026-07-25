import AppKit
import Foundation

/// First-run setup.
///
/// `fingerlock init` does the same work from a terminal, but someone who installs
/// the package and right-clicks a file has no terminal in the loop. Both paths end
/// up in `Recovery.create` and `Enclave.create`.
final class SetupWindow: NSObject, NSWindowDelegate {
    private let window: NSWindow
    private let passphrase = NSSecureTextField()
    private let confirm = NSSecureTextField()
    private let status = NSTextField(labelWithString: "")
    private let createButton = NSButton()
    private var onFinish: ((Bool) -> Void)?

    override init() {
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 460, height: 300),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        super.init()
        window.title = "Fingerlock Setup"
        window.delegate = self
        window.center()
        build()
    }

    /// Shows the window and calls back with whether keys now exist.
    func run(_ completion: @escaping (Bool) -> Void) {
        onFinish = completion
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        window.makeFirstResponder(passphrase)
    }

    private func build() {
        let content = NSView(frame: window.contentRect(forFrameRect: window.frame))
        window.contentView = content

        let heading = NSTextField(labelWithString: "Choose a recovery passphrase")
        heading.font = .systemFont(ofSize: 15, weight: .semibold)

        let blurb = NSTextField(wrappingLabelWithString: """
            Sealed files open with your fingerprint. The passphrase is the other way \
            in — it works if this Mac's enrolled fingerprints change, or on a \
            different machine. Store it somewhere you'll still have it later.
            """)
        blurb.font = .systemFont(ofSize: 12)
        blurb.textColor = .secondaryLabelColor

        let passLabel = NSTextField(labelWithString: "Passphrase")
        let confirmLabel = NSTextField(labelWithString: "Confirm")
        for f in [passphrase, confirm] {
            f.bezelStyle = .roundedBezel
            f.target = self
            f.action = #selector(create)
        }

        status.font = .systemFont(ofSize: 11)
        status.textColor = .secondaryLabelColor

        createButton.title = "Create Keys"
        createButton.bezelStyle = .rounded
        createButton.keyEquivalent = "\r"
        createButton.target = self
        createButton.action = #selector(create)

        let grid = NSGridView(views: [
            [passLabel, passphrase],
            [confirmLabel, confirm],
        ])
        grid.column(at: 0).xPlacement = .trailing
        grid.rowSpacing = 8
        grid.columnSpacing = 8

        let stack = NSStackView(views: [heading, blurb, grid, status, createButton])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 14
        stack.edgeInsets = NSEdgeInsets(top: 24, left: 24, bottom: 24, right: 24)
        stack.translatesAutoresizingMaskIntoConstraints = false
        content.addSubview(stack)

        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            stack.topAnchor.constraint(equalTo: content.topAnchor),
            passphrase.widthAnchor.constraint(equalToConstant: 260),
        ])
    }

    @objc private func create() {
        let a = passphrase.stringValue
        let b = confirm.stringValue

        guard a.count >= 8 else { return fail("Use at least 8 characters.") }
        guard a == b else { return fail("The two passphrases don't match.") }

        status.textColor = .secondaryLabelColor
        status.stringValue = "Creating keys…"
        createButton.isEnabled = false

        do {
            if !Recovery.exists() { _ = try Recovery.create(passphrase: a) }
            if !Enclave.exists() { _ = try Enclave.create() }
        } catch {
            createButton.isEnabled = true
            return fail("\(error)")
        }

        passphrase.stringValue = ""
        confirm.stringValue = ""
        finish(true)
    }

    private func fail(_ message: String) {
        status.textColor = .systemRed
        status.stringValue = message
    }

    private func finish(_ ok: Bool) {
        window.orderOut(nil)
        NSApp.setActivationPolicy(.accessory)
        let cb = onFinish
        onFinish = nil
        cb?(ok)
    }

    func windowWillClose(_ notification: Notification) {
        guard onFinish != nil else { return }
        finish(Enclave.exists() && Recovery.exists())
    }
}

/// True when there is nothing to set up.
func setupComplete() -> Bool {
    Enclave.exists() && Recovery.exists()
}
