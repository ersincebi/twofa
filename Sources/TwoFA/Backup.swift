import AppKit
import UniformTypeIdentifiers

/// Plain-text backups: one `otpauth://` link per line, importable by most authenticator apps.
@MainActor
enum Backup {
    static func export(_ accounts: [Account]) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "TwoFA Backup.txt"
        panel.allowedContentTypes = [.plainText]
        panel.message = "This file contains your secrets unencrypted. Keep it somewhere safe."
        NSApp.activate(ignoringOtherApps: true)
        guard panel.runModal() == .OK, let url = panel.url else { return }

        let text = accounts.map(\.otpauthURI).joined(separator: "\n") + "\n"
        do {
            try text.write(to: url, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
            show("Exported \(accounts.count) account(s).")
        } catch {
            show("Export failed: \(error.localizedDescription)")
        }
    }

    static func importFile(into store: AccountStore) {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.plainText]
        NSApp.activate(ignoringOtherApps: true)
        guard panel.runModal() == .OK, let url = panel.url,
              let text = try? String(contentsOf: url, encoding: .utf8)
        else { return }

        let parsed = text.split(whereSeparator: \.isNewline).compactMap { Account(otpauthURI: String($0)) }
        let added = store.importAccounts(parsed)
        show("Imported \(added) new account(s)" + (parsed.count > added ? ", skipped \(parsed.count - added) duplicate(s)." : "."))
    }

    private static func show(_ message: String) {
        let alert = NSAlert()
        alert.messageText = message
        alert.runModal()
    }
}
