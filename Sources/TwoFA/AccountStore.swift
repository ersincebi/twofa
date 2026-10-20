import Foundation

/// Persists accounts as JSON in ~/Library/Application Support/TwoFA (owner read/write only).
@MainActor
final class AccountStore: ObservableObject {
    @Published private(set) var accounts: [Account] = []

    private let fileURL: URL

    init() {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let directory = support.appendingPathComponent("TwoFA", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        fileURL = directory.appendingPathComponent("accounts.json")
        load()
    }

    func upsert(_ account: Account) {
        if let index = accounts.firstIndex(where: { $0.id == account.id }) {
            accounts[index] = account
        } else {
            accounts.append(account)
        }
        save()
    }

    func delete(_ account: Account) {
        accounts.removeAll { $0.id == account.id }
        save()
    }

    func move(_ account: Account, by offset: Int) {
        guard let index = accounts.firstIndex(where: { $0.id == account.id }) else { return }
        let target = index + offset
        guard accounts.indices.contains(target) else { return }
        accounts.swapAt(index, target)
        save()
    }

    private func load() {
        guard let data = try? Data(contentsOf: fileURL) else { return }
        accounts = (try? JSONDecoder().decode([Account].self, from: data)) ?? []
    }

    private func save() {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(accounts) else { return }
        do {
            try data.write(to: fileURL, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
        } catch {
            NSLog("TwoFA: failed to save accounts: \(error)")
        }
    }
}
