import Foundation

/// Persists accounts as JSON in a single login-keychain item.
@MainActor
final class AccountStore: ObservableObject {
    @Published private(set) var accounts: [Account] = []
    /// Set when the keychain could not be read; saving is disabled so nothing gets overwritten.
    @Published private(set) var loadError: String?

    private static let keychainAccount = "accounts"

    /// Pre-keychain storage, migrated and removed on first launch.
    private let legacyFileURL = FileManager.default
        .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("TwoFA/accounts.json")

    init() {
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

    /// Adds accounts whose secret isn't already present. Returns how many were added.
    @discardableResult
    func importAccounts(_ incoming: [Account]) -> Int {
        var added = 0
        for account in incoming where !accounts.contains(where: { $0.secret == account.secret }) {
            accounts.append(account)
            added += 1
        }
        if added > 0 { save() }
        return added
    }

    private func load() {
        switch Keychain.read(Self.keychainAccount) {
        case .found(let data):
            accounts = (try? JSONDecoder().decode([Account].self, from: data)) ?? []
        case .notFound:
            migrateLegacyFile()
        case .failed(let status):
            loadError = "Couldn't read the keychain (error \(status)). Reopen TwoFA and allow access."
            NSLog("TwoFA: keychain read failed: \(status)")
        }
    }

    private func migrateLegacyFile() {
        guard let data = try? Data(contentsOf: legacyFileURL),
              let legacy = try? JSONDecoder().decode([Account].self, from: data)
        else { return }
        accounts = legacy
        save()
        // Only drop the plaintext file once the keychain copy reads back intact.
        if case .found(let stored) = Keychain.read(Self.keychainAccount),
           (try? JSONDecoder().decode([Account].self, from: stored)) == legacy {
            try? FileManager.default.removeItem(at: legacyFileURL)
        }
    }

    private func save() {
        guard loadError == nil else { return }
        guard let data = try? JSONEncoder().encode(accounts) else { return }
        let status = Keychain.write(data, account: Self.keychainAccount)
        if status != errSecSuccess {
            NSLog("TwoFA: keychain write failed: \(status)")
        }
    }
}
