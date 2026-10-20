import Foundation

enum SyncStatus: Equatable {
    case off
    case syncing
    case synced
    case offline
    case failed(String)
}

/// Keeps accounts in a login-keychain item and, once connected, in sync with the shared web vault.
@MainActor
final class AccountStore: ObservableObject {
    @Published private(set) var accounts: [Account] = []
    /// Set when the keychain could not be read; saving is disabled so nothing gets overwritten.
    @Published private(set) var loadError: String?
    @Published private(set) var syncStatus: SyncStatus = .off

    private static let keychainAccount = "accounts"
    private static let sessionAccount = "sync-session"
    private static let versionKey = "syncVersion"

    /// Pre-keychain storage, migrated and removed on first launch.
    private let legacyFileURL = FileManager.default
        .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("TwoFA/accounts.json")

    private var session: SyncSession?
    /// Last vault contents confirmed by the server; edits are replayed on top of it.
    private var serverAccounts: [Account] = []
    private var version: Int {
        get { UserDefaults.standard.integer(forKey: Self.versionKey) }
        set { UserDefaults.standard.set(newValue, forKey: Self.versionKey) }
    }
    private var pushTask: Task<Void, Never>?

    var isSyncEnabled: Bool { session != nil }

    init() {
        load()
        if loadError == nil, case .found(let data) = Keychain.read(Self.sessionAccount) {
            session = try? JSONDecoder().decode(SyncSession.self, from: data)
        }
        if session != nil {
            serverAccounts = accounts
            syncStatus = .offline
            Task { await sync() }
        }
        Timer.scheduledTimer(withTimeInterval: 300, repeats: true) { [weak self] _ in
            Task { await self?.sync() }
        }
    }

    // MARK: Editing

    func upsert(_ account: Account) {
        apply { list in
            if let index = list.firstIndex(where: { $0.id == account.id }) {
                list[index] = account
            } else {
                list.append(account)
            }
        }
    }

    func delete(_ account: Account) {
        apply { list in list.removeAll { $0.id == account.id } }
    }

    func move(_ account: Account, by offset: Int) {
        apply { list in
            guard let index = list.firstIndex(where: { $0.id == account.id }) else { return }
            let target = index + offset
            guard list.indices.contains(target) else { return }
            list.swapAt(index, target)
        }
    }

    /// Adds accounts whose secret isn't already present. Returns how many were added.
    @discardableResult
    func importAccounts(_ incoming: [Account]) -> Int {
        let fresh = Self.missing(incoming, from: accounts)
        if !fresh.isEmpty {
            apply { list in list += Self.missing(fresh, from: list) }
        }
        return fresh.count
    }

    private static func missing(_ incoming: [Account], from list: [Account]) -> [Account] {
        incoming.filter { account in !list.contains { $0.secret == account.secret } }
    }

    /// Applies an edit locally right away and, when syncing, pushes it to the vault in order.
    private func apply(_ change: @escaping (inout [Account]) -> Void) {
        guard loadError == nil else { return }
        change(&accounts)
        save()
        guard session != nil else { return }
        let previous = pushTask
        pushTask = Task {
            await previous?.value
            await push(change)
        }
    }

    // MARK: Sync

    func connect(password: String) async throws {
        guard let salt = try await VaultClient().salt() else { throw SyncError.noVault }
        let newSession = try await Task.detached {
            try VaultCrypto.deriveSession(password: password, salt: salt)
        }.value
        let client = VaultClient(token: newSession.authToken)
        var (newVersion, data) = try await client.fetch()
        var remote = try data.map { try VaultCrypto.decrypt($0, key: newSession.encKey) } ?? []

        // Accounts that so far only lived on this Mac go up first, so nothing is lost if this fails.
        let localOnly = Self.missing(accounts, from: remote)
        if !localOnly.isEmpty {
            remote += localOnly
            newVersion = try await client.put(version: newVersion, data: VaultCrypto.encrypt(remote, key: newSession.encKey))
        }

        Keychain.write(try JSONEncoder().encode(newSession), account: Self.sessionAccount)
        session = newSession
        version = newVersion
        serverAccounts = remote
        accounts = remote
        save()
        syncStatus = .synced
    }

    func disconnect() {
        Keychain.delete(Self.sessionAccount)
        session = nil
        syncStatus = .off
    }

    func sync() async {
        guard let session, loadError == nil else { return }
        await pushTask?.value
        syncStatus = .syncing
        do {
            let (remoteVersion, data) = try await VaultClient(token: session.authToken).fetch()
            if remoteVersion != version || accounts != serverAccounts {
                try adopt(version: remoteVersion, data: data)
            }
            syncStatus = .synced
        } catch {
            handle(error)
        }
    }

    private func push(_ change: (inout [Account]) -> Void) async {
        guard let session else { return }
        syncStatus = .syncing
        let client = VaultClient(token: session.authToken)
        for _ in 0..<3 {
            var next = serverAccounts
            change(&next)
            do {
                version = try await client.put(version: version, data: VaultCrypto.encrypt(next, key: session.encKey))
                serverAccounts = next
                accounts = next
                save()
                syncStatus = .synced
                return
            } catch SyncError.conflict(let remoteVersion, let data) {
                do {
                    try adopt(version: remoteVersion, data: data)
                } catch {
                    break
                }
            } catch {
                // Roll back to what the server has, like the web app does.
                accounts = serverAccounts
                save()
                handle(error)
                if case .offline = syncStatus { syncStatus = .failed("Offline — change not saved.") }
                return
            }
        }
        accounts = serverAccounts
        save()
        syncStatus = .failed("Couldn't save the change. Try again.")
    }

    private func adopt(version remoteVersion: Int, data: String?) throws {
        guard let session else { return }
        serverAccounts = try data.map { try VaultCrypto.decrypt($0, key: session.encKey) } ?? []
        version = remoteVersion
        accounts = serverAccounts
        save()
    }

    private func handle(_ error: Error) {
        switch error {
        case SyncError.offline:
            syncStatus = .offline
        case SyncError.wrongPassword:
            disconnect()
            syncStatus = .failed("The vault password changed. Connect again.")
        default:
            syncStatus = .failed(error.localizedDescription)
        }
    }

    // MARK: Keychain storage

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
