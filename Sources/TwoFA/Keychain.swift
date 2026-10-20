import Foundation
import Security

/// Minimal wrapper around a single generic-password item in the login keychain.
enum Keychain {
    enum ReadResult {
        case found(Data)
        case notFound
        case failed(OSStatus)
    }

    private static let service = "com.ersincebi.twofa"

    private static func baseQuery(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    static func read(_ account: String) -> ReadResult {
        var query = baseQuery(account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            return .found(item as? Data ?? Data())
        case errSecItemNotFound:
            return .notFound
        default:
            return .failed(status)
        }
    }

    static func delete(_ account: String) {
        SecItemDelete(baseQuery(account) as CFDictionary)
    }

    @discardableResult
    static func write(_ data: Data, account: String) -> OSStatus {
        let query = baseQuery(account)
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        guard status == errSecItemNotFound else { return status }

        var item = query
        item[kSecValueData as String] = data
        item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked
        item[kSecAttrLabel as String] = "TwoFA \(account)"
        return SecItemAdd(item as CFDictionary, nil)
    }
}
