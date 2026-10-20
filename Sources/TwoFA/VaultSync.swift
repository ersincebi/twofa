import CommonCrypto
import CryptoKit
import Foundation

// Same vault format as the web app (web/public/crypto.js): PBKDF2-SHA256 (600k) → HKDF-SHA256 splits
// into an AES-256-GCM key that never leaves the device and an auth token the server stores as a hash.

/// What gets kept in the keychain once this Mac is connected. No password is stored.
struct SyncSession: Codable {
    var encKey: Data
    var authToken: String
}

enum SyncError: LocalizedError {
    case noVault
    case wrongPassword
    case locked
    case offline
    case conflict(version: Int, data: String?)
    case server(Int)
    case corrupt

    var errorDescription: String? {
        switch self {
        case .noVault: return "No vault yet. Create it at 2fa.ersincebi.com first."
        case .wrongPassword: return "Wrong password."
        case .locked: return "Too many attempts. Try again in 15 minutes."
        case .offline: return "Can't reach the sync server."
        case .conflict: return "The vault changed on another device. Try again."
        case .server(let status): return "Sync server error (\(status))."
        case .corrupt: return "Couldn't read the vault."
        }
    }
}

private struct VaultPayload: Codable {
    var accounts: [Account]
}

enum VaultCrypto {
    static let iterations: UInt32 = 600_000

    static func deriveSession(password: String, salt: String) throws -> SyncSession {
        guard let saltData = Data(base64Encoded: salt) else { throw SyncError.corrupt }
        let passwordBytes = Array(password.utf8)
        var master = [UInt8](repeating: 0, count: 32)
        let status = saltData.withUnsafeBytes { saltBuffer in
            passwordBytes.withUnsafeBufferPointer { passwordBuffer in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    UnsafeRawPointer(passwordBuffer.baseAddress)?.assumingMemoryBound(to: CChar.self),
                    passwordBytes.count,
                    saltBuffer.bindMemory(to: UInt8.self).baseAddress,
                    saltData.count,
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                    iterations,
                    &master,
                    master.count
                )
            }
        }
        guard status == kCCSuccess else { throw SyncError.corrupt }

        let inputKey = SymmetricKey(data: master)
        func expand(_ label: String) -> Data {
            HKDF<SHA256>.deriveKey(inputKeyMaterial: inputKey, salt: Data(), info: Data(label.utf8), outputByteCount: 32)
                .withUnsafeBytes { Data($0) }
        }
        return SyncSession(encKey: expand("twofa-encryption"), authToken: expand("twofa-auth").base64EncodedString())
    }

    /// Returns base64(nonce || ciphertext || tag), the layout WebCrypto's AES-GCM produces.
    static func encrypt(_ accounts: [Account], key: Data) throws -> String {
        let plaintext = try JSONEncoder().encode(VaultPayload(accounts: accounts))
        guard let combined = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key)).combined else {
            throw SyncError.corrupt
        }
        return combined.base64EncodedString()
    }

    static func decrypt(_ data: String, key: Data) throws -> [Account] {
        guard let combined = Data(base64Encoded: data),
              let box = try? AES.GCM.SealedBox(combined: combined),
              let plaintext = try? AES.GCM.open(box, using: SymmetricKey(data: key)),
              let payload = try? JSONDecoder().decode(VaultPayload.self, from: plaintext)
        else { throw SyncError.corrupt }
        return payload.accounts
    }
}

/// Talks to the Worker in web/src/worker.js.
struct VaultClient {
    static let defaultURL = URL(string: "https://2fa.ersincebi.com")!

    var token: String?
    var baseURL = Self.defaultURL

    func salt() async throws -> String? {
        let (_, json) = try await send("GET", "/api/salt")
        return json["salt"] as? String
    }

    func fetch() async throws -> (version: Int, data: String?) {
        let (status, json) = try await send("GET", "/api/vault")
        guard status == 200, let version = json["version"] as? Int else { throw SyncError.server(status) }
        return (version, json["data"] as? String)
    }

    /// Compare-and-set write; throws `.conflict` with the newer server copy when `version` is stale.
    func put(version: Int, data: String) async throws -> Int {
        let (status, json) = try await send("PUT", "/api/vault", body: ["version": version, "data": data])
        if status == 409, let current = json["version"] as? Int {
            throw SyncError.conflict(version: current, data: json["data"] as? String)
        }
        guard status == 200, let newVersion = json["version"] as? Int else { throw SyncError.server(status) }
        return newVersion
    }

    private func send(_ method: String, _ path: String, body: [String: Any]? = nil) async throws -> (Int, [String: Any]) {
        var request = URLRequest(url: baseURL.appendingPathComponent(path), timeoutInterval: 15)
        request.httpMethod = method
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let token {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        if let body {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await URLSession.shared.data(for: request)
        } catch {
            throw SyncError.offline
        }
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        if status == 401 { throw SyncError.wrongPassword }
        if status == 429 { throw SyncError.locked }
        let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
        return (status, json)
    }
}
