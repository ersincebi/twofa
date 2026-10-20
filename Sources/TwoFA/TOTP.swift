import CryptoKit
import Foundation

enum OTPAlgorithm: String, Codable, CaseIterable, Identifiable {
    case sha1 = "SHA1"
    case sha256 = "SHA256"
    case sha512 = "SHA512"

    var id: String { rawValue }
}

enum Base32 {
    private static let lookup: [Character: UInt32] = {
        var table: [Character: UInt32] = [:]
        for (index, char) in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".enumerated() {
            table[char] = UInt32(index)
        }
        return table
    }()

    /// Strips spaces, dashes and padding so secrets copied from websites just work.
    static func normalize(_ string: String) -> String {
        string.uppercased().filter { !$0.isWhitespace && $0 != "-" && $0 != "=" }
    }

    static func decode(_ string: String) -> Data? {
        let cleaned = normalize(string)
        guard !cleaned.isEmpty else { return nil }

        var buffer: UInt32 = 0
        var bitCount = 0
        var output = Data()
        for char in cleaned {
            guard let value = lookup[char] else { return nil }
            buffer = (buffer << 5) | value
            bitCount += 5
            if bitCount >= 8 {
                bitCount -= 8
                output.append(UInt8((buffer >> UInt32(bitCount)) & 0xFF))
            }
        }
        return output.isEmpty ? nil : output
    }
}

/// RFC 6238 time-based one-time password generator.
enum TOTP {
    static func code(
        secret: Data,
        date: Date = Date(),
        period: Int = 30,
        digits: Int = 6,
        algorithm: OTPAlgorithm = .sha1
    ) -> String {
        let counter = UInt64(date.timeIntervalSince1970) / UInt64(period)
        let message = withUnsafeBytes(of: counter.bigEndian) { Data($0) }
        let key = SymmetricKey(data: secret)

        let mac: [UInt8]
        switch algorithm {
        case .sha1:
            mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
        case .sha256:
            mac = Array(HMAC<SHA256>.authenticationCode(for: message, using: key))
        case .sha512:
            mac = Array(HMAC<SHA512>.authenticationCode(for: message, using: key))
        }

        // Dynamic truncation (RFC 4226 section 5.3).
        let offset = Int(mac[mac.count - 1] & 0x0F)
        let truncated = mac[offset..<offset + 4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) } & 0x7FFF_FFFF
        var modulus: UInt32 = 1
        for _ in 0..<digits { modulus *= 10 }

        let value = String(truncated % modulus)
        return String(repeating: "0", count: max(0, digits - value.count)) + value
    }

    static func secondsRemaining(period: Int = 30, date: Date = Date()) -> Int {
        period - Int(date.timeIntervalSince1970) % period
    }
}
