import CoreImage
import XCTest
@testable import TwoFA

final class TOTPTests: XCTestCase {
    /// Test vectors from RFC 6238 Appendix B (8 digits, 30 s period).
    func testRFC6238Vectors() {
        let keys: [OTPAlgorithm: Data] = [
            .sha1: Data("12345678901234567890".utf8),
            .sha256: Data("12345678901234567890123456789012".utf8),
            .sha512: Data("1234567890123456789012345678901234567890123456789012345678901234".utf8),
        ]
        let vectors: [(TimeInterval, [OTPAlgorithm: String])] = [
            (59, [.sha1: "94287082", .sha256: "46119246", .sha512: "90693936"]),
            (1_111_111_109, [.sha1: "07081804", .sha256: "68084774", .sha512: "25091201"]),
            (1_111_111_111, [.sha1: "14050471", .sha256: "67062674", .sha512: "99943326"]),
            (1_234_567_890, [.sha1: "89005924", .sha256: "91819424", .sha512: "93441116"]),
            (2_000_000_000, [.sha1: "69279037", .sha256: "90698825", .sha512: "38618901"]),
            (20_000_000_000, [.sha1: "65353130", .sha256: "77737706", .sha512: "47863826"]),
        ]
        for (time, expected) in vectors {
            for (algorithm, code) in expected {
                let actual = TOTP.code(
                    secret: keys[algorithm]!, date: Date(timeIntervalSince1970: time),
                    digits: 8, algorithm: algorithm
                )
                XCTAssertEqual(actual, code, "\(algorithm) at \(time)")
            }
        }
    }

    func testSecondsRemaining() {
        XCTAssertEqual(TOTP.secondsRemaining(period: 30, date: Date(timeIntervalSince1970: 59)), 1)
        XCTAssertEqual(TOTP.secondsRemaining(period: 30, date: Date(timeIntervalSince1970: 60)), 30)
    }
}

final class Base32Tests: XCTestCase {
    func testDecodesAndIgnoresFormatting() {
        let expected = Data("12345678901234567890".utf8)
        XCTAssertEqual(Base32.decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"), expected)
        XCTAssertEqual(Base32.decode("gezd gnbv-gy3t qojq gezd gnbv gy3t qojq===="), expected)
    }

    func testRejectsInvalidInput() {
        XCTAssertNil(Base32.decode(""))
        XCTAssertNil(Base32.decode("NOT-BASE32-1!"))
    }
}

final class OTPAuthTests: XCTestCase {
    func testParsesLink() throws {
        let account = try XCTUnwrap(Account(otpauthURI:
            "otpauth://totp/ACME%20Co:john@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60"))
        XCTAssertEqual(account.issuer, "ACME Co")
        XCTAssertEqual(account.name, "john@example.com")
        XCTAssertEqual(account.secret, "JBSWY3DPEHPK3PXP")
        XCTAssertEqual(account.algorithm, .sha256)
        XCTAssertEqual(account.digits, 8)
        XCTAssertEqual(account.period, 60)
    }

    func testRejectsNonTOTP() {
        XCTAssertNil(Account(otpauthURI: "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP"))
        XCTAssertNil(Account(otpauthURI: "https://example.com"))
        XCTAssertNil(Account(otpauthURI: "otpauth://totp/x?secret=!!!"))
    }

    func testRoundTrip() throws {
        var original = Account(issuer: "My Bank", name: "me@example.com", secret: "JBSWY3DPEHPK3PXP")
        original.digits = 8
        original.algorithm = .sha512
        let parsed = try XCTUnwrap(Account(otpauthURI: original.otpauthURI))
        XCTAssertEqual(parsed.issuer, original.issuer)
        XCTAssertEqual(parsed.name, original.name)
        XCTAssertEqual(parsed.secret, original.secret)
        XCTAssertEqual(parsed.digits, original.digits)
        XCTAssertEqual(parsed.algorithm, original.algorithm)
    }
}

final class QRCodeTests: XCTestCase {
    func testReadsGeneratedQRCode() throws {
        let link = "otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
        let filter = try XCTUnwrap(CIFilter(name: "CIQRCodeGenerator"))
        filter.setValue(Data(link.utf8), forKey: "inputMessage")
        let image = try XCTUnwrap(filter.outputImage).transformed(by: CGAffineTransform(scaleX: 10, y: 10))
        XCTAssertEqual(QRCode.messages(in: image), [link])
    }
}

final class VaultCryptoTests: XCTestCase {
    /// Produced by web/public/crypto.js, so both apps must agree on keys and format.
    private let salt = "AAECAwQFBgcICQoLDA0ODw=="
    private let webAuthToken = "6oGlDNHGAZQmuV5AwE4KnTDuLtDccn8uSbDFaknmYUQ="
    private let webData = "9aIGKfsqqXOKYJk7D5cF2O7hoUXOfCTEzMHAyfI+WsjZvG8E2kFseD0oOINV+W0yxUoaVOrD9uUuqV3aKANf/GiWBaIrdCshetJTE+G+akX/wFapu+YUbZUWgvz/K/+YhF5WjT7lOgZ5s94yUfVKHHURDN4Ov5qVRODSL4OhTS9Xga+SDG+ETwwoZdF3kF4cDQftDua2P/5rADUnCJ4yxQiL9MOZVOy9906K4+8AJ09FIq5eiZGgOzx8+Krk7EbJqjoygfiUIzY="

    func testMatchesWebApp() throws {
        let session = try VaultCrypto.deriveSession(password: "correct horse battery staple", salt: salt)
        XCTAssertEqual(session.authToken, webAuthToken)

        let accounts = try VaultCrypto.decrypt(webData, key: session.encKey)
        XCTAssertEqual(accounts.count, 1)
        XCTAssertEqual(accounts[0].issuer, "GitHub")
        XCTAssertEqual(accounts[0].secret, "JBSWY3DPEHPK3PXP")
        XCTAssertEqual(accounts[0].id.uuidString.lowercased(), "6f1c2a7e-3b4d-4e5f-8a9b-0c1d2e3f4a5b")

        let roundTrip = try VaultCrypto.decrypt(VaultCrypto.encrypt(accounts, key: session.encKey), key: session.encKey)
        XCTAssertEqual(roundTrip, accounts)
    }

    func testWrongPasswordFails() throws {
        let wrong = try VaultCrypto.deriveSession(password: "nope", salt: salt)
        XCTAssertNotEqual(wrong.authToken, webAuthToken)
        XCTAssertThrowsError(try VaultCrypto.decrypt(webData, key: wrong.encKey))
    }
}

/// Runs against `wrangler dev` when TWOFA_TEST_SERVER is set (e.g. http://localhost:8799).
final class VaultClientIntegrationTests: XCTestCase {
    func testCreateReadWriteConflict() async throws {
        guard let server = ProcessInfo.processInfo.environment["TWOFA_TEST_SERVER"].flatMap(URL.init(string:)) else {
            throw XCTSkip("TWOFA_TEST_SERVER not set")
        }
        let anonymous = VaultClient(token: nil, baseURL: server)
        let initialSalt = try await anonymous.salt()
        XCTAssertNil(initialSalt)

        // Create the vault the way the web app does (first write claims it).
        let salt = Data((0..<16).map { _ in UInt8.random(in: 0...255) }).base64EncodedString()
        let session = try VaultCrypto.deriveSession(password: "integration test pw", salt: salt)
        var request = URLRequest(url: server.appendingPathComponent("/api/vault"))
        request.httpMethod = "PUT"
        request.setValue("Bearer \(session.authToken)", forHTTPHeaderField: "Authorization")
        request.httpBody = try JSONSerialization.data(withJSONObject: [
            "version": 0, "data": try VaultCrypto.encrypt([], key: session.encKey), "salt": salt,
        ])
        let (_, response) = try await URLSession.shared.data(for: request)
        XCTAssertEqual((response as? HTTPURLResponse)?.statusCode, 200)
        let storedSalt = try await anonymous.salt()
        XCTAssertEqual(storedSalt, salt)

        let client = VaultClient(token: session.authToken, baseURL: server)
        let (version, data) = try await client.fetch()
        XCTAssertEqual(version, 1)
        XCTAssertEqual(try VaultCrypto.decrypt(try XCTUnwrap(data), key: session.encKey), [])

        let account = Account(issuer: "GitHub", name: "me", secret: "JBSWY3DPEHPK3PXP")
        let v2 = try await client.put(version: 1, data: VaultCrypto.encrypt([account], key: session.encKey))
        XCTAssertEqual(v2, 2)

        do {
            _ = try await client.put(version: 1, data: VaultCrypto.encrypt([], key: session.encKey))
            XCTFail("stale write should conflict")
        } catch SyncError.conflict(let current, let currentData) {
            XCTAssertEqual(current, 2)
            XCTAssertEqual(try VaultCrypto.decrypt(try XCTUnwrap(currentData), key: session.encKey), [account])
        }

        let wrong = try VaultCrypto.deriveSession(password: "wrong", salt: salt)
        do {
            _ = try await VaultClient(token: wrong.authToken, baseURL: server).fetch()
            XCTFail("wrong password should be rejected")
        } catch SyncError.wrongPassword {}
    }
}
