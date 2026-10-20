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
