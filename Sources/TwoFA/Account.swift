import Foundation

struct Account: Identifiable, Codable, Hashable {
    var id = UUID()
    var issuer: String
    var name: String
    var secret: String
    var digits: Int = 6
    var period: Int = 30
    var algorithm: OTPAlgorithm = .sha1

    var displayTitle: String {
        issuer.isEmpty ? (name.isEmpty ? "Unnamed" : name) : issuer
    }

    func code(at date: Date = Date()) -> String {
        guard let key = Base32.decode(secret) else { return String(repeating: "-", count: digits) }
        return TOTP.code(secret: key, date: date, period: period, digits: digits, algorithm: algorithm)
    }
}

extension Account {
    /// Parses `otpauth://totp/Issuer:name?secret=...&issuer=...` links (e.g. from QR codes).
    init?(otpauthURI: String) {
        guard
            let components = URLComponents(string: otpauthURI.trimmingCharacters(in: .whitespacesAndNewlines)),
            components.scheme?.lowercased() == "otpauth",
            components.host?.lowercased() == "totp"
        else { return nil }

        let query = Dictionary(
            (components.queryItems ?? []).map { ($0.name.lowercased(), $0.value ?? "") },
            uniquingKeysWith: { first, _ in first }
        )
        guard let secret = query["secret"], Base32.decode(secret) != nil else { return nil }

        let label = String(components.path.drop(while: { $0 == "/" }))
        let parts = label.split(separator: ":", maxSplits: 1).map {
            $0.trimmingCharacters(in: .whitespaces)
        }
        let labelIssuer = parts.count == 2 ? parts[0] : ""
        let labelName = parts.last ?? ""

        self.init(
            issuer: query["issuer"].flatMap { $0.isEmpty ? nil : $0 } ?? labelIssuer,
            name: labelName,
            secret: Base32.normalize(secret)
        )
        if let digits = query["digits"].flatMap(Int.init), (6...8).contains(digits) {
            self.digits = digits
        }
        if let period = query["period"].flatMap(Int.init), period > 0 {
            self.period = period
        }
        if let algorithm = query["algorithm"].flatMap({ OTPAlgorithm(rawValue: $0.uppercased()) }) {
            self.algorithm = algorithm
        }
    }
}

extension Account {
    /// The standard `otpauth://` link for this account, understood by most authenticator apps.
    var otpauthURI: String {
        var components = URLComponents()
        components.scheme = "otpauth"
        components.host = "totp"
        components.path = "/" + (issuer.isEmpty ? name : "\(issuer):\(name)")
        var query = [URLQueryItem(name: "secret", value: secret)]
        if !issuer.isEmpty {
            query.append(URLQueryItem(name: "issuer", value: issuer))
        }
        query += [
            URLQueryItem(name: "algorithm", value: algorithm.rawValue),
            URLQueryItem(name: "digits", value: String(digits)),
            URLQueryItem(name: "period", value: String(period)),
        ]
        components.queryItems = query
        return components.string ?? ""
    }
}
