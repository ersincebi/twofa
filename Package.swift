// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "TwoFA",
    platforms: [.macOS(.v13)],
    targets: [
        .executableTarget(name: "TwoFA", path: "Sources/TwoFA"),
        .testTarget(name: "TwoFATests", dependencies: ["TwoFA"], path: "Tests/TwoFATests"),
    ]
)
