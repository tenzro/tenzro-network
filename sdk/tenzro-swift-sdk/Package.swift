// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "TenzroSDK",
    // Minimums are a judgment call (modern async/await + Observation), not
    // verified against any compatibility requirement.
    platforms: [.iOS(.v17), .macOS(.v14), .visionOS(.v1)],
    products: [
        .library(name: "TenzroSDK", targets: ["TenzroSDK"]),
    ],
    dependencies: [
        // CryptoKit's API on every platform; on Apple platforms it is CryptoKit.
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"6.0.0"),
    ],
    targets: [
        .target(name: "TenzroSDK", dependencies: [.product(name: "Crypto", package: "swift-crypto")]),
        .testTarget(name: "TenzroSDKTests", dependencies: ["TenzroSDK"]),
    ],
    swiftLanguageModes: [.v6]
)
