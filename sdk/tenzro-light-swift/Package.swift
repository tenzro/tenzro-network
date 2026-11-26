// swift-tools-version:6.0
// The Tenzro light client for Swift: the bindings of sdk/tenzro-ffi,
// generated from the built library by ./bindings.sh. The tests link the
// host's build of the library and replay the shared fixture.
//
// Preview: the surface may change before it is stable.

import PackageDescription

let package = Package(
    name: "TenzroLight",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [
        .library(name: "TenzroLight", targets: ["TenzroLight"]),
    ],
    targets: [
        .target(
            name: "TenzroLightFFI",
            linkerSettings: [
                .linkedLibrary("tenzro_ffi"),
                .unsafeFlags(["-L../../target/release"]),
            ]
        ),
        .target(name: "TenzroLight", dependencies: ["TenzroLightFFI"]),
        .testTarget(name: "TenzroLightTests", dependencies: ["TenzroLight"]),
    ]
)
