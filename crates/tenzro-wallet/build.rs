// Emit the Swift runtime rpath when device-custody-se links the CryptoKit shim.
//
// The Swift dylibs record `@rpath` install names and `cargo:rustc-link-arg`
// does not propagate from a dependency to its dependents, so every crate that
// transitively links `tenzro-device-key` has to emit this itself or its test
// binary links cleanly and then aborts with
// "Library not loaded: @rpath/libswift_Concurrency.dylib".
//
// Gated on the feature as well as the target: without `device-custody-se` the
// shim is not linked at all and the rpath would be noise.
fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let se = std::env::var("CARGO_FEATURE_DEVICE_CUSTODY_SE").is_ok();
    if se && (os == "macos" || os == "ios") {
        println!("cargo:rustc-link-search=native=/usr/lib/swift");
        println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    }
}
