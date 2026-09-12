// Emit the Swift runtime rpath.
//
// This crate transitively links the CryptoKit shim in `tenzro-device-key` (via
// tenzro-tee → tenzro-secure-enclave). Those Swift dylibs record `@rpath`
// install names, and `cargo:rustc-link-arg` does not propagate from a
// dependency to its dependents, so every crate in the chain has to emit this
// itself or its test binary links cleanly and then aborts with
// "Library not loaded: @rpath/libswift_Concurrency.dylib".
fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os == "macos" || os == "ios" {
        println!("cargo:rustc-link-search=native=/usr/lib/swift");
        println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    }
}
