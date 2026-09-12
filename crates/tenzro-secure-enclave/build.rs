// Emit the Swift runtime rpath.
//
// This crate transitively links the CryptoKit shim in `tenzro-device-key`, and
// those Swift dylibs record `@rpath` install names. Without this the crate links
// cleanly and then aborts at startup with
// "Library not loaded: @rpath/libswift_Concurrency.dylib".
//
// It has to be repeated here rather than inherited: `cargo:rustc-link-arg` does
// not propagate to dependents, `-static-stdlib` is rejected on Apple platforms,
// and `links` metadata is not delivered for a target-gated dependency (cargo
// passes no DEP_* variables at all — verified).
fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os == "macos" || os == "ios" {
        println!("cargo:rustc-link-search=native=/usr/lib/swift");
        println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    }
}
