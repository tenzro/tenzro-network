fn main() {
    // tenzro-device-key links the Swift runtime from /usr/lib/swift by @rpath
    // on Apple targets. A library's link arguments do not reach the binaries
    // that use it, so the rpath has to come from the binary itself, or the
    // executable aborts at load with "Library not loaded:
    // @rpath/libswift_Concurrency.dylib".
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    }
}
