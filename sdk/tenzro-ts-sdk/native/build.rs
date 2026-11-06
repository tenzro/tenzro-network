fn main() {
    napi_build::setup();
    // tenzro-device-key links the Swift runtime from /usr/lib/swift by @rpath
    // on Apple targets, and the rpath has to come from the final binary.
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    }
}
