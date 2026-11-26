fn main() {
    // tenzro-device-key links the Swift runtime from /usr/lib/swift by @rpath
    // on Apple targets. A library's link arguments do not reach the binaries
    // that use it, so the rpath has to come from the binary itself, or the
    // executable aborts at load with "Library not loaded:
    // @rpath/libswift_Concurrency.dylib".
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    }

    // The main thread runs the whole command under the async runtime. Linux
    // and macOS give it 8 MiB; a Windows linker reserves 1 MiB unless told
    // otherwise, which a debug build overflows. Reserve the same 8 MiB there.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        match std::env::var("CARGO_CFG_TARGET_ENV").as_deref() {
            Ok("msvc") => println!("cargo:rustc-link-arg-bins=/STACK:8388608"),
            Ok("gnu") => println!("cargo:rustc-link-arg-bins=-Wl,--stack,8388608"),
            _ => {}
        }
    }
}
