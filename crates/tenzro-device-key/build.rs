// Compiles the CryptoKit shim (swift/TenzroSE.swift) into a static library and
// links it. Apple targets only — every other platform builds with no Swift
// toolchain involved and no behaviour change.
//
// Why a Swift shim at all: CryptoKit's SecureEnclave API is the only route that
// persists a Secure Enclave key without an Apple provisioning profile, and it
// has no C or Objective-C entry point. See src/backend_se.rs.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "macos" && target_os != "ios" {
        return;
    }

    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("swift/TenzroSE.swift");
    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-env-changed=TENZRO_SWIFTC");

    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let lib = out.join("libtenzrose.a");

    let swiftc = locate_swiftc();
    let target = swift_target(&target_os);

    let mut cmd = Command::new(&swiftc);
    cmd.args(["-O", "-parse-as-library", "-emit-library", "-static"])
        .args(["-module-name", "TenzroSE"])
        .args(["-target", &target]);

    // The Command Line Tools toolchain cannot infer its own SDK and fails with
    // "unable to load standard library" unless -sdk is explicit. Xcode's swiftc
    // does not need it, but passing it is harmless there.
    if let Some(sdk) = locate_sdk(&target_os) {
        cmd.args(["-sdk", &sdk]);
    }

    let status = cmd
        .arg("-o")
        .arg(&lib)
        .arg(&src)
        .status()
        .unwrap_or_else(|e| panic!("failed to run {}: {e}", swiftc.display()));

    assert!(status.success(), "swiftc failed building {}", src.display());
    assert!(
        lib.exists(),
        "swiftc reported success but {} is missing",
        lib.display()
    );

    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=tenzrose");

    // The Swift runtime ships with the OS, so link it dynamically.
    //
    // ⚠ These dylibs record `@rpath` install names, so every binary that
    // transitively links this crate needs an rpath to /usr/lib/swift or it links
    // cleanly and then dies at startup with "Library not loaded:
    // @rpath/libswift_Concurrency.dylib".
    //
    // `cargo:rustc-link-arg` does NOT propagate to dependents and
    // `-static-stdlib` is rejected on Apple platforms, so the runtime can be
    // neither inherited nor baked in. Every crate that transitively links this
    // shim therefore emits this same rpath from its own build script — see
    // tenzro-secure-enclave/build.rs. Publishing it as `links` metadata does
    // not help: this is a target-gated dependency, so cargo hands dependents no
    // DEP_* variables to read (verified, not assumed).
    println!("cargo:rustc-link-search=native=/usr/lib/swift");
    for l in ["swiftCore", "swiftFoundation", "swift_Concurrency"] {
        println!("cargo:rustc-link-lib=dylib={l}");
    }
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    for fw in [
        "CryptoKit",
        "Foundation",
        "Security",
        "CoreFoundation",
        "LocalAuthentication",
    ] {
        println!("cargo:rustc-link-lib=framework={fw}");
    }
}

/// Prefer an explicit override, then Xcode, then the Command Line Tools. Xcode's
/// swiftc refuses to run at all until its licence is accepted, so CLT is a real
/// fallback rather than a theoretical one.
fn locate_swiftc() -> PathBuf {
    if let Ok(p) = std::env::var("TENZRO_SWIFTC") {
        return PathBuf::from(p);
    }
    let clt = PathBuf::from("/Library/Developer/CommandLineTools/usr/bin/swiftc");
    if let Ok(o) = Command::new("xcrun").args(["--find", "swiftc"]).output() {
        if o.status.success() {
            let p = PathBuf::from(String::from_utf8_lossy(&o.stdout).trim().to_string());
            // Probe it: xcrun happily returns a path that then refuses to run.
            if Command::new(&p)
                .arg("--version")
                .output()
                .is_ok_and(|r| r.status.success())
            {
                return p;
            }
        }
    }
    if clt.exists() {
        return clt;
    }
    panic!(
        "no usable swiftc found. Install the Xcode Command Line Tools \
         (xcode-select --install), or set TENZRO_SWIFTC to a swiftc that runs."
    );
}

fn locate_sdk(target_os: &str) -> Option<String> {
    let name = if target_os == "ios" {
        "iphoneos"
    } else {
        "macosx"
    };
    if let Ok(o) = Command::new("xcrun")
        .args(["--sdk", name, "--show-sdk-path"])
        .output()
    {
        if o.status.success() {
            let p = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if !p.is_empty() && PathBuf::from(&p).exists() {
                return Some(p);
            }
        }
    }
    let fallback = "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk";
    (target_os == "macos" && PathBuf::from(fallback).exists()).then(|| fallback.to_string())
}

fn swift_target(target_os: &str) -> String {
    let arch = match std::env::var("CARGO_CFG_TARGET_ARCH")
        .unwrap_or_default()
        .as_str()
    {
        "aarch64" => "arm64",
        other => other.to_string().leak(),
    };
    if target_os == "ios" {
        format!("{arch}-apple-ios15.0")
    } else {
        // 14.0 is the floor that has the CryptoKit SecureEnclave surface we use.
        format!("{arch}-apple-macosx14.0")
    }
}
