use std::path::Path;
use std::process::Command;

/// Record the vendored llama.cpp submodule commit so the cluster module can
/// gate cluster membership on a matching build. The RPC wire protocol has no
/// version negotiation, so members must share the exact llama.cpp commit;
/// emitting it at build time keeps the gate honest across submodule bumps.
fn main() {
    let commit = vendored_llama_commit().unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=LLAMA_CPP_COMMIT={commit}");
}

fn vendored_llama_commit() -> Option<String> {
    // crates/tenzro-model -> repo root is two levels up.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let submodule = Path::new(&manifest)
        .join("../../vendor/llama-cpp-rs/llama-cpp-sys-2/llama.cpp");
    if !submodule.exists() {
        return None;
    }
    println!("cargo:rerun-if-changed={}", submodule.join("HEAD").display());
    let out = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .current_dir(&submodule)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let commit = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if commit.is_empty() {
        None
    } else {
        Some(commit)
    }
}
