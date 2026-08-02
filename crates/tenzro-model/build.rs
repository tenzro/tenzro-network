use std::path::{Path, PathBuf};
use std::process::Command;

/// Record an identifier for the vendored llama.cpp source so the cluster module
/// can gate cluster membership on a matching build. The RPC wire protocol has no
/// version negotiation, so members must share the exact llama.cpp source;
/// emitting this at build time keeps the gate honest across vendor bumps.
///
/// llama.cpp is vendored in one of two shapes depending on the checkout, and the
/// identifier has to be correct in both:
///
/// - **As a git submodule** — the directory is its own repository, so its `HEAD`
///   is the llama.cpp commit and is exactly what we want.
/// - **As plain tracked files** (the current shape of this repo: ~2900 regular
///   files under `vendor/llama-cpp-rs/`, only `vendor/erc8004-evm` is a real
///   gitlink) — the directory is *not* its own repository. Running
///   `git rev-parse HEAD` inside it walks up to the enclosing monorepo and
///   returns the **monorepo** commit, which is wrong: it changes on every commit
///   to any part of the tree, so two nodes built from byte-identical llama.cpp
///   sources would report different identifiers and refuse to cluster.
///
/// The second case is detected by comparing the directory against the git
/// toplevel it resolves to. When they differ, the correct identifier is the
/// **tree hash of that subdirectory** (`HEAD:<relative path>`), which changes if
/// and only if the vendored llama.cpp content changes.
fn main() {
    let commit = vendored_llama_id().unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=LLAMA_CPP_COMMIT={commit}");
}

fn vendored_llama_id() -> Option<String> {
    // crates/tenzro-model -> repo root is two levels up.
    let manifest = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let vendored = Path::new(&manifest).join("../../vendor/llama-cpp-rs/llama-cpp-sys-2/llama.cpp");
    if !vendored.exists() {
        return None;
    }

    let toplevel = git_output(&vendored, &["rev-parse", "--show-toplevel"]).map(PathBuf::from)?;

    // Canonicalize both sides before comparing — `vendored` still carries the
    // `../..` segments, while git always prints an absolute resolved path.
    let vendored_abs = vendored.canonicalize().ok()?;
    let toplevel_abs = toplevel.canonicalize().ok()?;

    if vendored_abs == toplevel_abs {
        // Own repository (submodule): HEAD is the llama.cpp commit.
        println!(
            "cargo:rerun-if-changed={}",
            vendored_abs.join(".git").display()
        );
        return git_output(&vendored_abs, &["rev-parse", "--short=12", "HEAD"]);
    }

    // Vendored as plain files inside an enclosing repository. Use the tree hash
    // of the subdirectory so the identifier tracks the llama.cpp content and
    // nothing else.
    let rel = vendored_abs.strip_prefix(&toplevel_abs).ok()?;
    let spec = format!("HEAD:{}", rel.to_str()?);
    println!("cargo:rerun-if-changed={}", vendored_abs.display());
    git_output(&toplevel_abs, &["rev-parse", "--short=12", &spec])
}

fn git_output(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}
