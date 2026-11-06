//! The committed finality program is the build of the source next to it.
//!
//! `finality-guest.source` records the image id of `finality-guest.bin` and
//! a digest of everything the guest-builder container builds it from: the
//! guest's manifest, lockfile and source, the manifest and source of every
//! path dependency its lockfile names, and the `risc0-build` release that
//! picks the container. Both tests run on any host. A change to any of those
//! inputs fails the second until the guest is rebuilt
//! (`tests/guest_reproduces.rs`) and the record, the binary and the genesis
//! finality program id are updated together.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

fn methods() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The recorded `key value` lines of `finality-guest.source`.
fn recorded(key: &str) -> String {
    let record = std::fs::read_to_string(methods().join("finality-guest.source")).expect("finality-guest.source");
    record
        .lines()
        .find_map(|l| l.strip_prefix(key).and_then(|v| v.strip_prefix(' ')))
        .unwrap_or_else(|| panic!("finality-guest.source records no {key}"))
        .trim()
        .to_string()
}

/// Every file under `dir`, recursively.
fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            files(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// The path dependencies the guest's lockfile names: packages without a
/// registry source, other than the guest itself.
fn path_dependencies(lock: &str) -> Vec<String> {
    let mut out = Vec::new();
    for package in lock.split("[[package]]").skip(1) {
        let name = package
            .lines()
            .find_map(|l| l.strip_prefix("name = "))
            .map(|n| n.trim_matches('"').to_string());
        let sourced = package.lines().any(|l| l.starts_with("source = "));
        if let Some(name) = name
            && !sourced
            && name != "finality-guest"
        {
            out.push(name);
        }
    }
    out.sort();
    out
}

/// SHA-256 over every input file, in path order: its path relative to the
/// crates directory, its length and its bytes; then the `risc0-build`
/// release in the prover's lockfile.
fn source_digest() -> String {
    let crates = methods().join("../..").canonicalize().expect("the crates directory");
    let guest = methods().join("guest");
    let lock = std::fs::read_to_string(guest.join("Cargo.lock")).expect("the guest's Cargo.lock");
    let mut inputs = vec![guest.join("Cargo.toml"), guest.join("Cargo.lock")];
    files(&guest.join("src"), &mut inputs);
    for name in path_dependencies(&lock) {
        let dir = crates.join(&name);
        inputs.push(dir.join("Cargo.toml"));
        files(&dir.join("src"), &mut inputs);
    }
    let mut named: Vec<(String, PathBuf)> = inputs
        .into_iter()
        .map(|p| {
            let p = p.canonicalize().expect("an input file");
            let rel = p.strip_prefix(&crates).expect("under crates").to_string_lossy().replace('\\', "/");
            (rel, p)
        })
        .collect();
    named.sort();
    let mut h = Sha256::new();
    h.update(b"tenzro/finality-guest/source");
    for (rel, path) in &named {
        let bytes = std::fs::read(path).expect("an input file");
        h.update((rel.len() as u64).to_be_bytes());
        h.update(rel.as_bytes());
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(&bytes);
    }
    let prover_lock = std::fs::read_to_string(methods().join("../Cargo.lock")).expect("the prover's Cargo.lock");
    let release = prover_lock
        .split("[[package]]")
        .find(|p| p.contains("name = \"risc0-build\""))
        .and_then(|p| p.lines().find_map(|l| l.strip_prefix("version = ")))
        .expect("the prover locks risc0-build")
        .trim_matches('"')
        .to_string();
    h.update(release.as_bytes());
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn the_committed_guest_is_the_recorded_build() {
    let id: Vec<u8> = tenzro_finality_methods::FINALITY_GUEST_ID.iter().flat_map(|w| w.to_le_bytes()).collect();
    assert_eq!(hex(&id), recorded("image_id"), "finality-guest.bin is not the build finality-guest.source records");
}

#[test]
fn the_guest_source_is_what_the_committed_guest_was_built_from() {
    let digest = source_digest();
    assert_eq!(
        digest,
        recorded("source_digest"),
        "the finality guest's source changed since finality-guest.bin was built: rebuild it \
         (tests/guest_reproduces.rs), record image_id and source_digest {digest} in \
         finality-guest.source, and name the new image id in config/genesis-prod.toml"
    );
}
