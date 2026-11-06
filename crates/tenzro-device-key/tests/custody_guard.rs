//! Build-time guard: no software key path may reappear in release code.
//!
//! Scans the workspace's Rust sources (outside `tests/`, `benches/`,
//! `examples/`, `vendor/` and `#[cfg(test)]` modules) and its deployment files
//! for the constructs that held keys in software: key files, sealed seeds,
//! seeded transport keys, software key generation, and seed delivery through
//! the environment or argv. A hit fails the test with the file and line.
//!
//! Keys the hardware cannot hold are derived on demand through
//! `tenzro_device_key::derive`; P-256 keys live in the TPM or Secure Enclave
//! through `tenzro_device_key::signer`. Neither needs anything listed here.

use std::path::{Path, PathBuf};

/// Names of deleted software-custody paths. None may appear in release code.
const NEVER: &[&str] = &[
    "tpm_derive",
    "secret_key_seed",
    "load_validator_keypair",
    "load_validator_pq_key",
    "load_validator_bls_key",
    "generate_and_persist_keyset",
    "load_or_generate_model_recipient_key",
    "SealedSecret",
    "PqCompanion",
    "SecureEnclaveUnlocker",
    "seal_to_machine",
    "sub_identity",
    "hardware_keystore_unlock",
    "recovery-code.txt",
    ".mldsa.seed",
];

/// Software key generation or seed handling. Allowed only where listed in
/// [`ALLOWED`].
const KEYGEN: &[&str] = &[
    "KeyPair::generate(",
    "Ed25519SignerImpl::generate(",
    "MlDsaSigningKey::generate(",
    "BlsKeyPair::generate(",
    "SigningKey::random(",
    "SigningKey::generate(",
    ".seed_bytes()",
    "X25519KeyPair::from_secret_bytes(",
];

/// `(path suffix, pattern, why it is not a custody path)`.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "crates/tenzro-crypto/src/",
        "",
        "the primitives themselves; this guard checks their callers",
    ),
    (
        "crates/tenzro-payments/src/test_support.rs",
        "",
        "compiled only under cfg(test) (lib.rs gates the module)",
    ),
    (
        "crates/tenzro-node/src/validator_net_tests.rs",
        "Ed25519SignerImpl::generate(",
        "compiled only under cfg(test) (lib.rs gates the module); a test validator node key",
    ),
    (
        "crates/tenzro-vm/src/native/machine_payment_tests.rs",
        "",
        "compiled only under cfg(test) (payment_settlement.rs gates the module)",
    ),
    (
        "crates/tenzro-iroh/src/pq_endpoint.rs",
        "MlDsaSigningKey::generate(",
        "a channel key made fresh each boot and held only in memory; the machine's \
         hardware ML-DSA key signs its binding, and nothing stores it",
    ),
    (
        "crates/tenzro-iroh/src/pq_endpoint.rs",
        "SigningKey::generate(",
        "the same per-boot channel key (MlDsaSigningKey::generate( contains this pattern)",
    ),
];

/// Deployment and script content that delivered keys in software.
const DEPLOY_NEVER: &[&str] = &[
    "BEGIN PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "WALLET_PK",
    "TENZRO_MEDIA_GEN_SEED",
    "--seed-hex",
    "tenzro-genkeys",
    "tenzro-fetch-keys.service",
    "TENZRO_KEYSTORE_PASSWORD",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate sits two levels below the workspace root")
        .to_path_buf()
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if p.is_dir() {
            if matches!(
                name.as_str(),
                ".git" | "target" | "node_modules" | ".venv" | "vendor" | ".claude"
            ) {
                continue;
            }
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

fn is_release_rust(rel: &str) -> bool {
    rel.ends_with(".rs")
        && !rel
            .split('/')
            .any(|c| matches!(c, "tests" | "benches" | "examples"))
        && !rel.ends_with("/build.rs")
}

/// The lines of a source file outside `#[cfg(test)]` items, with their
/// 1-based line numbers. An item's extent is found by brace depth.
fn release_lines(src: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    // After a `#[cfg(test)]` attribute: inside the gated item, with its brace
    // depth and whether its body has opened yet.
    let mut pending = false;
    let mut in_item = false;
    let mut opened = false;
    let mut depth: i64 = 0;
    for (i, line) in src.lines().enumerate() {
        let t = line.trim_start();
        if in_item {
            let open = line.matches('{').count() as i64;
            depth += open - line.matches('}').count() as i64;
            opened |= open > 0;
            if (opened && depth <= 0) || (!opened && t.ends_with(';')) {
                in_item = false;
            }
            continue;
        }
        if t.starts_with("#[cfg(test)]") || t.starts_with("#[cfg(any(test") {
            pending = true;
            continue;
        }
        if pending && !t.starts_with("#[") && !t.is_empty() {
            pending = false;
            let open = line.matches('{').count() as i64;
            depth = open - line.matches('}').count() as i64;
            opened = open > 0;
            in_item = !((opened && depth <= 0) || (!opened && t.ends_with(';')));
            continue;
        }
        if pending {
            continue;
        }
        out.push((i + 1, line));
    }
    out
}

fn allowed(rel: &str, pattern: &str) -> bool {
    ALLOWED
        .iter()
        .any(|(path, pat, _)| rel.contains(path) && (pat.is_empty() || *pat == pattern))
}

fn scan() -> Vec<String> {
    let root = workspace_root();
    let mut files = Vec::new();
    walk(&root, &mut files);
    let mut hits = Vec::new();
    for f in files {
        let rel = f
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let Ok(src) = std::fs::read_to_string(&f) else {
            continue;
        };
        if is_release_rust(&rel) {
            for (n, line) in release_lines(&src) {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                for p in NEVER {
                    if line.contains(p) {
                        hits.push(format!("{rel}:{n}: {p}"));
                    }
                }
                for p in KEYGEN {
                    if line.contains(p) && !allowed(&rel, p) {
                        hits.push(format!("{rel}:{n}: {p}"));
                    }
                }
            }
        } else if rel.starts_with("deploy/")
            || rel.starts_with("scripts/")
            || rel.starts_with("config/")
            || rel.contains("Dockerfile")
            || rel.ends_with(".service")
            || rel.ends_with(".timer")
            || rel.ends_with(".sh")
        {
            for (i, line) in src.lines().enumerate() {
                for p in DEPLOY_NEVER {
                    if line.contains(p) {
                        hits.push(format!("{rel}:{}: {p}", i + 1));
                    }
                }
            }
        }
    }
    hits
}

#[test]
fn no_software_key_path_in_release_code() {
    let hits = scan();
    assert!(
        hits.is_empty(),
        "software key custody found in release code:\n{}",
        hits.join("\n")
    );
}

/// The guard must see what it is looking for: a planted hit in a release
/// position is reported, and the same line inside a test item is not.
#[test]
fn the_guard_detects_a_planted_software_key() {
    let planted = "fn f() {\n    let k = KeyPair::generate(KeyType::Ed25519);\n}\n\
                   #[cfg(test)]\nfn helper() {\n    let k = KeyPair::generate(KeyType::Ed25519);\n}\n\
                   #[cfg(test)]\nmod tests {\n    fn g() {\n        KeyPair::generate(KeyType::Ed25519);\n    }\n}\n\
                   fn after() {\n    let k = KeyPair::generate(KeyType::Ed25519);\n}\n";
    let lines = release_lines(planted);
    let hits: Vec<usize> = lines
        .iter()
        .filter(|(_, l)| l.contains("KeyPair::generate("))
        .map(|(n, _)| *n)
        .collect();
    assert_eq!(hits, vec![2, 15], "{lines:?}");
    assert!(is_release_rust("crates/x/src/lib.rs"));
    assert!(!is_release_rust("crates/x/tests/t.rs"));
    assert!(!allowed(
        "crates/tenzro-node/src/node.rs",
        "KeyPair::generate("
    ));
    assert!(allowed(
        "crates/tenzro-crypto/src/keys.rs",
        "KeyPair::generate("
    ));
}
