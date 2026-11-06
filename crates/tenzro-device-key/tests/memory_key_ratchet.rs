//! Ratchet: production code may not gain a place that holds a private key in
//! process memory. Private keys live in a TPM, a Secure Enclave or a passkey.
//!
//! The scan counts, per source file, the lines before the file's first
//! `#[cfg(test)]` that make or hold a software private key. Each count must
//! equal the entry in `ALLOWED`: a file not listed with a count above zero
//! fails, a count that grew fails, and a count that fell fails until the entry
//! is lowered, so the list only shrinks. The goal is an empty list.
//!
//! Entries with the reason `one operation` derive a key from hardware output,
//! use it once and wipe it; they stay. Entries with any other reason are
//! migration work: each is removed by moving its record type to the hardware
//! batch signer (`tenzro_device_key::batch_signer`).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const PATTERNS: &[&str] = &[
    "SigningKey::from_bytes",
    "SigningKey::generate",
    "MlDsaSigningKey::generate",
    "MlDsaSigningKey::from_seed",
    "Ed25519SignerImpl::generate",
    "EphemeralSecret",
    "struct LockedKey",
    "struct LockedSeeds",
];

/// (file relative to crates/, allowed count, reason)
const ALLOWED: &[(&str, usize, &str)] = &[
    // Migration work: moves to the hardware batch signer, record type by record type.
    (
        "tenzro-node/src/tpm_key_holder.rs",
        1,
        "transport key K of the key holder link to a remote provider: ephemeral, never written, usable for transport only (cannot sign records, votes or funds), bound by a passkey grant until T; the local socket uses the kernel peer credentials (peer_cred) and an allowed-uid list and holds no key. Residual stated in docs/CHANNEL-AUTHENTICATION.md",
    ),
    // A key made for one operation, consumed or wiped; the type zeroizes on drop (checked below).
    (
        "tenzro-consensus/src/channel.rs",
        3,
        "one operation: x25519 EphemeralSecret, consumed by diffie_hellman, held only across the handshake",
    ),
    (
        "tenzro-device-key/src/session.rs",
        3,
        "one operation: P-256 EphemeralSecret, consumed by the agreement, held only across the handshake",
    ),
    (
        "tenzro-device-key/src/envelope.rs",
        2,
        "one operation: ephemeral agreement for one wrap, dropped at once",
    ),
    (
        "tenzro-device-key/src/credential.rs",
        2,
        "one operation: ephemeral agreement for one credential, dropped at once",
    ),
    (
        "tenzro-device-key/src/derive.rs",
        2,
        "one operation: key derived from hardware output, used for one signature, wiped",
    ),
    (
        "tenzro-device-key/src/backend_tpm.rs",
        1,
        "one operation: ephemeral agreement for one TPM import, dropped at once",
    ),
];

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if n == "target" || n == "tests" || n == "benches" || n == "examples" || n == "vendor" {
                continue;
            }
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if n.ends_with("_tests.rs") || n == "test_support.rs" {
                continue;
            }
            out.push(p);
        }
    }
}

fn counts() -> BTreeMap<String, usize> {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for c in fs::read_dir(&crates).unwrap().flatten() {
        rs_files(&c.path().join("src"), &mut files);
    }
    let mut out = BTreeMap::new();
    for f in files {
        let Ok(text) = fs::read_to_string(&f) else {
            continue;
        };
        let mut n = 0;
        // Items gated to tests or to the test-only key features are skipped
        // by brace depth. The features themselves are checked by
        // `test_only_key_features_are_enabled_only_from_dev_dependencies`.
        let mut skipping = false;
        let mut depth: i32 = 0;
        let mut opened = false;
        for line in text.lines() {
            let t = line.trim_start();
            if t.starts_with("#[cfg(test)]") && !skipping && depth == 0 && !t.contains("mod ") {
                // A test module or a test-only item: skip it as an item.
                skipping = true;
                depth = 0;
                opened = false;
                continue;
            }
            if !skipping
                && (t.starts_with("#[cfg(any(test, feature = \"test-")
                    || t.starts_with("#[cfg(feature = \"test-"))
            {
                skipping = true;
                depth = 0;
                opened = false;
                continue;
            }
            if skipping {
                for c in line.chars() {
                    match c {
                        '{' => {
                            depth += 1;
                            opened = true;
                        }
                        '}' => depth -= 1,
                        _ => {}
                    }
                }
                if (opened && depth <= 0) || (!opened && t.ends_with(';')) {
                    skipping = false;
                }
                continue;
            }
            if t.starts_with("//") {
                continue;
            }
            if PATTERNS.iter().any(|p| line.contains(p)) {
                n += 1;
            }
        }
        if n > 0 {
            let rel = f
                .strip_prefix(&crates)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(rel, n);
        }
    }
    out
}

#[test]
fn production_code_gains_no_in_memory_private_key_and_the_list_only_shrinks() {
    let found = counts();
    let mut problems = Vec::new();
    for (file, n) in &found {
        match ALLOWED.iter().find(|(f, _, _)| f == file) {
            None => problems.push(format!("NEW site: {file} has {n}")),
            Some((_, allowed, _)) if n > allowed => {
                problems.push(format!("GREW: {file} has {n}, allowed {allowed}"))
            }
            Some((_, allowed, _)) if n < allowed => problems.push(format!(
                "SHRANK: {file} has {n}, list says {allowed}; lower the entry"
            )),
            _ => {}
        }
    }
    for (f, _, _) in ALLOWED {
        if !found.contains_key(*f) {
            problems.push(format!("STALE: {f} no longer has a site; remove the entry"));
        }
    }
    assert!(
        problems.is_empty(),
        "in-memory key ratchet:\n{}\nfound: {found:#?}",
        problems.join("\n")
    );
}

#[test]
fn test_only_key_features_are_enabled_only_from_dev_dependencies() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut bad = Vec::new();
    for c in fs::read_dir(&crates).unwrap().flatten() {
        let Ok(text) = fs::read_to_string(c.path().join("Cargo.toml")) else {
            continue;
        };
        let mut section = String::new();
        for line in text.lines() {
            let t = line.trim();
            if t.starts_with('[') {
                section = t.to_string();
                continue;
            }
            let names_feature = [
                "\"test-keys\"",
                "\"test-support\"",
                "\"test-software-keys\"",
                "\"test-root\"",
            ]
            .iter()
            .any(|f| t.contains(f));
            let tool_crate = ["tenzro-sim", "tenzro-econsim", "tenzro-settlement-fuzz"]
                .iter()
                .any(|n| c.path().ends_with(n));
            if names_feature
                && !tool_crate
                && t.contains("features")
                && !section.contains("dev-dependencies")
                && !section.starts_with("[features")
            {
                bad.push(format!("{}: {t}", c.path().display()));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "a test-only key feature is enabled outside dev-dependencies:\n{}",
        bad.join("\n")
    );
}

/// The ephemeral key types the `one operation` entries rely on wipe
/// themselves when dropped.
#[test]
fn ephemeral_agreement_secrets_zeroize_on_drop() {
    fn zeroizes<T: zeroize::ZeroizeOnDrop>() {}
    // x25519-dalek 2 wipes through a Drop impl (its default `zeroize` feature)
    // without exposing the marker trait; a plain byte array needs no drop, so
    // `needs_drop` shows the wiping Drop impl is present.
    assert!(std::mem::needs_drop::<x25519_dalek::EphemeralSecret>());
    zeroizes::<p256::ecdh::EphemeralSecret>();
    zeroizes::<ed25519_dalek::SigningKey>();
}

// ---------------------------------------------------------------------------
// Second scan: key FILES. A private key is never read from or written to a
// file. Hardware-wrapped blobs (a TPM or Secure Enclave blob is useless off
// its chip) and password-sealed public records are listed with their reason.
// ---------------------------------------------------------------------------

const FILE_OPS: &[&str] = &[
    "fs::write",
    "fs::read(",
    "fs::read_to_string",
    "File::create",
    "File::open",
    "OpenOptions",
];
const KEY_WORDS: &[&str] = &["key", "seed", "secret", "pem", "keystore"];

/// File names that once held a software private key. They may not appear in
/// production source at all.
const FORBIDDEN_NAMES: &[&str] = &[
    "join(\"validator_key\")",
    "join(\"node_key\")",
    "join(\"node_key.bin\")",
    "join(\"validator_key.bin\")",
    "join(\"ed25519_key\")",
    "join(\"node.key\")",
    "join(\"secret.key\")",
    "join(\"identity.key\")",
    "join(\"private.pem\")",
    "\"validator_key\".as_ref()",
];

/// (file, allowed lines, reason)
const ALLOWED_FILE_OPS: &[(&str, usize, &str)] = &[
    (
        "tenzro-econsim/src/bin/tenzro-econsim.rs",
        1,
        "not a key: reads seeds.jsonl, simulation seeds of a tool binary",
    ),
    (
        "tenzro-openshell/src/gateway_auth.rs",
        1,
        "public key: reads the gateway's PUBLIC key PEM to verify tokens",
    ),
    (
        "tenzro-tee/src/key_release.rs",
        1,
        "hardware-wrapped: ciphertext only on disk; the unwrap key is the attested environment's own confidential-compute release key. A key that never leaves a hardware root of trust counts as hardware; the limit is that this root is TEE hardware, not TPM, secure element or passkey",
    ),
];

fn file_op_counts() -> (BTreeMap<String, usize>, Vec<String>) {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    for c in fs::read_dir(&crates).unwrap().flatten() {
        rs_files(&c.path().join("src"), &mut files);
    }
    let mut out = BTreeMap::new();
    let mut forbidden = Vec::new();
    for f in files {
        let Ok(text) = fs::read_to_string(&f) else {
            continue;
        };
        let rel = f
            .strip_prefix(&crates)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let mut n = 0;
        for (i, line) in text.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("#[cfg(test)]") {
                break;
            }
            if t.starts_with("//") {
                continue;
            }
            if FORBIDDEN_NAMES.iter().any(|w| line.contains(w)) {
                forbidden.push(format!("{rel}:{}: {t}", i + 1));
            }
            let lower = line.to_lowercase();
            if FILE_OPS.iter().any(|o| line.contains(o))
                && KEY_WORDS.iter().any(|w| lower.contains(w))
            {
                n += 1;
            }
        }
        if n > 0 {
            out.insert(rel, n);
        }
    }
    (out, forbidden)
}

#[test]
fn no_private_key_is_read_from_or_written_to_a_file_and_the_list_only_shrinks() {
    let (found, forbidden) = file_op_counts();
    let mut problems = Vec::new();
    for f in &forbidden {
        problems.push(format!("FORBIDDEN key file name: {f}"));
    }
    for (file, n) in &found {
        match ALLOWED_FILE_OPS.iter().find(|(f, _, _)| f == file) {
            None => problems.push(format!("NEW file site: {file} has {n}")),
            Some((_, a, _)) if n > a => problems.push(format!("GREW: {file} has {n}, allowed {a}")),
            Some((_, a, _)) if n < a => problems.push(format!(
                "SHRANK: {file} has {n}, list says {a}; lower the entry"
            )),
            _ => {}
        }
    }
    for (f, _, _) in ALLOWED_FILE_OPS {
        if !found.contains_key(*f) {
            problems.push(format!("STALE: {f} no longer has a site; remove the entry"));
        }
    }
    assert!(
        problems.is_empty(),
        "key file ratchet:\n{}\nfound: {found:#?}",
        problems.join("\n")
    );
}
