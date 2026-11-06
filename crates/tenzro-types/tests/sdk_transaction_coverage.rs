//! The SDKs build every consensus transaction type.
//!
//! Reads the `TransactionType` variants from the type's own source and the
//! kinds the Rust (`TxKind`), TypeScript (`TX_KINDS`) and Python (`TX_KINDS`)
//! SDKs build, and
//! refuses any difference: a variant added to the network without its SDK
//! builder, or a builder for a variant that no longer exists.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// The body between `open` and the next line that is exactly `close`.
fn block<'a>(text: &'a str, open: &str, close: &str) -> &'a str {
    let start = text
        .find(open)
        .unwrap_or_else(|| panic!("{open} not found"))
        + open.len();
    let end = text[start..]
        .find(&format!("\n{close}"))
        .unwrap_or_else(|| panic!("end of {open} not found"));
    &text[start..start + end]
}

/// Variant names at four spaces of indent.
fn variant_names(body: &str) -> Vec<String> {
    body.lines()
        .filter_map(|l| l.strip_prefix("    "))
        .filter(|l| l.starts_with(|c: char| c.is_ascii_uppercase()))
        .map(|l| {
            l.chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect()
        })
        .collect()
}

#[test]
fn every_sdk_builds_every_transaction_type() {
    let network = variant_names(block(
        &read("crates/tenzro-types/src/transaction.rs"),
        "pub enum TransactionType {",
        "}",
    ));
    assert!(
        network.len() > 50,
        "read {} variants; the parser lost the enum",
        network.len()
    );

    let rust = variant_names(block(
        &read("sdk/tenzro-sdk/src/typed_tx.rs"),
        "pub enum TxKind {",
        "}",
    ));
    assert_eq!(
        rust, network,
        "the Rust SDK's TxKind differs from TransactionType"
    );

    let ts: Vec<String> = block(
        &read("sdk/tenzro-ts-sdk/packages/core/src/typed-tx.ts"),
        "export const TX_KINDS = [",
        "] as const;",
    )
    .lines()
    .filter_map(|l| l.trim().strip_prefix('"'))
    .filter_map(|l| l.split('"').next())
    .map(str::to_string)
    .collect();
    assert_eq!(
        ts, network,
        "the TypeScript SDK's TX_KINDS differs from TransactionType"
    );

    let py: Vec<String> = block(
        &read("sdk/tenzro-py/tenzro/typed_tx.py"),
        "TX_KINDS = (",
        ")",
    )
    .lines()
    .filter_map(|l| l.trim().strip_prefix('"'))
    .filter_map(|l| l.split('"').next())
    .map(str::to_string)
    .collect();
    assert_eq!(
        py, network,
        "the Python SDK's TX_KINDS differs from TransactionType"
    );
}

/// The SDKs prove possession of an enrolled ML-DSA-65 key under the context
/// the node verifies it with.
#[test]
fn sdks_enroll_pq_keys_under_the_node_context() {
    let node = read("crates/tenzro-crypto/src/composite.rs");
    let ctx = node
        .lines()
        .find_map(|l| l.trim().strip_prefix("Self::PqKeyEnrollment => b\""))
        .and_then(|l| l.split('"').next())
        .expect("the node's PqKeyEnrollment context");
    let rust = read("sdk/tenzro-sdk/src/account_keys.rs");
    assert!(
        rust.contains(&format!(
            "PQ_KEY_ENROLLMENT_SIGNATURE_CONTEXT: &[u8] = b\"{ctx}\";"
        )),
        "Rust SDK context differs"
    );
    let ts = read("sdk/tenzro-ts-sdk/packages/core/src/account-keys.ts");
    assert!(
        ts.contains(&format!(
            "PQ_KEY_ENROLLMENT_SIGNATURE_CONTEXT = new TextEncoder().encode('{ctx}');"
        )),
        "TypeScript SDK context differs"
    );
    let py = read("sdk/tenzro-py/tenzro/account_keys.py");
    assert!(
        py.contains(&format!("PQ_KEY_ENROLLMENT_SIGNATURE_CONTEXT = b\"{ctx}\"")),
        "Python SDK context differs"
    );
}
