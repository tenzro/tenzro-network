//! The shared hash-based voucher vectors (`sdk/fixtures/hash_voucher`): the
//! keys a channel commits to and vouchers signed under them, which the
//! channel contracts verify byte for byte.
//!
//! Rerun with `TENZRO_WRITE_FIXTURES=1` after a deliberate format change.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tenzro_crypto::hash_voucher::{VoucherKeyTree, verify};

fn tree_vectors(seed: [u8; 32], height: u8, leaves: &[u32]) -> Value {
    let tree = VoucherKeyTree::derive(seed, height).unwrap();
    let keys = tree.keys();
    let vouchers: Vec<Value> = leaves
        .iter()
        .map(|&leaf| {
            let digest: [u8; 32] = Sha256::digest(format!("voucher {leaf}")).into();
            let sig = tree.sign(leaf, &digest).unwrap();
            verify(&keys, &digest, &sig).unwrap();
            json!({
                "leaf": leaf,
                "digest": format!("0x{}", hex::encode(digest)),
                "signature": format!("0x{}", hex::encode(sig.to_bytes())),
            })
        })
        .collect();
    json!({
        "seed": format!("0x{}", hex::encode(seed)),
        "public_seed": format!("0x{}", hex::encode(keys.public_seed)),
        "height": keys.height,
        "root": format!("0x{}", hex::encode(keys.root)),
        "vouchers": vouchers,
    })
}

fn vectors() -> Value {
    json!({
        "scheme": "wots-sha256-merkle",
        "trees": [
            tree_vectors([1; 32], 2, &[0, 1, 2, 3]),
            tree_vectors([7; 32], 4, &[0, 5, 13, 15]),
            tree_vectors([0x5a; 32], 10, &[0, 511, 1023]),
        ],
    })
}

/// `v` with every object's keys in order, so the file reads the same
/// whether or not serde_json keeps insertion order (a feature another crate
/// in the build may turn on).
fn sorted(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut entries: Vec<(String, Value)> = m.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(entries.into_iter().map(|(k, v)| (k, sorted(v))).collect())
        }
        Value::Array(a) => Value::Array(a.into_iter().map(sorted).collect()),
        other => other,
    }
}

#[test]
fn the_shared_vectors_are_current() {
    let path = "sdk/fixtures/hash_voucher/vectors.json";
    let full = format!("{}/../../{path}", env!("CARGO_MANIFEST_DIR"));
    let text = serde_json::to_string_pretty(&sorted(vectors())).unwrap() + "\n";
    if std::env::var("TENZRO_WRITE_FIXTURES").is_ok() {
        std::fs::create_dir_all(std::path::Path::new(&full).parent().unwrap()).unwrap();
        std::fs::write(&full, text).unwrap();
        return;
    }
    let on_disk = std::fs::read_to_string(&full).unwrap_or_default();
    assert_eq!(
        on_disk, text,
        "{path} is stale: rerun with TENZRO_WRITE_FIXTURES=1"
    );
}
