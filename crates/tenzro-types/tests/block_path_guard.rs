//! The block-application path does not call the blob store.
//!
//! Consensus, the VM, settlement, finality and the token logic decide and
//! apply blocks. The blob store (shard bytes, model files) is reached only
//! from the node's replication tasks. A poisoned or full blob store can
//! then cost log noise and a retry loop but cannot stall a block, as the
//! 2026-10 investigation found in the live logs. This fails when a
//! block-path crate starts naming the blob store.

use std::fs;
use std::path::{Path, PathBuf};

const BLOCK_PATH: &[&str] = &[
    "tenzro-vm",
    "tenzro-consensus",
    "tenzro-finality",
    "tenzro-settlement",
    "tenzro-token",
];

const FORBIDDEN: &[&str] = &[
    "iroh_blobs",
    "iroh::blobs",
    "BlobStore",
    "bao_file",
    "blob_store",
];

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().and_then(|x| x.to_str()) == Some("rs") {
            out.push(p);
        }
    }
}

#[test]
fn the_block_path_crates_never_name_the_blob_store() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut seen = 0;
    for krate in BLOCK_PATH {
        let mut files = Vec::new();
        rs_files(&root.join(krate).join("src"), &mut files);
        assert!(!files.is_empty(), "{krate} has no sources to scan");
        for f in files {
            seen += 1;
            let text = fs::read_to_string(&f).unwrap_or_default();
            for word in FORBIDDEN {
                assert!(
                    !text.contains(word),
                    "{} names {word}: block application must not depend on the blob store",
                    f.display()
                );
            }
        }
    }
    assert!(seen > 100, "the scan saw only {seen} files");
}
