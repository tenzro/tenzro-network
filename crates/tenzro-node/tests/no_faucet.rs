//! The network is transfer-only: TNZO is allocated at genesis and moves by
//! transfer, and grants come from governance. No code, genesis, config,
//! script, SDK, tool or document may bring a faucet back.

use std::path::{Path, PathBuf};

/// Files that may name the word: the gate test asserting that no faucet
/// method exists, and this test.
const ALLOWED: &[&str] = &[
    "crates/tenzro-node/src/rpc_gates.rs",
    "crates/tenzro-node/tests/no_faucet.rs",
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
                ".git"
                    | "target"
                    | "node_modules"
                    | ".venv"
                    | "vendor"
                    | ".claude"
                    | "dist"
                    | "__pycache__"
            ) {
                continue;
            }
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

#[test]
fn no_faucet_anywhere() {
    let root = workspace_root();
    let mut files = Vec::new();
    walk(&root, &mut files);
    let mut hits = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if ALLOWED.contains(&rel.as_str()) {
            continue;
        }
        // Binary files (model vocabularies, images) are not text to check.
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (i, line) in text.lines().enumerate() {
            if line.to_ascii_lowercase().contains("faucet") {
                hits.push(format!("{rel}:{}", i + 1));
            }
        }
    }
    assert!(hits.is_empty(), "faucet references: {hits:#?}");
}
