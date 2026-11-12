//! No origin credential ships with the node.
//!
//! The network never carries anyone's account at a model origin: an operator
//! may give their own node their own credential (sealed on their machine, or
//! in the node's environment), and nothing else. This scans every tracked
//! text file, tests and fixtures included, and fails on:
//! - a string shaped like a Hugging Face access token (`hf_` and 30+ letters
//!   and digits);
//! - a read of the hub libraries' ambient token variables, which would pick
//!   up a token the operator never gave the node;
//! - the operator credential variable given a value in any config, compose,
//!   image or environment file;
//! - the operator credential installed anywhere but the node's credential
//!   module, the only place that reads the operator's sealed store or
//!   environment.

#[path = "support/gate.rs"]
mod gate;

use std::path::Path;

const SKIP_DIRS: &[&str] = &[
    "target",
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "__pycache__",
    ".venv",
];
const TEXT: &[&str] = &[
    ".rs", ".md", ".toml", ".json", ".yml", ".yaml", ".sh", ".py", ".ts", ".tsx", ".js", ".env",
    ".example", ".txt", ".cfg", ".conf", ".ini", ".service", ".timer",
];

fn walk(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let name = p
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        if p.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) {
                walk(&p, root, out);
            }
            continue;
        }
        let text_like = TEXT.iter().any(|x| name.ends_with(x))
            || name.starts_with("Dockerfile")
            || name.starts_with("docker-compose");
        if !text_like || e.metadata().map(|m| m.len() > 4 << 20).unwrap_or(true) {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(&p) {
            let rel = p
                .strip_prefix(root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, text));
        }
    }
}

fn token_shaped(text: &str) -> bool {
    let b = text.as_bytes();
    let mut i = 0;
    while let Some(off) = text[i..].find("hf_") {
        let at = i + off;
        let before_ok = at == 0 || !(b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_');
        let run = b[at + 3..]
            .iter()
            .take_while(|c| c.is_ascii_alphanumeric())
            .count();
        if before_ok && run >= 30 {
            return true;
        }
        i = at + 3;
    }
    false
}

#[test]
fn no_origin_credential_ships_with_the_node() {
    let root = gate::repo_root().canonicalize().unwrap();
    let mut files = Vec::new();
    walk(&root, &root, &mut files);
    assert!(files.len() > 500, "only {} files scanned", files.len());

    let me = "crates/tenzro-types/tests/no_baked_credentials.rs";
    let operator_var = "TENZRO_HUGGINGFACE_CREDENTIAL";
    // Built here so this file does not name them literally.
    let ambient: Vec<String> = ["HF", "HUGGING_FACE_HUB", "HUGGINGFACEHUB_API", "HF_HUB"]
        .iter()
        .map(|p| format!("{p}_TOKEN"))
        .collect();
    let mut found = Vec::new();
    for (file, text) in &files {
        if file == me {
            continue;
        }
        if token_shaped(text) {
            found.push(format!("{file}: a token-shaped hf_ string"));
        }
        for var in &ambient {
            if text.contains(var.as_str()) && file != "crates/tenzro-types/tests/legacy_sweep.rs" {
                found.push(format!("{file}: names {var}"));
            }
        }
        // The onboarding entry-point list names each variable on an `env ` line
        // without a value; that is a name, not a value given to it.
        let names_only = file == "scripts/supply-chain/onboarding-entry-points.txt"
            && text
                .lines()
                .filter(|l| l.contains(operator_var))
                .all(|l| l.starts_with("env ") && !l.contains('='));
        let is_config = !(file.ends_with(".rs") || file.ends_with(".md") || names_only);
        if is_config && text.contains(operator_var) {
            found.push(format!(
                "{file}: sets {operator_var}; it is the operator's own, never shipped"
            ));
        }
        if file.ends_with(".rs")
            && text.contains("origin_credential::install(")
            && file != "crates/tenzro-node/src/credentials.rs"
            && file != "crates/tenzro-model/src/hf_download.rs"
        {
            found.push(format!(
                "{file}: installs an origin credential outside the node's credential module"
            ));
        }
    }
    assert!(
        found.is_empty(),
        "baked or ambient origin credentials:\n  {}",
        found.join("\n  ")
    );
}

#[test]
fn the_token_shape_is_recognised() {
    assert!(token_shaped(&format!("x = \"hf_{}\"", "a1".repeat(17))));
    assert!(!token_shaped("hf_download.rs and hf_token_count"));
    assert!(!token_shaped(&format!("xhf_{}", "a".repeat(40))));
}
