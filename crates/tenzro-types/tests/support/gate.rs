//! Source readers shared by the genesis-gate tests.

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Files under `dirs` (repo-relative) with one of `exts`, as
/// (repo-relative path, text). Test directories and test files are skipped.
pub fn files(dirs: &[&str], exts: &[&str]) -> Vec<(String, String)> {
    let root = repo_root();
    let mut stack: Vec<PathBuf> = dirs.iter().map(|d| root.join(d)).collect();
    let mut out = Vec::new();
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if p.is_dir() {
                if !matches!(
                    name,
                    "tests" | "test" | "__tests__" | "node_modules" | "dist" | "__pycache__"
                ) {
                    stack.push(p);
                }
                continue;
            }
            let is_test = name == "tests.rs"
                || name.ends_with("_tests.rs")
                || name.ends_with(".test.ts")
                || name.ends_with(".spec.ts")
                || name.starts_with("test_");
            if is_test || !exts.iter().any(|x| name.ends_with(x)) {
                continue;
            }
            if let Ok(text) = std::fs::read_to_string(&p) {
                let rel = p
                    .strip_prefix(&root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .replace('\\', "/")
                    .replace("/./", "/");
                out.push((rel, text));
            }
        }
    }
    out.sort();
    out
}

/// Every crate's `src` plus the SDK sources.
pub fn workspace_sources() -> Vec<(String, String)> {
    let root = repo_root();
    let mut dirs: Vec<String> = vec![
        "sdk/tenzro-sdk/src".into(),
        "sdk/tenzro-ts-sdk/src".into(),
        "sdk/tenzro-ts-sdk/packages".into(),
        "sdk/tenzro-py/tenzro".into(),
        "sdk/tenzro-py/native/src".into(),
    ];
    for c in std::fs::read_dir(root.join("crates"))
        .expect("crates dir")
        .flatten()
    {
        if let Some(n) = c.file_name().to_str() {
            dirs.push(format!("crates/{n}/src"));
        }
    }
    let dirs: Vec<&str> = dirs.iter().map(String::as_str).collect();
    files(&dirs, &[".rs", ".ts", ".py"])
}

/// The part of a source file before its test module, comments included.
pub fn before_tests(text: &str) -> String {
    let mut out = String::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        if line.trim_start().starts_with("#[cfg(test)]")
            && lines.peek().is_some_and(|n| {
                let n = n.trim_start();
                let n = n
                    .strip_prefix("pub(crate) ")
                    .or_else(|| n.strip_prefix("pub(super) "))
                    .or_else(|| n.strip_prefix("pub "))
                    .unwrap_or(n);
                n.starts_with("mod ")
            })
        {
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// The part of a source file before its test module, without comment lines.
pub fn non_test(text: &str) -> String {
    before_tests(text)
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            !(t.starts_with("//")
                || t.starts_with('*')
                || t.starts_with("/*")
                || t.starts_with("# "))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Every method the node dispatches: the union of the three classification
/// tables in `rpc_gates.rs`. The `rpc_gates` tests refuse to pass unless these
/// tables equal the dispatcher's method set, so reading them reads the surface.
pub fn rpc_methods() -> BTreeSet<String> {
    let src = std::fs::read_to_string(repo_root().join("crates/tenzro-node/src/rpc_gates.rs"))
        .expect("rpc_gates.rs");
    let mut out = BTreeSet::new();
    for table in ["ADMIN_METHODS", "OWNER_METHODS", "OPEN_METHODS"] {
        let start = src
            .find(&format!("pub const {table}"))
            .expect("method table");
        let body = &src[start..];
        let body = &body[..body.find("];").expect("table end")];
        for line in body.lines().skip(1) {
            let code = line.split("//").next().unwrap_or("");
            out.extend(quoted(code, true));
        }
    }
    assert!(out.len() > 100, "rpc_gates tables not found");
    out
}

/// Quoted literals on a line. Rust sources quote strings with `"` only
/// (`'` opens lifetimes and chars); TypeScript and Python use all three.
pub fn quoted(line: &str, rust: bool) -> Vec<String> {
    let mut out = Vec::new();
    let b = line.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let q = b[i];
        if (q == b'"' || (!rust && (q == b'\'' || q == b'`')))
            && let Some(len) = line[i + 1..].find(q as char)
        {
            out.push(line[i + 1..i + 1 + len].to_string());
            i += len + 2;
            continue;
        }
        i += 1;
    }
    out
}

/// Whether `s` is shaped like an RPC method name: a namespace, an optional
/// subsystem, then a camelCase verb (`tenzro_listPayments`,
/// `tenzro_iroh_getConfig`, `eth_getCode`).
pub fn is_rpc_name(s: &str) -> bool {
    let Some((ns, rest)) = s.split_once('_') else {
        return false;
    };
    if !matches!(ns, "tenzro" | "eth" | "net" | "web3") {
        return false;
    }
    let verb = rest.rsplit('_').next().unwrap_or(rest);
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && verb.chars().next().is_some_and(|c| c.is_ascii_lowercase())
        && (verb.chars().any(|c| c.is_ascii_uppercase()) || ns != "tenzro")
}

/// RPC names a source file quotes.
pub fn rpc_names_in(path: &str, text: &str) -> BTreeSet<String> {
    let rust = path.ends_with(".rs");
    text.lines()
        .flat_map(|l| quoted(l, rust))
        .filter(|s| is_rpc_name(s))
        .collect()
}
