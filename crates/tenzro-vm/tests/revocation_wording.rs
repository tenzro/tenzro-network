//! Revoking an agent stops it on Tenzro at once and on another chain only at
//! the expiry of the grant it holds there (docs/AGENT_ACCOUNTS.md,
//! "Revocation"). No published text may say the second happens at once: a
//! reader who believes it leaves a compromised agent's remote grant running.
//!
//! A paragraph that speaks of revoking, of another chain, and of an
//! immediate effect must also name the expiry that bounds the remote side.

use std::path::{Path, PathBuf};

const REVOKE: &[&str] = &["revok", "revocation", "kill switch", "kill-switch"];
const ELSEWHERE: &[&str] = &[
    "other chain",
    "another chain",
    "every chain",
    "all chains",
    "remote",
    "elsewhere",
    "cross-chain",
];
const AT_ONCE: &[&str] = &[
    "at once",
    "immediate",
    "instant",
    "right away",
    "everywhere",
];
const BOUND: &[&str] = &["expir", "time window", "ttl"];

/// Whether `paragraph` claims revocation is immediate on another chain
/// without naming the expiry that bounds it.
fn overclaims(paragraph: &str) -> bool {
    let p = paragraph.to_lowercase();
    let any = |words: &[&str]| words.iter().any(|w| p.contains(w));
    any(REVOKE) && any(ELSEWHERE) && any(AT_ONCE) && !any(BOUND)
}

fn markdown(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            markdown(&path, out);
        } else if path.extension().is_some_and(|e| e == "md") {
            out.push(path);
        }
    }
}

#[test]
fn no_published_text_says_a_revocation_is_immediate_on_another_chain() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = vec![root.join("README.md")];
    markdown(&root.join("docs"), &mut files);
    let mut found = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        for paragraph in text.split("\n\n") {
            if overclaims(paragraph) {
                let line = paragraph.lines().next().unwrap_or_default();
                found.push(format!("{}: {line}", file.display()));
            }
        }
    }
    assert!(
        found.is_empty(),
        "these paragraphs say a revocation is immediate on another chain; say it stops the \
         agent there at the grant's expiry:\n{}",
        found.join("\n")
    );
}

#[test]
fn the_check_refuses_an_immediate_claim_and_admits_the_bounded_one() {
    assert!(overclaims(
        "Revoking an agent stops it at once on every chain it holds a remote account on."
    ));
    assert!(overclaims(
        "The kill switch takes effect immediately, on Tenzro and on remote chains alike."
    ));
    assert!(!overclaims(
        "Revocation is immediate on Tenzro; a remote account stops the agent at most at the \
         grant's expiry."
    ));
    assert!(!overclaims("Revoking a grant: it stops applying at once."));
    assert!(!overclaims("A remote grant runs for its time window."));
}
