//! The boundary guard: the repository carries no names of other companies'
//! products, no internal planning labels, no emojis, no compatibility shims in
//! the protocol crates, and no protocol surface that is not on the approved
//! list.
//!
//! - Names. Other organizations' product names never appear in the tree. The
//!   Praecise engine and praecise-harness are open-source dependencies and may
//!   be named as such; [`PRAECISE_DEPENDENCY_FORMS`] lists every accepted form,
//!   and any other mention fails.
//! - Third-party networks listed in [`NETWORKS_NOT_NAMED`] are named nowhere
//!   in the tree: not in code, generated references or internal files.
//! - Planning labels, planning language and emojis never appear.
//! - Compatibility. Protocol crates declare no item named for a legacy or
//!   compatibility path, no new serde alias and no RPC method alias.
//! - Surface. Every native module, native selector, RPC namespace and RPC method
//!   is listed in `support/protocol_surface.txt`, with its class.
//!
//! The rejected names are stored reversed so this file does not carry them.

#[path = "support/gate.rs"]
mod gate;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

fn rev(s: &str) -> String {
    s.chars().rev().collect()
}

/// Rejected names, matched case-insensitively anywhere (stored reversed).
const NAMES_ANYWHERE: &[&str] = &[
    "etacruf",
    "sdlrowgnivil",
    "sdlrow gnivil",
    "negsil",
    "sevles evisrucer",
    "sevlesevisrucer",
    "znvrp",
    "sdnuos enihcam",
    "sdnuosenihcam",
    "spondi",
    "ielep",
    "reivir",
    "moc.esicearp",
    "duolc.esicearp",
    "ia.esicearp",
];

/// Rejected names, matched case-insensitively as whole words (stored reversed).
const NAMES_WORD_ANY_CASE: &[&str] = &["ilob"];

/// Rejected names, matched as whole words with this exact case (stored reversed).
const NAMES_WORD_EXACT: &[&str] = &["ARO", "SCR", "assI", "NBR"];

/// The forms in which the open-source Praecise engine and praecise-harness may
/// be named: crate and package names, repository paths, import paths, the
/// node's engine identifiers, and "the Praecise engine" in prose. Matched
/// case-insensitively, with runs of whitespace and comment markers read as one
/// space.
const PRAECISE_DEPENDENCY_FORMS: &[&str] = &[
    "praecise-engine",
    "praecise_engine",
    "praecise-harness",
    "praecise_harness",
    "@praecise/harness",
    "praecise-runtime",
    "praecise_runtime",
    "praecise-host",
    "praecise_host",
    "praecise-diffusion",
    "praecise_diffusion",
    "praecise-train",
    "praecise_train",
    "praecise-codec",
    "praecise_codec",
    "praecise-onnx",
    "praecise_onnx",
    "github.com/praecise/praecise-engine",
    "github.com/praecise/praecise-harness",
    "github.com/praecise/llama.cpp",
    "praecise/llama.cpp",
    "praecise engine",
    "praecise's engine",
    "praecise speech engine",
    "praecise diffusion engine",
    "praecise media pipeline",
    "praecise video codec",
    "praecise scheduler",
    "praecise's layer pipeline",
    "praecisetask",
    "praeciseembedder",
    "praecise_embedder",
    "engine::praecise",
    "self::praecise",
    "load_praecise",
    "self.praecise",
    "praecise: enginemodels",
    "\"praecise\"",
    "praecise/{task}",
];

/// Source files that declare the node's engine identifier itself.
const PRAECISE_IDENTIFIER_FILES: &[&str] = &["crates/tenzro-model/src/model_host.rs"];

/// Third-party networks the tree never names (stored reversed).
const NETWORKS_NOT_NAMED: &[&str] = &["notnac"];

/// Internal files that never ship and are not public documents: the
/// assistant instruction files the public-tree scanner's path rules refuse
/// (stored reversed, so this list never reads as a citation of them).
const INTERNAL_FILES: &[&str] = &["dm.EDUALC", "dm.STNEGA"];

/// Planning language (stored reversed), matched case-insensitively.
const PLANNING_PHRASES: &[&str] = &[
    "hguorhtkaerb",
    "teser naelc",
    "htap laud",
    "htap-laud",
    "tuo-pir",
    "noisiced renwo",
    "ctg erofeb",
    "etag siseneg",
    "retsulc partstoob",
    "tnemucod hcraeser lanretni",
    "pihs-pots",
    "dnuof tidua eht",
];

const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "vendor",
    "node_modules",
    "dist",
    "__pycache__",
    ".next",
    ".claude",
];

const TEXT_EXTS: &[&str] = &[
    ".rs", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".py", ".md", ".toml", ".yml", ".yaml", ".json",
    ".sh", ".txt", ".go", ".move", ".fc", ".proto", ".sol", ".html", ".css", ".service",
    ".example", ".qnt", ".cfg", ".conf", ".env",
];

fn is_text(name: &str) -> bool {
    if name == "package-lock.json" || name.ends_with(".lock") {
        return false;
    }
    name.starts_with("Dockerfile")
        || matches!(
            name,
            "NOTICE" | "LICENSE" | "Makefile" | ".gitignore" | ".dockerignore"
        )
        || TEXT_EXTS.iter().any(|x| name.ends_with(x))
}

/// Every first-party text file in the repository, as (repo-relative path,
/// text). Read as bytes so a file with an invalid or NUL byte is still read.
fn tree() -> Vec<(String, String)> {
    let root = gate::repo_root();
    let mut stack = vec![root.clone()];
    let mut out = Vec::new();
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if p.is_dir() {
                if !SKIP_DIRS.contains(&name) {
                    stack.push(p);
                }
                continue;
            }
            if !is_text(name) {
                continue;
            }
            if let Ok(bytes) = std::fs::read(&p) {
                out.push((rel(&root, &p), String::from_utf8_lossy(&bytes).into_owned()));
            }
        }
    }
    out.sort();
    out
}

fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

fn is_internal(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    INTERNAL_FILES.iter().any(|f| rev(f) == name) || path.starts_with("tools/sync/")
}

fn line_of(text: &str, at: usize) -> usize {
    text[..at].matches('\n').count() + 1
}

fn word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Byte offsets where `needle` occurs in `hay` as a whole word.
fn word_hits(hay: &str, needle: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = hay[from..].find(needle) {
        let at = from + i;
        let end = at + needle.len();
        let before = hay[..at].chars().next_back().is_none_or(|c| !word_char(c));
        let after = hay[end..].chars().next().is_none_or(|c| !word_char(c));
        if before && after {
            out.push(at);
        }
        from = end;
    }
    out
}

fn substring_hits(hay: &str, needle: &str) -> Vec<usize> {
    hay.match_indices(needle).map(|(i, _)| i).collect()
}

#[test]
fn the_reversed_lists_read_back() {
    assert_eq!(rev("cba"), "abc");
    assert_eq!(word_hits("a xy b xyz", "xy"), vec![2]);
}

#[test]
fn no_other_organizations_product_is_named() {
    let mut found = Vec::new();
    for (path, text) in tree() {
        if path == "crates/tenzro-types/tests/boundary_guard.rs" {
            continue;
        }
        let lower = text.to_ascii_lowercase();
        for n in NAMES_ANYWHERE {
            let n = rev(n);
            for at in substring_hits(&lower, &n) {
                found.push(format!("{path}:{}", line_of(&text, at)));
            }
        }
        for n in NAMES_WORD_ANY_CASE {
            for at in word_hits(&lower, &rev(n)) {
                found.push(format!("{path}:{}", line_of(&text, at)));
            }
        }
        for n in NAMES_WORD_EXACT {
            for at in word_hits(&text, &rev(n)) {
                found.push(format!("{path}:{}", line_of(&text, at)));
            }
        }
    }
    assert!(
        found.is_empty(),
        "another organization's product is named (see the reversed lists in this file):\n  {}",
        found.join("\n  ")
    );
}

/// Applications built on the network by one developer, its hosts and its
/// clients, matched case-insensitively anywhere (stored reversed). The network
/// treats every developer's applications alike, so none is named.
const APPLICATION_NAMES: &[&str] = &[
    "sbal orznet",
    "mroftalp sbal",
    "tellaw sbal",
    "seciov orznet",
    "ilc-sbal",
    "sbalzt",
    "zyx.orznet",
];

/// Application names matched as whole words with this exact case (reversed).
const APPLICATION_WORDS: &[&str] = &["krowdleiF"];

/// Test vectors that still carry an application's relying party: (file,
/// maximum number of lines). The count only goes down.
const APPLICATION_NAME_LIMITS: &[(&str, usize)] = &[];

#[test]
fn no_application_built_on_the_network_is_named() {
    let mut found = Vec::new();
    for (path, text) in tree() {
        if path == "crates/tenzro-types/tests/boundary_guard.rs" || is_internal(&path) {
            continue;
        }
        let lower = text.to_ascii_lowercase();
        let mut lines = BTreeSet::new();
        for n in APPLICATION_NAMES {
            for at in substring_hits(&lower, &rev(n)) {
                lines.insert(line_of(&text, at));
            }
        }
        for n in APPLICATION_WORDS {
            for at in word_hits(&text, &rev(n)) {
                lines.insert(line_of(&text, at));
            }
        }
        let limit = APPLICATION_NAME_LIMITS
            .iter()
            .find(|(f, _)| *f == path)
            .map_or(0, |(_, n)| *n);
        if lines.len() > limit {
            found.extend(lines.iter().map(|l| format!("{path}:{l}")));
        }
    }
    assert!(
        found.is_empty(),
        "an application built on the network is named (see the reversed lists in this file):\n  {}",
        found.join("\n  ")
    );
}

/// `text` lower-cased, with each run of whitespace and comment markers read as
/// one space, and a map from each output byte to its input byte.
fn normalized(text: &str) -> (String, Vec<usize>) {
    let mut out = String::with_capacity(text.len());
    let mut map = Vec::with_capacity(text.len());
    let mut gap = false;
    for (i, c) in text.char_indices() {
        if c.is_whitespace() || c == '/' && gap || c == '!' && gap || c == '#' && gap {
            if !gap {
                out.push(' ');
                map.push(i);
            }
            gap = true;
            continue;
        }
        gap = false;
        for l in c.to_lowercase() {
            let start = out.len();
            out.push(l);
            map.extend(std::iter::repeat_n(i, out.len() - start));
        }
    }
    (out, map)
}

#[test]
fn praecise_is_named_only_as_an_open_source_dependency() {
    let mut found = Vec::new();
    for (path, text) in tree() {
        if path == "crates/tenzro-types/tests/boundary_guard.rs" || is_internal(&path) {
            continue;
        }
        if !text.to_ascii_lowercase().contains("praecise") {
            continue;
        }
        let (norm, map) = normalized(&text);
        let mut covered = vec![false; norm.len()];
        for form in PRAECISE_DEPENDENCY_FORMS {
            for at in substring_hits(&norm, form) {
                covered[at..at + form.len()]
                    .iter_mut()
                    .for_each(|c| *c = true);
            }
        }
        for at in substring_hits(&norm, "praecise") {
            if covered[at] {
                continue;
            }
            let identifier = PRAECISE_IDENTIFIER_FILES.contains(&path.as_str())
                && norm[at..].starts_with("praecise,");
            if !identifier {
                found.push(format!(
                    "{path}:{}: {}",
                    line_of(&text, map[at]),
                    &norm[at..(at + 60).min(norm.len())]
                ));
            }
        }
    }
    assert!(
        found.is_empty(),
        "Praecise named other than as the open-source engine or harness dependency:\n  {}",
        found.join("\n  ")
    );
}

#[test]
fn no_third_party_network_is_named_anywhere() {
    let mut found = Vec::new();
    for (path, text) in tree() {
        let body = text.to_ascii_lowercase();
        for n in NETWORKS_NOT_NAMED {
            let n = rev(n);
            for (i, line) in body.lines().enumerate() {
                if line.contains(&n) {
                    found.push(format!("{path}:{}", i + 1));
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "a third-party network is named in the tree:\n  {}",
        found.join("\n  ")
    );
}

/// An internal planning label: a release-plan tag, a plan-board number, an
/// internal design-note number or a plan item after "Phase".
fn planning_label(prev: &str, word: &str) -> bool {
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    let b = word.as_bytes();
    let plan_item = (2..=3).contains(&b.len())
        && (b'A'..=b'G').contains(&b[0])
        && b[1].is_ascii_digit()
        && (b.len() == 2 || b[2].is_ascii_lowercase());
    if plan_item && matches!(prev, "Phase" | "Phases" | "charter" | "Charter") {
        return true;
    }
    if let Some(rest) = word.strip_prefix(&rev("-ctg")) {
        return !rest.is_empty();
    }
    if let Some(rest) = word.strip_prefix("PB-") {
        return digits(rest) || rest.strip_prefix('G').is_some_and(digits);
    }
    if let Some(rest) = word.strip_prefix("RFC-") {
        return rest.len() == 4 && rest.starts_with('0') && digits(rest);
    }
    if let Some(rest) = word.strip_prefix("WP") {
        return digits(rest);
    }
    false
}

fn words(line: &str) -> Vec<&str> {
    line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .filter(|w| !w.is_empty())
        .collect()
}

#[test]
fn no_internal_planning_label_or_language() {
    let mut found = Vec::new();
    for (path, text) in tree() {
        if path == "crates/tenzro-types/tests/boundary_guard.rs" || is_internal(&path) {
            continue;
        }
        let lower = text.to_ascii_lowercase();
        for p in PLANNING_PHRASES {
            for at in substring_hits(&lower, &rev(p)) {
                found.push(format!("{path}:{}: planning language", line_of(&text, at)));
            }
        }
        for (i, line) in text.lines().enumerate() {
            let ws = words(line);
            for (j, w) in ws.iter().enumerate() {
                let prev = if j == 0 { "" } else { ws[j - 1] };
                if planning_label(prev, w) {
                    found.push(format!("{path}:{}: {w}", i + 1));
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "internal planning labels or language:\n  {}",
        found.join("\n  ")
    );
}

fn is_emoji(c: char) -> bool {
    matches!(c as u32,
        0x1F000..=0x1FAFF
        | 0x2600..=0x26FF
        | 0x2705 | 0x274C | 0x274E | 0x2753..=0x2757 | 0x2795..=0x2797 | 0x27B0 | 0x27BF
        | 0x2B50 | 0x2B55 | 0x2B1B | 0x2B1C | 0x231A | 0x231B | 0x23E9..=0x23FA | 0xFE0F)
}

fn in_test_path(path: &str) -> bool {
    path.split('/')
        .any(|s| matches!(s, "tests" | "test" | "__tests__" | "fixtures"))
        || path.ends_with("_tests.rs")
        || path.ends_with(".test.ts")
        || path.ends_with(".spec.ts")
}

#[test]
fn no_emojis() {
    let mut found = Vec::new();
    for (path, text) in tree() {
        if in_test_path(&path) {
            continue;
        }
        let text = if path.ends_with(".rs") {
            gate::before_tests(&text)
        } else {
            text
        };
        for (i, line) in text.lines().enumerate() {
            if let Some(c) = line.chars().find(|c| is_emoji(*c)) {
                found.push(format!("{path}:{}: U+{:04X}", i + 1, c as u32));
            }
        }
    }
    assert!(found.is_empty(), "emojis:\n  {}", found.join("\n  "));
}

/// Crates whose state or wire format the network agrees on.
const PROTOCOL_CRATES: &[&str] = &[
    "tenzro-consensus",
    "tenzro-vm",
    "tenzro-node",
    "tenzro-types",
    "tenzro-token",
    "tenzro-settlement",
    "tenzro-identity",
    "tenzro-network",
    "tenzro-storage",
    "tenzro-bridge",
    "tenzro-payments",
    "tenzro-crypto",
    "tenzro-finality",
];

/// Serde aliases kept today: (file, count). The count only goes down.
const SERDE_ALIASES: &[(&str, usize)] = &[];

fn segments(name: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in name.split('_').filter(|p| !p.is_empty()) {
        let mut cur = String::new();
        for c in part.chars() {
            if c.is_ascii_uppercase()
                && !cur.is_empty()
                && !cur.chars().all(|c| c.is_ascii_uppercase())
            {
                out.push(cur.to_ascii_lowercase());
                cur = String::new();
            }
            cur.push(c);
        }
        if !cur.is_empty() {
            out.push(cur.to_ascii_lowercase());
        }
    }
    out
}

#[test]
fn protocol_crates_carry_no_compatibility_paths() {
    let dirs: Vec<String> = PROTOCOL_CRATES
        .iter()
        .map(|c| format!("crates/{c}/src"))
        .collect();
    let dirs: Vec<&str> = dirs.iter().map(String::as_str).collect();
    let mut found = Vec::new();
    for (path, text) in gate::files(&dirs, &[".rs"]) {
        let code = gate::non_test(&text);
        let aliases = code
            .lines()
            .filter(|l| l.contains("#[serde(") && l.contains("alias"))
            .count();
        let allowed = SERDE_ALIASES
            .iter()
            .find(|(f, _)| *f == path)
            .map_or(0, |(_, n)| *n);
        if aliases > allowed {
            found.push(format!(
                "{path}: {aliases} serde aliases (allowed {allowed})"
            ));
        }
        if code.contains("#[deprecated") {
            found.push(format!("{path}: #[deprecated]"));
        }
        for line in code.lines() {
            let t = line.trim_start();
            let t = t.strip_prefix("pub ").unwrap_or(t);
            let t = t.strip_prefix("pub(crate) ").unwrap_or(t);
            for kw in [
                "fn ", "struct ", "enum ", "const ", "static ", "type ", "mod ", "trait ",
            ] {
                if let Some(rest) = t.strip_prefix(kw) {
                    let name: String = rest.chars().take_while(|c| word_char(*c)).collect();
                    if segments(&name)
                        .iter()
                        .any(|s| s == "legacy" || s == "compat")
                    {
                        found.push(format!("{path}: {kw}{name}"));
                    }
                }
            }
        }
    }
    let rpc = std::fs::read_to_string(gate::repo_root().join("crates/tenzro-node/src/rpc.rs"))
        .expect("rpc.rs");
    for (i, line) in gate::non_test(&rpc).lines().enumerate() {
        let names = gate::rpc_names_in("rpc.rs", line);
        if names.len() > 1 && line.contains('|') && line.contains("=>") {
            found.push(format!(
                "crates/tenzro-node/src/rpc.rs:{}: method alias",
                i + 1
            ));
        }
    }
    assert!(
        found.is_empty(),
        "compatibility paths in protocol crates:\n  {}",
        found.join("\n  ")
    );
}

/// Held-over harness lines still waiting for their removal commit. The ceiling
/// only goes down: removing a line lowers it, nothing may raise it.
const PENDING_REMOVAL_H_CEILING: usize = 11;

/// The approved surface: kind -> name -> class. Every P, R and N line names a
/// decision-log entry in docs/LAYERS.md.
fn approved() -> BTreeMap<String, BTreeMap<String, String>> {
    let text = std::fs::read_to_string(
        gate::repo_root().join("crates/tenzro-types/tests/support/protocol_surface.txt"),
    )
    .expect("protocol_surface.txt");
    let log =
        std::fs::read_to_string(gate::repo_root().join("docs/LAYERS.md")).expect("docs/LAYERS.md");
    let mut out: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut held_over = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        assert!(
            matches!(parts[2], "P" | "R" | "N" | "H"),
            "class must be P, R or N (U is not allowed, H only as a held-over removal): {line}"
        );
        if parts[2] == "H" {
            assert_eq!(parts.len(), 3, "malformed surface line: {line}");
            held_over += 1;
        } else {
            assert_eq!(
                parts.len(),
                4,
                "P, R and N lines name a decision-log id: {line}"
            );
            assert!(
                log.contains(&format!("### {}\n", parts[3])),
                "decision-log id {} has no entry in docs/LAYERS.md: {line}",
                parts[3]
            );
        }
        out.entry(parts[0].to_string())
            .or_default()
            .insert(parts[1].to_string(), parts[2].to_string());
    }
    assert!(
        held_over <= PENDING_REMOVAL_H_CEILING,
        "{held_over} H lines exceed the ceiling {PENDING_REMOVAL_H_CEILING}: H lines may only be removed"
    );
    out
}

fn native_modules() -> BTreeSet<String> {
    let root = gate::repo_root().join("crates/tenzro-vm/src/native");
    let mut out = BTreeSet::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).expect("native dir").flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.ends_with(".rs")
                || name == "mod.rs"
                || name == "tests.rs"
                || name.ends_with("_tests.rs")
            {
                continue;
            }
            let r = rel(&root, &p);
            out.insert(r.trim_end_matches(".rs").to_string());
        }
    }
    out
}

fn native_selectors() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (_, text) in gate::files(&["crates/tenzro-vm/src"], &[".rs"]) {
        for (i, _) in text.match_indices("pub const SELECTOR_") {
            let name: String = text[i + "pub const ".len()..]
                .chars()
                .take_while(|c| word_char(*c))
                .collect();
            out.insert(name);
        }
    }
    out
}

fn namespace(method: &str) -> String {
    let parts: Vec<&str> = method.split('_').collect();
    match parts.len() {
        1 => "solana".to_string(),
        2 => parts[0].to_string(),
        _ => format!("{}_{}", parts[0], parts[1]),
    }
}

#[test]
fn the_protocol_surface_is_on_the_approved_list() {
    let approved = approved();
    let empty = BTreeMap::new();
    let listed = |kind: &str| approved.get(kind).unwrap_or(&empty).clone();
    let methods = gate::rpc_methods();
    let actual: [(&str, BTreeSet<String>); 4] = [
        ("native", native_modules()),
        ("selector", native_selectors()),
        ("namespace", methods.iter().map(|m| namespace(m)).collect()),
        ("rpc", methods),
    ];
    let mut unlisted = Vec::new();
    let mut stale = Vec::new();
    for (kind, names) in &actual {
        let list = listed(kind);
        assert!(!names.is_empty(), "no {kind} entries found in the source");
        for n in names {
            if !list.contains_key(n) {
                unlisted.push(format!("{kind} {n}"));
            }
        }
        for n in list.keys() {
            if !names.contains(n) {
                stale.push(format!("{kind} {n}"));
            }
        }
    }
    if !stale.is_empty() {
        eprintln!(
            "protocol_surface.txt lists entries the source no longer has; remove them:\n  {}",
            stale.join("\n  ")
        );
    }
    assert!(
        unlisted.is_empty(),
        "protocol surface not on the approved list (crates/tenzro-types/tests/support/protocol_surface.txt); \
         a protocol or node-role addition is listed there as P or R, application logic belongs in a harness:\n  {}",
        unlisted.join("\n  ")
    );
}
