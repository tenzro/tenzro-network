//! The supply-chain configuration exists, pins, and matches the policy file. A drift (a tool that
//! stops running in CI, an action named by tag, a registry added to one list and not the other, an
//! advisory accepted without a reason) fails here.

use std::fs;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn strings_in_list(text: &str, key: &str) -> Vec<String> {
    let start = text
        .find(&format!("{key} = ["))
        .unwrap_or_else(|| panic!("no {key} list"));
    let rest = &text[start..];
    let end = rest.find(']').expect("list ends");
    rest[..end]
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

#[test]
fn the_files_the_policy_names_exist() {
    for f in [
        "supply-chain/policy.toml",
        "supply-chain/config.toml",
        "supply-chain/audits.toml",
        "supply-chain/imports.lock",
        "deny.toml",
        ".cargo/audit.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "scripts/testnet/security/tools.env",
        "scripts/supply-chain/check-pins.sh",
        "scripts/supply-chain/advisory-gate.sh",
        "scripts/supply-chain/release.sh",
        ".github/workflows/supply-chain.yml",
        "docs/SUPPLY-CHAIN.md",
    ] {
        assert!(root().join(f).is_file(), "{f} is missing");
    }
    assert!(read("supply-chain/config.toml").contains("[cargo-vet]"));
}

#[test]
fn deny_toml_is_strict_and_lists_the_sources_the_policy_lists() {
    let deny = read("deny.toml");
    let policy = read("supply-chain/policy.toml");
    assert!(
        deny.contains("yanked = \"deny\""),
        "a yanked crate must fail the build"
    );
    assert!(deny.contains("unknown-registry = \"deny\""));
    assert!(deny.contains("unknown-git = \"deny\""));
    assert_eq!(
        strings_in_list(&deny, "allow-registry"),
        vec![sources_registry(&policy)],
        "deny.toml and the policy name different registries"
    );
    let mut in_deny = strings_in_list(&deny, "allow-git");
    let mut in_policy = strings_in_list(&policy, "git");
    in_deny.sort();
    in_policy.sort();
    assert_eq!(
        in_deny, in_policy,
        "deny.toml and the policy name different git sources"
    );
}

fn sources_registry(policy: &str) -> String {
    policy
        .lines()
        .find_map(|l| l.trim().strip_prefix("registry = "))
        .map(|v| v.trim().trim_matches('"').to_string())
        .expect("the policy names the registry")
}

#[test]
fn every_accepted_advisory_carries_a_reason() {
    for file in ["deny.toml", ".cargo/audit.toml"] {
        let text = read(file);
        for (n, line) in text.lines().enumerate() {
            let l = line.trim();
            if l.starts_with("{ id =") {
                assert!(
                    l.contains("reason ="),
                    "{file}:{} accepts an advisory without a reason: {l}",
                    n + 1
                );
            }
        }
    }
}

#[test]
fn the_toolchain_and_the_security_tools_are_pinned_exactly() {
    let tc = read("rust-toolchain.toml");
    let channel = tc
        .lines()
        .find_map(|l| l.trim().strip_prefix("channel"))
        .and_then(|v| v.split('"').nth(1))
        .expect("a channel");
    assert!(
        channel.chars().all(|c| c.is_ascii_digit() || c == '.')
            && channel.matches('.').count() == 2,
        "rust-toolchain.toml channel {channel} is not an exact version"
    );
    let env = read("scripts/testnet/security/tools.env");
    for tool in [
        "CARGO_AUDIT_VERSION",
        "CARGO_DENY_VERSION",
        "CARGO_VET_VERSION",
    ] {
        let v = env
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{tool}=")))
            .unwrap_or_else(|| panic!("{tool} is not pinned"));
        assert!(
            v.split('.').count() == 3 && v.split('.').all(|p| p.parse::<u32>().is_ok()),
            "{tool}={v} is not an exact version"
        );
    }
}

#[test]
fn the_workflow_runs_every_gate_with_the_pinned_tools() {
    let wf = read(".github/workflows/supply-chain.yml");
    let policy = read("supply-chain/policy.toml");
    for step in strings_in_list(&policy, "steps") {
        assert!(wf.contains(&step), "the workflow no longer runs `{step}`");
    }
    assert!(
        wf.contains("scripts/testnet/security/tools.env"),
        "tool versions come from tools.env"
    );
    for tool in ["cargo-deny", "cargo-audit", "cargo-vet"] {
        assert!(
            wf.contains(&format!("cargo install --locked {tool} --version")),
            "{tool} is not installed locked at a pinned version"
        );
    }
    assert!(
        wf.contains("schedule:"),
        "a weekly run catches new advisories on an unchanged lockfile"
    );
}

#[test]
fn every_action_is_named_by_commit_and_every_cargo_call_is_locked() {
    let dir = root().join(".github/workflows");
    for entry in fs::read_dir(&dir).expect("workflows") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("yml") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        let text = fs::read_to_string(&path).unwrap();
        for (n, line) in text.lines().enumerate() {
            let l = line.trim();
            if let Some(rest) = l
                .strip_prefix("- uses: ")
                .or_else(|| l.strip_prefix("uses: "))
            {
                let spec = rest.split_whitespace().next().unwrap();
                if spec.starts_with("./") {
                    continue;
                }
                let sha = spec.split('@').nth(1).unwrap_or("");
                assert!(
                    sha.len() == 40 && sha.chars().all(|c| c.is_ascii_hexdigit()),
                    "{name}:{} names {spec} by tag or branch, not by commit",
                    n + 1
                );
            }
            for sub in ["build", "test", "check", "clippy", "bench"] {
                let call = format!("cargo {sub} ");
                if l.contains(&call) && !l.starts_with('#') {
                    assert!(
                        l.contains("--locked") || l.contains("--offline"),
                        "{name}:{} runs `cargo {sub}` without --locked",
                        n + 1
                    );
                }
            }
        }
    }
}
