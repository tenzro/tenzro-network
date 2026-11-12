//! Guard: every config file the repository ships for a node parses through
//! the loader the node uses. A file that carries a key the loader does not
//! know is a node that aborts at start-up, so it fails here, in the build.

use std::path::{Path, PathBuf};

use tenzro_node::config::GenesisConfig;
use tenzro_node::network_profile::NetworkProfile;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn toml_files(dir: &Path, prefix: &str) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| {
            p.extension().is_some_and(|x| x == "toml")
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(prefix))
        })
        .collect();
    files.sort();
    files
}

#[test]
fn every_shipped_network_profile_parses_for_its_own_chain() {
    let dir = repo().join("config/network");
    let mut seen = 0;
    for path in toml_files(&dir, "") {
        let chain: u64 = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("{}: name is not a chain id", path.display()));
        let text = std::fs::read_to_string(&path).unwrap();
        let profile = NetworkProfile::parse(&text, chain)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert_eq!(profile.chain_id, chain);
        seen += 1;
    }
    assert!(seen >= 1, "no network profile found in {}", dir.display());
}

#[test]
fn every_shipped_genesis_input_parses() {
    let root = repo();
    let mut files = toml_files(&root.join("config"), "genesis");
    files.extend(toml_files(&root.join("scripts/testnet/privnet"), "genesis"));
    files.extend(toml_files(&root.join("crates/tenzro-node/genesis"), ""));
    assert!(!files.is_empty());
    for path in files {
        let text = std::fs::read_to_string(&path).unwrap();
        toml::from_str::<GenesisConfig>(&text)
            .unwrap_or_else(|e| panic!("{} does not parse as a genesis: {e}", path.display()));
    }
}
