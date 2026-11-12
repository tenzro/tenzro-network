//! The launch rules as a build stage: a genesis whose validator set cannot
//! survive one failure fails the build.
//!
//! `config/genesis-launch.toml` and `config/genesis-prod.toml` are templates
//! (`validators = []`) until the founding validators' entries are pasted in at
//! launch; a template is checked to be a template. A filled genesis is checked
//! with `tenzro_consensus::launch_check::check_launch_set`: at least four
//! validators, live ones above two thirds of the stake, and a live spare. Every
//! `[[validators]]` entry is produced by `GenesisValidator::from_local_hardware`
//! and carries the hardware consensus key's proof of possession, so a hardware
//! identity is a property of the entry.
//!
//! Which validators are live at launch is not in the file. The launch
//! procedure lists the addresses that answered a hardware-signed challenge in
//! `TENZRO_LAUNCH_LIVE` (comma-separated); when it is unset every entry is
//! assumed live, which is the right assumption for the structural check CI
//! runs. `TENZRO_LAUNCH_GENESIS` adds a genesis file to check; its governed
//! parameters are held to the registry bounds as well.

use std::path::{Path, PathBuf};

use tenzro_consensus::launch_check::{LaunchValidator, check_launch_set};
use tenzro_node::config::GenesisConfig;

fn config_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config")
}

fn set_of(g: &GenesisConfig) -> Vec<LaunchValidator> {
    let live: Option<Vec<String>> = std::env::var("TENZRO_LAUNCH_LIVE")
        .ok()
        .map(|v| v.split(',').map(|s| s.trim().to_lowercase()).collect());
    g.validators
        .iter()
        .map(|v| LaunchValidator {
            name: v.address.clone(),
            stake: u128::from(v.stake),
            live: live
                .as_ref()
                .is_none_or(|l| l.contains(&v.address.to_lowercase())),
            hardware_identity: !v.proof_of_possession.is_empty() && !v.node_key_proof.is_empty(),
        })
        .collect()
}

fn check_file(path: &Path) {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let g: GenesisConfig =
        toml::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    // The node refuses a genesis whose governed parameters are outside the
    // registry bounds, so the stage refuses it too, before any host starts.
    if let Err(refusal) = g.network_params() {
        panic!(
            "{}: the governed parameters are refused: {refusal}",
            path.display()
        );
    }
    if g.validators.is_empty() {
        // A template. The check runs when the entries are filled in.
        return;
    }
    if let Err(refusal) = check_launch_set(&set_of(&g)) {
        panic!(
            "{}: the validator set is refused: {refusal}",
            path.display()
        );
    }
}

#[test]
fn the_launch_and_production_genesis_files_pass_the_launch_rules() {
    check_file(&config_dir().join("genesis-launch.toml"));
    check_file(&config_dir().join("genesis-prod.toml"));
    if let Ok(extra) = std::env::var("TENZRO_LAUNCH_GENESIS") {
        check_file(Path::new(&extra));
    }
}

#[test]
fn a_filled_genesis_of_the_2026_shape_would_fail_this_stage() {
    // Four equal validators, one permanently gone: refused.
    let set: Vec<LaunchValidator> = (0..4)
        .map(|i| LaunchValidator {
            name: format!("v{i}"),
            stake: 5_000_000,
            live: i != 3,
            hardware_identity: true,
        })
        .collect();
    assert!(check_launch_set(&set).is_err());
}

/// The shipped active-set floor is the launch minimum, derived from the same
/// arithmetic as the launch check, so ejection can never be configured to
/// leave a set the launch check would refuse.
#[test]
fn the_shipped_active_set_floor_is_the_launch_minimum() {
    for name in ["genesis-launch.toml", "genesis-prod.toml"] {
        let path = config_dir().join(name);
        let text = std::fs::read_to_string(&path).unwrap();
        let g: GenesisConfig = toml::from_str(&text).unwrap();
        let floor = g
            .network_params()
            .unwrap()
            .into_iter()
            .find(|(k, _)| *k == "staking.active_set_floor")
            .map(|(_, v)| v)
            .expect("the floor is a governed parameter");
        assert!(
            floor >= tenzro_consensus::launch_check::MIN_LAUNCH_VALIDATORS as u64,
            "{name}: staking.active_set_floor = {floor} is below the launch minimum"
        );
    }
}
