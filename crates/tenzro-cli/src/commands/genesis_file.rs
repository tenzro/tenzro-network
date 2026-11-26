//! The genesis file as a light client reads it: the validators that form the
//! first committee, and the seat budget they share.

use std::path::Path;

use anyhow::{Context, Result, anyhow};
use serde::Deserialize;
use tenzro_consensus::{ConsensusConfig, ValidatorInfo, ValidatorPublicKey};
use tenzro_types::primitives::Address;

#[derive(Deserialize)]
struct GenesisFile {
    validators: Vec<Validator>,
    #[serde(default)]
    consensus: Consensus,
}

#[derive(Deserialize)]
struct Validator {
    address: String,
    ml_dsa_public_key: String,
    p256_public_key: String,
    node_key: String,
    stake: u64,
}

#[derive(Deserialize, Default)]
struct Consensus {
    seat_budget: Option<u64>,
}

fn bytes(what: &str, hex_text: &str) -> Result<Vec<u8>> {
    hex::decode(hex_text.trim().trim_start_matches("0x"))
        .with_context(|| format!("genesis validator {what} is not hex"))
}

fn bytes32(what: &str, hex_text: &str) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(bytes(what, hex_text)?.as_slice())
        .map_err(|_| anyhow!("genesis validator {what} must be 32 bytes"))
}

/// Root of the committee the genesis text names.
pub fn committee_root_of(genesis: &str) -> Result<[u8; 32]> {
    let file: GenesisFile = toml::from_str(genesis).context("the genesis file does not parse")?;
    let validators = file
        .validators
        .iter()
        .map(|v| {
            let key = ValidatorPublicKey::new(
                bytes("ml_dsa_public_key", &v.ml_dsa_public_key)?,
                bytes("p256_public_key", &v.p256_public_key)?,
            )
            .map_err(|e| anyhow!("genesis validator {}: {e}", v.address))?;
            Ok(ValidatorInfo::new(
                Address::new(bytes32("address", &v.address)?),
                key,
                bytes32("node_key", &v.node_key)?,
                v.stake as u128,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let seat_budget = file
        .consensus
        .seat_budget
        .unwrap_or(ConsensusConfig::default().seat_budget);
    let committee = tenzro_consensus::committee::genesis_committee(validators, seat_budget)
        .map_err(|e| anyhow!("the genesis validators do not form a committee: {e}"))?;
    Ok(committee.root())
}

/// Root of the committee the genesis file at `path` names.
pub fn committee_root(path: &Path) -> Result<[u8; 32]> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read the genesis file {}", path.display()))?;
    committee_root_of(&text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn genesis(stakes: &[u64], seat_budget: Option<u64>) -> (String, Vec<ValidatorInfo>) {
        use tenzro_consensus::ValidatorSigner as _;
        use tenzro_consensus::validator_key::test_signer::SoftwareTestSigner;

        let mut text = String::from("chain_id = 7\n");
        let mut infos = Vec::new();
        for (party, stake) in stakes.iter().enumerate() {
            let key = SoftwareTestSigner::from_seed(party as u64)
                .public_key()
                .clone();
            let address = Address::new([party as u8 + 1; 32]);
            let node_key = [party as u8 + 101; 32];
            text.push_str(&format!(
                "[[validators]]\naddress = \"0x{}\"\nml_dsa_public_key = \"{}\"\np256_public_key = \"{}\"\nnode_key = \"{}\"\nproof_of_possession = \"00\"\nstake = {stake}\n",
                hex::encode(address.0),
                hex::encode(&key.ml_dsa),
                hex::encode(&key.p256),
                hex::encode(node_key),
            ));
            infos.push(ValidatorInfo::new(address, key, node_key, *stake as u128));
        }
        if let Some(budget) = seat_budget {
            text.push_str(&format!("[consensus]\nseat_budget = {budget}\n"));
        }
        (text, infos)
    }

    #[test]
    fn the_root_read_from_a_genesis_file_is_the_root_of_its_first_committee() {
        let (text, infos) = genesis(&[5, 5, 5, 5], Some(40));
        let expected = tenzro_consensus::committee::genesis_committee(infos, 40)
            .unwrap()
            .root();
        assert_eq!(committee_root_of(&text).unwrap(), expected);
    }

    #[test]
    fn a_different_stake_or_no_validators_gives_another_answer() {
        let (even, _) = genesis(&[5, 5, 5, 5], None);
        let (uneven, _) = genesis(&[5, 5, 5, 9], None);
        assert_ne!(
            committee_root_of(&even).unwrap(),
            committee_root_of(&uneven).unwrap()
        );
        assert!(committee_root_of("chain_id = 7\nvalidators = []\n").is_err());
    }
}
