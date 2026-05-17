//! Explicit, operator-invoked validator keygen.
//!
//! This module is reachable only from the `tenzro-node init` subcommand
//! (see `main.rs`). The running node's `init_consensus()` path never
//! generates keys — it loads existing files and errors loudly if they
//! are missing, per the universal production-BFT norm (Aptos, Sui,
//! Cosmos/CometBFT, Solana, Monad, Ethereum CL clients, Celestia,
//! Babylon, Berachain — none do silent daemon-side keygen on start).
//!
//! Silent first-boot auto-keygen on a misconfigured / empty /
//! re-mounted volume silently forks a fresh validator identity:
//! the operator can't distinguish "fresh boot, identity created" from
//! "mount lost, identity recreated, stake bonded to dead pubkey,
//! slashing imminent." Explicit `init` keeps that fault loud.
//!
//! ## Persisted files
//!
//! All three are written to `{data_dir}/` with mode `0o600` on Unix:
//!
//! | File | Contents | Pubkey derivation |
//! |------|----------|-------------------|
//! | `validator_key` | Ed25519 keypair bytes (`KeyPair::to_bytes()`) | 32-byte Ed25519 public key |
//! | `validator_pq_key` | 32-byte ML-DSA-65 seed | 1952-byte ML-DSA-65 verifying key |
//! | `validator_bls_key` | 32-byte BLS12-381 secret scalar | 48-byte G1-compressed `min_pk` pubkey |
//!
//! ## Genesis v3 schema
//!
//! The three pubkeys correspond one-to-one with the three mandatory
//! fields on `GenesisValidator` (`public_key`, `pq_public_key`,
//! `bls_public_key`). The `init` subcommand emits a ready-to-paste
//! `[[validators]]` TOML stanza so an operator can assemble genesis v3
//! without manually deriving any of the three pubkeys.

use std::path::Path;

use tenzro_crypto::bls::{BlsKeyPair, BlsSecretKey};
use tenzro_crypto::pq::MlDsaSigningKey;
use tenzro_crypto::{KeyPair, KeyType};

use crate::error::{NodeError, Result};

/// One generated validator keyset. Holds private material in memory;
/// `into_pubkeys()` discards the secrets and yields just the public
/// halves for genesis assembly.
pub struct ValidatorKeyset {
    pub keypair: KeyPair,
    pub pq: MlDsaSigningKey,
    pub bls: BlsKeyPair,
}

/// The public-only projection of a `ValidatorKeyset`. Safe to print and
/// serialize.
#[derive(Clone)]
pub struct ValidatorPubkeys {
    /// 32-byte Ed25519 public key
    pub ed25519: Vec<u8>,
    /// 1952-byte ML-DSA-65 verifying key
    pub ml_dsa_65: Vec<u8>,
    /// 48-byte BLS12-381 G1-compressed `min_pk` pubkey
    pub bls12_381_g1: Vec<u8>,
}

impl ValidatorKeyset {
    /// Project to the public-only view; secret material is dropped at
    /// the end of this call's stack frame.
    pub fn pubkeys(&self) -> ValidatorPubkeys {
        ValidatorPubkeys {
            ed25519: self.keypair.public_key().as_bytes().to_vec(),
            ml_dsa_65: self.pq.verifying_key_bytes().to_vec(),
            bls12_381_g1: self.bls.public_key().to_bytes().to_vec(),
        }
    }
}

impl ValidatorPubkeys {
    /// Render this validator's three pubkeys as a `[[validators]]` TOML
    /// stanza suitable for direct concatenation into a genesis v3 file.
    ///
    /// `stake` is denominated in the smallest TNZO unit the genesis
    /// parser expects (`GenesisValidator::stake: u64`).
    pub fn to_genesis_toml(&self, stake: u64) -> String {
        let mut s = String::new();
        s.push_str("[[validators]]\n");
        s.push_str(&format!("public_key = \"0x{}\"\n", hex::encode(&self.ed25519)));
        s.push_str(&format!(
            "pq_public_key = \"0x{}\"\n",
            hex::encode(&self.ml_dsa_65)
        ));
        s.push_str(&format!(
            "bls_public_key = \"0x{}\"\n",
            hex::encode(&self.bls12_381_g1)
        ));
        s.push_str(&format!("stake = {}\n", stake));
        s
    }
}

/// Generate a fresh Ed25519 + ML-DSA-65 + BLS12-381 keyset and persist
/// all three secret files under `data_dir` with `0o600` permissions on
/// Unix.
///
/// Errors:
/// - `NodeError::KeysAlreadyExist` if any of the three files already
///   exists and `force` is `false`. This is the safety rail that
///   prevents `init` from accidentally overwriting an existing
///   validator identity.
/// - `NodeError::Other` on crypto / IO failures.
pub fn generate_and_persist_keyset(
    data_dir: &Path,
    force: bool,
) -> Result<ValidatorKeyset> {
    std::fs::create_dir_all(data_dir)
        .map_err(|e| NodeError::Other(format!("create data_dir {}: {}", data_dir.display(), e)))?;

    let ed_path = data_dir.join("validator_key");
    let pq_path = data_dir.join("validator_pq_key");
    let bls_path = data_dir.join("validator_bls_key");

    if !force {
        let mut existing = Vec::new();
        for p in [&ed_path, &pq_path, &bls_path] {
            if p.exists() {
                existing.push(p.display().to_string());
            }
        }
        if !existing.is_empty() {
            return Err(NodeError::KeysAlreadyExist(existing.join(", ")));
        }
    }

    let keypair = KeyPair::generate(KeyType::Ed25519)
        .map_err(|e| NodeError::Other(format!("Ed25519 keygen: {}", e)))?;
    let pq = MlDsaSigningKey::generate();
    let bls = BlsKeyPair::generate()
        .map_err(|e| NodeError::Other(format!("BLS keygen: {}", e)))?;

    write_secret(&ed_path, &keypair.to_bytes())?;
    write_secret(&pq_path, pq.seed_bytes())?;
    write_secret(&bls_path, &bls.secret_key().to_bytes())?;

    Ok(ValidatorKeyset { keypair, pq, bls })
}

/// Load the validator Ed25519 keypair from `{data_dir}/validator_key`.
/// Returns `NodeError::KeyMissing` if the file does not exist — the
/// node binary on `start` MUST fail loud here rather than generate.
pub fn load_validator_keypair(data_dir: &Path) -> Result<KeyPair> {
    let key_path = data_dir.join("validator_key");
    if !key_path.exists() {
        return Err(NodeError::KeyMissing {
            kind: "Ed25519 validator key",
            path: key_path.display().to_string(),
            hint: "run `tenzro-node init --data-dir <dir>` to generate",
        });
    }
    let bytes = std::fs::read(&key_path)
        .map_err(|e| NodeError::Other(format!("read {}: {}", key_path.display(), e)))?;
    KeyPair::from_bytes(KeyType::Ed25519, &bytes)
        .map_err(|e| NodeError::Other(format!("decode {}: {}", key_path.display(), e)))
}

/// Load the validator ML-DSA-65 signing key from
/// `{data_dir}/validator_pq_key`. Returns `NodeError::KeyMissing` if
/// the file does not exist.
pub fn load_validator_pq_key(data_dir: &Path) -> Result<MlDsaSigningKey> {
    let key_path = data_dir.join("validator_pq_key");
    if !key_path.exists() {
        return Err(NodeError::KeyMissing {
            kind: "ML-DSA-65 validator key",
            path: key_path.display().to_string(),
            hint: "run `tenzro-node init --data-dir <dir>` to generate",
        });
    }
    let bytes = std::fs::read(&key_path)
        .map_err(|e| NodeError::Other(format!("read {}: {}", key_path.display(), e)))?;
    MlDsaSigningKey::from_seed(&bytes)
        .map_err(|e| NodeError::Other(format!("decode {}: {}", key_path.display(), e)))
}

/// Load the validator BLS12-381 (`min_pk`) signing key from
/// `{data_dir}/validator_bls_key`. Returns `NodeError::KeyMissing` if
/// the file does not exist.
pub fn load_validator_bls_key(data_dir: &Path) -> Result<BlsKeyPair> {
    let key_path = data_dir.join("validator_bls_key");
    if !key_path.exists() {
        return Err(NodeError::KeyMissing {
            kind: "BLS12-381 validator key",
            path: key_path.display().to_string(),
            hint: "run `tenzro-node init --data-dir <dir>` to generate",
        });
    }
    let bytes = std::fs::read(&key_path)
        .map_err(|e| NodeError::Other(format!("read {}: {}", key_path.display(), e)))?;
    BlsSecretKey::from_bytes(&bytes)
        .map(BlsKeyPair::from_secret_key)
        .map_err(|e| NodeError::Other(format!("decode {}: {}", key_path.display(), e)))
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)
        .map_err(|e| NodeError::Other(format!("write {}: {}", path.display(), e)))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| NodeError::Other(format!("chmod 600 {}: {}", path.display(), e)))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn generate_then_load_roundtrip() {
        let dir = tempdir().unwrap();
        let ks = generate_and_persist_keyset(dir.path(), false).expect("generate");
        let pubs = ks.pubkeys();
        assert_eq!(pubs.ed25519.len(), 32);
        assert_eq!(pubs.ml_dsa_65.len(), 1952);
        assert_eq!(pubs.bls12_381_g1.len(), 48);

        let loaded_ed = load_validator_keypair(dir.path()).expect("load ed25519");
        assert_eq!(loaded_ed.public_key().as_bytes(), pubs.ed25519.as_slice());

        let loaded_pq = load_validator_pq_key(dir.path()).expect("load pq");
        assert_eq!(loaded_pq.verifying_key_bytes().to_vec(), pubs.ml_dsa_65);

        let loaded_bls = load_validator_bls_key(dir.path()).expect("load bls");
        assert_eq!(loaded_bls.public_key().to_bytes().to_vec(), pubs.bls12_381_g1);
    }

    #[test]
    fn refuses_to_overwrite_without_force() {
        let dir = tempdir().unwrap();
        generate_and_persist_keyset(dir.path(), false).expect("first generate");
        // Use a match instead of `expect_err`: `ValidatorKeyset`
        // intentionally doesn't implement Debug (would leak secret
        // material into panic messages), and `expect_err` requires it.
        match generate_and_persist_keyset(dir.path(), false) {
            Err(NodeError::KeysAlreadyExist(_)) => {}
            Err(other) => panic!("expected KeysAlreadyExist, got {:?}", other),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn force_overwrites_existing() {
        let dir = tempdir().unwrap();
        let first = generate_and_persist_keyset(dir.path(), false).expect("first");
        let second = generate_and_persist_keyset(dir.path(), true).expect("force overwrite");
        // New keypair must differ from the old one.
        assert_ne!(
            first.pubkeys().ed25519,
            second.pubkeys().ed25519,
            "force must rotate keys"
        );
    }

    #[test]
    fn load_missing_returns_key_missing() {
        let dir = tempdir().unwrap();
        // `KeyPair` doesn't implement Debug either (secret-material
        // hygiene), so match instead of `expect_err`.
        match load_validator_keypair(dir.path()) {
            Err(NodeError::KeyMissing { kind, .. }) => {
                assert_eq!(kind, "Ed25519 validator key");
            }
            Err(other) => panic!("expected KeyMissing, got {:?}", other),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn genesis_toml_has_three_pubkeys() {
        let dir = tempdir().unwrap();
        let ks = generate_and_persist_keyset(dir.path(), false).unwrap();
        let toml = ks.pubkeys().to_genesis_toml(1_000_000);
        assert!(toml.contains("[[validators]]"));
        assert!(toml.contains("public_key = \"0x"));
        assert!(toml.contains("pq_public_key = \"0x"));
        assert!(toml.contains("bls_public_key = \"0x"));
        assert!(toml.contains("stake = 1000000"));
    }
}
