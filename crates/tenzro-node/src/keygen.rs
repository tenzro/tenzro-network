//! Explicit, operator-invoked validator keygen.
//!
//! This module is reachable only from the `tenzro-node init` subcommand
//! (see `main.rs`). The running node's `init_consensus()` path never
//! generates keys — it loads existing files and errors loudly if they
//! are missing, per the universal production-BFT norm — none of the
//! established BFT stacks do silent daemon-side keygen on start.
//!
//! Silent first-boot auto-keygen on a misconfigured / empty /
//! re-mounted volume silently forks a fresh validator identity:
//! the operator can't distinguish "fresh boot, identity created" from
//! "mount lost, identity recreated, stake bonded to dead pubkey,
//! slashing imminent." Explicit `init` keeps that fault loud.
//!
//! ## Key custody at rest
//!
//! Secrets are never written in the clear when there is any alternative.
//! `write_secret` tries, in order:
//!
//! 1. **TPM-sealed** — `{file}.sealed/`, bound to this machine's TPM storage
//!    hierarchy, so a copied blob is inert on any other host. Covers Intel
//!    PTT, AMD fTPM, discrete TPMs, and ARM/Jetson via OP-TEE's fTPM.
//! 2. **Encrypted at rest** — `{file}.enc`, AES-256-GCM under an Argon2id key
//!    derived from the operator's unlock secret (a passkey-gated device key,
//!    or their KMS on a headless validator). This is the path for hosts with
//!    no TPM, which notably includes **every Apple machine** — Apple ships a
//!    Secure Enclave, not a TPM, so a TPM-only design would exclude them.
//! 3. **Plaintext `0o600`** — last resort only, when neither is available,
//!    and logged loudly at both write and read. Mode bits stop another user;
//!    they stop nothing that can read the disk.
//!
//! Reads reverse the same order, so a node upgraded to stronger custody never
//! silently falls back to a stale plaintext copy.
//!
//! ## Persisted files
//!
//! Under `{data_dir}/`, in whichever of the three forms above applies:
//!
//! | File | Contents | Pubkey derivation |
//! |------|----------|-------------------|
//! | `validator_key` | Ed25519 keypair bytes (`KeyPair::to_bytes()`) | 32-byte Ed25519 public key |
//! | `validator_pq_key` | 32-byte ML-DSA-65 seed | 1952-byte ML-DSA-65 verifying key |
//! | `validator_bls_key` | 32-byte BLS12-381 secret scalar | 48-byte G1-compressed `min_pk` pubkey |
//! | `validator_erc8004_system_key` | 32-byte secp256k1 secret scalar | 20-byte EVM address (Keccak-256 of uncompressed pubkey) |
//!
//! ## `validator_erc8004_system_key` — special case
//!
//! Unlike the three validator-identity keys, the `erc8004-system` key is
//! a per-node EVM-submitter key used only for **two internal writers**
//! that lack a caller signature: the TDIP `NativeErc8004Mirror`
//! register dispatch and the Stripe SPT reputation dispatcher (see
//! `project_erc8004_evm_architecture` decision). Losing or rotating
//! this key does not fork the validator's consensus stake — it only
//! changes the `msg.sender` on those two internal write paths.
//!
//! For that reason `load_or_generate_erc8004_system_key()` is
//! **idempotent and silent-on-miss**: if the file is absent it is
//! generated and persisted in place, so existing data dirs upgraded
//! from a pre-ERC-8004-mirror binary do not require operator
//! intervention. This silent-generate exemption explicitly does NOT
//! extend to the three validator-identity keys above.
//!
//! ## Genesis v3 schema
//!
//! The three validator-identity pubkeys correspond one-to-one with the
//! three mandatory fields on `GenesisValidator` (`public_key`,
//! `pq_public_key`, `bls_public_key`). The `init` subcommand emits a
//! ready-to-paste `[[validators]]` TOML stanza so an operator can
//! assemble genesis v3 without manually deriving any of the three
//! pubkeys. The `erc8004-system` key is purely node-local and never
//! appears in genesis.

use std::path::Path;

use tenzro_crypto::bls::{BlsKeyPair, BlsSecretKey};
use tenzro_crypto::encryption::SymmetricKey;
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
        s.push_str(&format!(
            "public_key = \"0x{}\"\n",
            hex::encode(&self.ed25519)
        ));
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
pub fn generate_and_persist_keyset(data_dir: &Path, force: bool) -> Result<ValidatorKeyset> {
    std::fs::create_dir_all(data_dir)
        .map_err(|e| NodeError::Other(format!("create data_dir {}: {}", data_dir.display(), e)))?;

    let ed_path = data_dir.join("validator_key");
    let pq_path = data_dir.join("validator_pq_key");
    let bls_path = data_dir.join("validator_bls_key");

    if !force {
        let mut existing = Vec::new();
        for p in [&ed_path, &pq_path, &bls_path] {
            if secret_exists(p) {
                existing.push(p.display().to_string());
            }
        }
        if !existing.is_empty() {
            return Err(NodeError::KeysAlreadyExist(existing.join(", ")));
        }
    }

    // Derived from this machine's TPM where there is one, so a node that loses
    // its data directory comes back as itself rather than as a stranger. Each
    // key gets its own purpose label, so one of them leaking says nothing about
    // the others.
    //
    // Every one of these is reloaded from bytes on a normal start, which is why
    // deriving the bytes is the whole change: the key types already accept a
    // seed, and nothing downstream can tell where it came from.
    let keypair = KeyPair::from_bytes(KeyType::Ed25519, &fresh_secret("validator-ed25519"))
        .map_err(|e| NodeError::Other(format!("Ed25519 keygen: {}", e)))?;
    let pq = MlDsaSigningKey::from_seed(&fresh_secret("validator-ml-dsa"))
        .map_err(|e| NodeError::Other(format!("ML-DSA keygen: {}", e)))?;
    let bls = BlsKeyPair::from_secret_key(
        BlsSecretKey::from_bytes(&fresh_secret("validator-bls"))
            .map_err(|e| NodeError::Other(format!("BLS keygen: {}", e)))?,
    );

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
    if !secret_exists(&key_path) {
        return Err(NodeError::KeyMissing {
            kind: "Ed25519 validator key",
            path: key_path.display().to_string(),
            hint: "run `tenzro-node init --data-dir <dir>` to generate",
        });
    }
    let bytes = read_secret(&key_path)?;
    KeyPair::from_bytes(KeyType::Ed25519, &bytes)
        .map_err(|e| NodeError::Other(format!("decode {}: {}", key_path.display(), e)))
}

/// Load the validator ML-DSA-65 signing key from
/// `{data_dir}/validator_pq_key`. Returns `NodeError::KeyMissing` if
/// the file does not exist.
pub fn load_validator_pq_key(data_dir: &Path) -> Result<MlDsaSigningKey> {
    let key_path = data_dir.join("validator_pq_key");
    if !secret_exists(&key_path) {
        return Err(NodeError::KeyMissing {
            kind: "ML-DSA-65 validator key",
            path: key_path.display().to_string(),
            hint: "run `tenzro-node init --data-dir <dir>` to generate",
        });
    }
    let bytes = read_secret(&key_path)?;
    MlDsaSigningKey::from_seed(&bytes)
        .map_err(|e| NodeError::Other(format!("decode {}: {}", key_path.display(), e)))
}

/// Load the validator BLS12-381 (`min_pk`) signing key from
/// `{data_dir}/validator_bls_key`. Returns `NodeError::KeyMissing` if
/// the file does not exist.
pub fn load_validator_bls_key(data_dir: &Path) -> Result<BlsKeyPair> {
    let key_path = data_dir.join("validator_bls_key");
    if !secret_exists(&key_path) {
        return Err(NodeError::KeyMissing {
            kind: "BLS12-381 validator key",
            path: key_path.display().to_string(),
            hint: "run `tenzro-node init --data-dir <dir>` to generate",
        });
    }
    let bytes = read_secret(&key_path)?;
    BlsSecretKey::from_bytes(&bytes)
        .map(BlsKeyPair::from_secret_key)
        .map_err(|e| NodeError::Other(format!("decode {}: {}", key_path.display(), e)))
}

/// Load the per-node ERC-8004 system secp256k1 key from
/// `{data_dir}/validator_erc8004_system_key`, generating it in place if
/// the file does not exist.
///
/// Unlike the three validator-identity keys, this key is silent-generate
/// on miss — see the module-level rustdoc for why losing/rotating it
/// does not fork the validator's consensus stake.
///
/// Returns the raw 32-byte secp256k1 secret scalar, suitable for passing
/// directly to
/// [`tenzro_bridge::evm_signer::EvmTransactionSigner::new`].
pub fn load_or_generate_erc8004_system_key(data_dir: &Path) -> Result<[u8; 32]> {
    use k256::SecretKey;

    std::fs::create_dir_all(data_dir)
        .map_err(|e| NodeError::Other(format!("create data_dir {}: {}", data_dir.display(), e)))?;

    let key_path = data_dir.join("validator_erc8004_system_key");

    if secret_exists(&key_path) {
        let bytes = read_secret(&key_path)?;
        if bytes.len() != 32 {
            return Err(NodeError::Other(format!(
                "{} has wrong length {} (expected 32)",
                key_path.display(),
                bytes.len()
            )));
        }
        // Validate as a well-formed secp256k1 scalar (rejects 0 and
        // values >= curve order). We only care that decoding succeeds —
        // the returned key is discarded; the caller receives the raw
        // bytes.
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes);
        SecretKey::from_slice(&buf).map_err(|e| {
            NodeError::Other(format!(
                "{} is not a valid secp256k1 scalar: {}",
                key_path.display(),
                e
            ))
        })?;
        return Ok(buf);
    }

    // Establish the key, persisted at 0o600 (or sealed where there is a chip).
    //
    // Derived rather than drawn from the system random source, so a wiped data
    // directory does not change which on-chain account this node speaks as.
    // That was `SecretKey::generate_from_rng`, which needed the `Generate`
    // trait and a `SysRng` lifted through `UnwrapErr`; deriving needs neither,
    // which is why those imports went with it.
    let sk: SecretKey = SecretKey::from_slice(&fresh_secret("erc8004-system"))
        .map_err(|e| NodeError::Other(format!("secp256k1 keygen: {}", e)))?;
    let bytes = sk.to_bytes();
    write_secret(&key_path, &bytes)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    tracing::info!(
        target: "tenzro::keygen",
        path = %key_path.display(),
        "generated fresh erc8004-system secp256k1 key (first boot or missing-file recovery)"
    );
    Ok(out)
}

/// Load the per-node X25519 sealed-model recipient key from
/// `{data_dir}/model_recipient_x25519_key`, generating it in place if
/// the file does not exist.
///
/// This key is the node's decryption identity for sealed model shards:
/// publishers wrap the per-artifact content key to this key's public
/// half via `tenzro_crypto::envelope_encrypt`. Like the ERC-8004 system
/// key it is silent-generate on miss — rotating it only means the node
/// must be re-added as a recipient on manifests sealed after rotation;
/// it carries no consensus stake.
///
/// Returns the raw 32-byte X25519 secret, suitable for
/// [`tenzro_crypto::encryption::X25519KeyPair::from_secret_bytes`].
pub fn load_or_generate_model_recipient_key(data_dir: &Path) -> Result<[u8; 32]> {
    std::fs::create_dir_all(data_dir)
        .map_err(|e| NodeError::Other(format!("create data_dir {}: {}", data_dir.display(), e)))?;

    let key_path = data_dir.join("model_recipient_x25519_key");

    if secret_exists(&key_path) {
        let bytes = read_secret(&key_path)?;
        if bytes.len() != 32 {
            return Err(NodeError::Other(format!(
                "{} has wrong length {} (expected 32)",
                key_path.display(),
                bytes.len()
            )));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&bytes);
        return Ok(buf);
    }

    let buf = fresh_secret("model-recipient-x25519");
    write_secret(&key_path, &buf)?;
    tracing::info!(
        target: "tenzro::keygen",
        path = %key_path.display(),
        "established the sealed-model X25519 recipient key"
    );
    Ok(buf)
}

/// Fresh key material for a purpose, derived from this machine's TPM where it
/// can be, and drawn from the system random source where it cannot.
///
/// This is the difference between an identity a machine keeps and one it merely
/// stores. Sealing protects a random key well — the blob is worthless on
/// another machine — but it does not survive the blob going away, and deleting
/// a data directory is something any administrator, any reinstall and any
/// misfired `rm` can do. The node then comes back as somebody new and
/// everything that knew it has to be told again.
///
/// Derived material has no such failure. The TPM recomputes it from a hierarchy
/// seed that never leaves the chip, so a wiped disk, a fresh install or an empty
/// data directory all return the same identity. The only thing that changes it
/// is an administrator clearing the TPM from firmware, which is exactly who
/// should be able to retire a machine.
///
/// Falling back to randomness on a machine with no chip is deliberate and is
/// said out loud: refusing would make every TPM-less VM unusable, and staying
/// quiet would let an operator believe in a guarantee they do not have.
fn fresh_secret(purpose: &str) -> [u8; 32] {
    if tenzro_tee::tpm_derive::derivation_available() {
        match tenzro_tee::tpm_derive::derive_secret(purpose) {
            Ok(bytes) => {
                tracing::info!(
                    target: "tenzro::keygen",
                    purpose,
                    "derived key material from the TPM; this identity survives a wiped data directory"
                );
                return *bytes;
            }
            // Reported rather than swallowed. A node that silently fell back to
            // randomness here would look identical to one that derived, right
            // up until somebody cleared the directory and it came back a
            // stranger.
            Err(e) => tracing::warn!(
                target: "tenzro::keygen",
                purpose,
                error = %e,
                "could not derive from the TPM; falling back to random key material, \
                 which will NOT survive the data directory being cleared"
            ),
        }
    } else {
        tracing::warn!(
            target: "tenzro::keygen",
            purpose,
            "no TPM available to derive from; this identity lives only in the data directory"
        );
    }
    let mut buf = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

/// Directory holding the TPM-sealed form of the secret at `path`.
///
/// Sealing produces two blobs (public area + encrypted private area) rather
/// than one file, so each secret gets its own subdirectory beside the key it
/// replaces: `validator_key` seals into `validator_key.sealed/`.
fn sealed_dir_for(path: &Path) -> std::path::PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(".sealed");
    std::path::PathBuf::from(p)
}

/// Persist a secret, sealed to the TPM whenever this host has one.
///
/// A private key written as plaintext is readable by anything that can read
/// the filesystem — a stolen disk, a backup, a container escape, a stray
/// `tar`. Mode `0o600` stops another *user*; it stops nothing that runs as
/// this user or gets the bytes offline. Sealing binds the secret to this
/// TPM's storage hierarchy, so the blob is worthless if copied elsewhere,
/// which is exactly the property a machine's own identity has to have before
/// it can vouch for itself (autonomous registration, and the node-alias bind
/// consent that proves this machine agreed to answer for a name).
///
/// On a host with no usable TPM the secret still has to be persisted or the
/// node cannot run at all, so it falls back to `0o600` and says so loudly —
/// once, at the point of writing, rather than leaving the operator to infer
/// it. That is the honest position: refusing outright would make every
/// developer machine and TPM-less VM unusable, and silently degrading would
/// let an operator believe in protection they do not have.
/// Process-level flag: when set, key persistence MUST use hardware TPM sealing
/// and refuses to degrade to encrypt-at-rest or plaintext. Autonomous operator
/// mode sets this before keygen so a TPM permission/absence failure is a hard
/// error, never a silent unsealed-key fallback.
static REQUIRE_HW_SEAL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Require (or stop requiring) hardware TPM sealing for all subsequent key
/// writes in this process. Called by autonomous-operator setup.
pub fn set_require_hw_seal(require: bool) {
    REQUIRE_HW_SEAL.store(require, std::sync::atomic::Ordering::Relaxed);
}

fn write_secret(path: &Path, bytes: &[u8]) -> Result<()> {
    let sealed_dir = sealed_dir_for(path);
    if tenzro_tee::tpm_seal::tpm_available() {
        std::fs::create_dir_all(&sealed_dir)
            .map_err(|e| NodeError::Other(format!("create {}: {}", sealed_dir.display(), e)))?;
        match tenzro_tee::tpm_seal::seal(&sealed_dir, bytes) {
            Ok(()) => {
                // Remove any plaintext predecessor: leaving it behind would
                // mean the key is sealed and also still lying next to it.
                if path.exists() {
                    let _ = std::fs::remove_file(path);
                    tracing::info!(
                        target: "tenzro::keygen",
                        path = %path.display(),
                        "removed plaintext key superseded by its TPM-sealed form"
                    );
                }
                tracing::info!(
                    target: "tenzro::keygen",
                    dir = %sealed_dir.display(),
                    "secret sealed to TPM"
                );
                return Ok(());
            }
            Err(e) => {
                let _ = std::fs::remove_dir_all(&sealed_dir);
                if REQUIRE_HW_SEAL.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err(NodeError::Other(format!(
                        "operator=autonomous requires a hardware-sealed key but TPM sealing \
                         failed for {}: {e}. Refusing to write an unsealed key — fix TPM access \
                         (permissions / tpm2-tools) and re-run, or use --operator self.",
                        path.display()
                    )));
                }
                tracing::warn!(
                    target: "tenzro::keygen",
                    path = %path.display(),
                    "TPM present but sealing failed ({e}); falling back to a 0o600 file"
                );
            }
        }
    }

    // Autonomous operator: hardware sealing is mandatory. If control reaches
    // here the TPM is absent or sealing failed — refuse rather than degrade to
    // encrypt-at-rest or plaintext.
    if REQUIRE_HW_SEAL.load(std::sync::atomic::Ordering::Relaxed) {
        return Err(NodeError::Other(format!(
            "operator=autonomous requires TPM-sealed keys but no working TPM is available \
             for {}. Refusing to write an unsealed key.",
            path.display()
        )));
    }

    // No TPM — passkey custody. Both paths are first-class: a validator
    // without a TPM is not a lesser validator, it is one whose operator holds
    // the key behind their own authenticator. Never refuse and never fall
    // through to plaintext; encrypt at rest under the operator's unlock
    // secret, which on a desktop is a hardware-backed device key gated by a
    // passkey/biometric and on a headless validator is their configured
    // unlock source.
    if let Some(passphrase) = operator_unlock_secret() {
        let ciphertext = encrypt_at_rest(bytes, &passphrase)?;
        let enc_path = encrypted_path_for(path);
        std::fs::write(&enc_path, &ciphertext)
            .map_err(|e| NodeError::Other(format!("write {}: {}", enc_path.display(), e)))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&enc_path, std::fs::Permissions::from_mode(0o600));
        }
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }
        tracing::info!(
            target: "tenzro::keygen",
            path = %enc_path.display(),
            "no TPM — key encrypted at rest under the operator's passkey-gated unlock secret"
        );
        return Ok(());
    }

    // Neither TPM nor a configured unlock secret. Still persist — refusing
    // would brick first-run and dev hosts — but make the exposure explicit
    // rather than letting an operator assume protection they do not have.
    tracing::warn!(
        target: "tenzro::keygen",
        path = %path.display(),
        "writing this key as a 0o600 PLAINTEXT file: no TPM on this host and no operator \
         unlock secret configured. Mode bits stop another user, not anyone who can read the \
         disk. Install tpm2-tools on a TPM host, or configure your passkey-gated unlock \
         secret, then re-run keygen to upgrade this key in place"
    );
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

/// Path of the passphrase-encrypted form of a secret.
fn encrypted_path_for(path: &Path) -> std::path::PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(".enc");
    std::path::PathBuf::from(p)
}

/// The operator's keystore-unlock secret, if one is configured.
///
/// # Where the secret legitimately comes from
///
/// This is the passkey half of "TPM or passkey". Hardware custody is a
/// tiered story because no single mechanism covers the fleet:
///
///   1. **TPM 2.0** — handled above, before this function is reached. Covers
///      Intel (PTT on the CSME), AMD (fTPM on the PSP), discrete Infineon /
///      ST / Nuvoton parts, and — importantly — ARM and Jetson, where
///      OP-TEE's fTPM TA plus `tpm_ftpm_tee` present a real `/dev/tpm0`, so
///      tpm2-tools works unmodified.
///   2. **Apple Secure Enclave** — `tenzro-device-key`, gated by Touch ID.
///      Not an optional nicety: **Apple ships no TPM on any Mac**, so a
///      TPM-only design would exclude every Apple machine outright. SEP keys
///      are P-256-only with no seal/unseal, so the symmetric key is wrapped
///      via ECDH rather than sealed.
///   3. **Android StrongBox / KeyMint** — Titan M2, Qualcomm SPU.
///   4. **WebAuthn PRF** (CTAP2 `hmac-secret`) — a passkey deriving a stable
///      secret rather than only signing. Note the hard limit: **PRF requires
///      user verification, so it cannot run unattended.** It suits an
///      operator unlocking a node interactively; it cannot be the unlock
///      path for a validator that must survive an unattended restart.
///   5. **KMS / operator secret store** — the non-interactive path a headless
///      validator actually needs, which is why this function reads a
///      configured source rather than prompting.
///
/// Deliberately not assumed: that Pluton means TPM (from 2026 silicon it no
/// longer backs the TPM on AMD and Qualcomm), or that Chinese TCM/TPCM parts
/// answer TPM commands (different algorithms — SM2/SM3/SM4 — and a different
/// command set entirely).
///
/// In every case the bytes on disk stay ciphertext and the unlocking factor
/// lives in hardware or a secret store the operator controls.
///
/// Reuses the `KeystoreUnlocker` contract the wallet keystore already relies
/// on, so a node has one unlock story rather than two: a hardware-backed
/// device key behind a passkey/biometric on desktop, the operator's
/// configured source on a headless validator.
fn operator_unlock_secret() -> Option<zeroize::Zeroizing<String>> {
    use tenzro_keystore_unlock::KeystoreUnlocker as _;
    // Same variable the wallet keystore unlocks from (`main.rs`), so an
    // operator configures their passkey-gated device key or KMS once and both
    // the wallet and the node's own identity keys are covered by it.
    tenzro_keystore_unlock::EnvUnlocker::new(crate::KEYSTORE_PASSWORD_ENV)
        .unlock_password()
        .ok()
        .filter(|p| !p.is_empty())
}

/// Argon2id KDF matching the wallet keystore's profile (64 MiB, t=3, p=4), so
/// both stores cost an attacker the same to grind.
fn derive_at_rest_key(passphrase: &str, salt: &[u8; 32]) -> Result<SymmetricKey> {
    let params = argon2::Params::new(65536, 3, 4, Some(32))
        .map_err(|e| NodeError::Other(format!("argon2 params: {e}")))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key_bytes)
        .map_err(|e| NodeError::Other(format!("argon2 derivation: {e}")))?;
    SymmetricKey::from_bytes(&key_bytes).map_err(|e| NodeError::Other(e.to_string()))
}

/// Encrypt at rest: `salt(32) || AES-256-GCM(nonce||ct||tag)`.
fn encrypt_at_rest(secret: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    let mut salt = [0u8; 32];
    getrandom_0_4::fill(&mut salt)
        .map_err(|e| NodeError::Other(format!("salt generation: {e}")))?;
    let key = derive_at_rest_key(passphrase, &salt)?;
    let ct = tenzro_crypto::encryption::encrypt_aes(&key, secret)
        .map_err(|e| NodeError::Other(format!("encrypt-at-rest: {e}")))?;
    let mut out = Vec::with_capacity(salt.len() + ct.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Inverse of [`encrypt_at_rest`].
fn decrypt_at_rest(blob: &[u8], passphrase: &str) -> Result<Vec<u8>> {
    if blob.len() <= 32 {
        return Err(NodeError::Other(
            "encrypted key blob is truncated".to_string(),
        ));
    }
    let (salt_bytes, ct) = blob.split_at(32);
    let mut salt = [0u8; 32];
    salt.copy_from_slice(salt_bytes);
    let key = derive_at_rest_key(passphrase, &salt)?;
    tenzro_crypto::encryption::decrypt_aes(&key, ct)
        .map_err(|e| NodeError::Other(format!("decrypt-at-rest: {e}")))
}

/// Whether a secret is stored at `path` in *any* of the forms
/// [`read_secret`] can read.
///
/// A secret lives in one of three places and only one of them is the path
/// itself: TPM-sealed under `<path>.sealed/`, encrypted at rest beside it, or
/// plaintext at `path`. [`write_secret`] deletes the plaintext once it has
/// sealed, so testing `path.exists()` reports a sealed key as *absent* — which
/// made loaders raise `KeyMissing` for a key that was right there, and made the
/// overwrite guard wave through a clobber of a key it could not see.
///
/// That stayed hidden because sealing never actually succeeded: the sealing
/// parent was created at the Endorsement Key's handle and every seal failed, so
/// every host fell back to plaintext and `path.exists()` happened to be right.
/// Fixing the handle made sealing work and turned this into 191 failures.
///
/// Mirrors `read_secret`'s precedence deliberately. If the two ever disagree,
/// the node either refuses to start on a key it can read or overwrites one it
/// cannot see.
fn secret_exists(path: &Path) -> bool {
    tenzro_tee::tpm_seal::is_sealed(&sealed_dir_for(path))
        || encrypted_path_for(path).exists()
        || path.exists()
}

/// Read a secret back, preferring the TPM-sealed form.
///
/// Sealed first so a node that has been upgraded to sealed storage never
/// silently falls back to a stale plaintext copy. `unseal` fails on a blob
/// produced by a different TPM, which is the point — a copied key directory
/// does not become a working identity on another machine.
fn read_secret(path: &Path) -> Result<Vec<u8>> {
    // Strongest custody first, so a node upgraded to sealed or encrypted
    // storage never silently falls back to a stale plaintext copy.
    let sealed_dir = sealed_dir_for(path);
    if tenzro_tee::tpm_seal::is_sealed(&sealed_dir) {
        return tenzro_tee::tpm_seal::unseal(&sealed_dir)
            .map(|z| z.to_vec())
            .map_err(|e| NodeError::Other(format!("unseal {}: {}", sealed_dir.display(), e)));
    }

    let enc_path = encrypted_path_for(path);
    if enc_path.exists() {
        let blob = std::fs::read(&enc_path)
            .map_err(|e| NodeError::Other(format!("read {}: {}", enc_path.display(), e)))?;
        let passphrase = operator_unlock_secret().ok_or_else(|| {
            NodeError::Other(format!(
                "{} is encrypted at rest but no operator unlock secret is available. \
                 Authenticate with your passkey-gated device key, or set \
                 TENZRO_KEYSTORE_PASSWORD, before starting the node.",
                enc_path.display()
            ))
        })?;
        return decrypt_at_rest(&blob, &passphrase);
    }

    // Plaintext remains readable so an existing node still starts, but say so
    // — the operator should know this key is not protected at rest, and
    // re-running keygen now upgrades it in place.
    let bytes = std::fs::read(path)
        .map_err(|e| NodeError::Other(format!("read {}: {}", path.display(), e)))?;
    tracing::warn!(
        target: "tenzro::keygen",
        path = %path.display(),
        "loaded a PLAINTEXT key: not TPM-sealed and not encrypted at rest. \
         Anything able to read this file holds this node's identity"
    );
    Ok(bytes)
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
        assert_eq!(
            loaded_bls.public_key().to_bytes().to_vec(),
            pubs.bls12_381_g1
        );
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
    fn a_wiped_data_directory_returns_the_same_identity() {
        // The whole point of deriving rather than generating. Establish a
        // keyset, destroy every trace of it — the case an operator creates with
        // one `rm -rf`, and the case that used to cost a machine its name — and
        // establish it again. On a machine that can derive, the second keyset is
        // the first one.
        //
        // On a machine with no chip this asserts nothing and says so, rather
        // than failing: a developer laptop must still be able to run the suite,
        // and a test that passed there by accident would be worse than one that
        // skips honestly.
        if !tenzro_tee::tpm_derive::derivation_available() {
            eprintln!("no TPM on this host; the recovery guarantee is not exercised here");
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let first = generate_and_persist_keyset(d.path(), true).unwrap();
        let before = first.keypair.to_bytes();

        for entry in std::fs::read_dir(d.path()).unwrap() {
            let p = entry.unwrap().path();
            if p.is_dir() {
                std::fs::remove_dir_all(&p).unwrap();
            } else {
                std::fs::remove_file(&p).unwrap();
            }
        }
        // The process cache would otherwise answer for the chip and prove
        // nothing about recovery.
        tenzro_tee::tpm_derive::forget_cached_root();

        let second = generate_and_persist_keyset(d.path(), true).unwrap();
        assert_eq!(
            before,
            second.keypair.to_bytes(),
            "a wiped data directory must not change who this machine is"
        );
        assert_eq!(
            first.pq.seed_bytes(),
            second.pq.seed_bytes(),
            "and not for any one of its keys"
        );
        assert_eq!(
            first.bls.secret_key().to_bytes(),
            second.bls.secret_key().to_bytes()
        );
    }

    #[test]
    fn erc8004_system_key_generates_on_miss() {
        let dir = tempdir().unwrap();
        let key1 = load_or_generate_erc8004_system_key(dir.path()).expect("generate");
        assert_eq!(key1.len(), 32);
        assert_ne!(key1, [0u8; 32], "generated key must not be all zeros");

        // Subsequent calls return the same persisted bytes (idempotent).
        let key2 = load_or_generate_erc8004_system_key(dir.path()).expect("reload");
        assert_eq!(key1, key2, "second load must match first generation");
    }

    #[test]
    fn erc8004_system_key_rejects_wrong_length() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("validator_erc8004_system_key");
        std::fs::write(&key_path, b"too-short").unwrap();
        match load_or_generate_erc8004_system_key(dir.path()) {
            Err(NodeError::Other(msg)) => {
                assert!(msg.contains("wrong length"), "unexpected error: {}", msg);
            }
            other => panic!("expected length error, got {:?}", other.map(|_| "Ok")),
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

#[cfg(test)]
mod at_rest_tests {
    use super::*;

    /// A key written with an operator unlock secret must not be recoverable
    /// from the bytes alone — that is the whole point of the passkey fallback
    /// for hosts without a TPM.
    #[test]
    fn encrypted_at_rest_round_trips_and_hides_the_secret() {
        let secret = b"this-is-a-validator-private-key!";
        let blob = encrypt_at_rest(secret, "operator-passkey-derived").unwrap();

        // Ciphertext must not contain the plaintext.
        assert!(
            blob.windows(secret.len()).all(|w| w != secret),
            "plaintext key must not appear in the at-rest blob"
        );
        // Salt is prepended, so two encryptions of the same secret differ.
        let blob2 = encrypt_at_rest(secret, "operator-passkey-derived").unwrap();
        assert_ne!(blob, blob2, "each write must use a fresh salt");

        let out = decrypt_at_rest(&blob, "operator-passkey-derived").unwrap();
        assert_eq!(out, secret);
    }

    /// The wrong operator cannot recover the key.
    #[test]
    fn decrypt_at_rest_rejects_a_wrong_secret() {
        let blob = encrypt_at_rest(b"validator-key-bytes-here-000000!", "right").unwrap();
        assert!(decrypt_at_rest(&blob, "wrong").is_err());
    }

    #[test]
    fn truncated_blob_is_rejected_rather_than_panicking() {
        assert!(decrypt_at_rest(&[0u8; 8], "x").is_err());
    }
}
