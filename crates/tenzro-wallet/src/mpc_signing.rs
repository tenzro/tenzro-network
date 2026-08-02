//! FROST-Ed25519 threshold signing coordinator (RFC 9591).
//!
//! For in-process custody (auto-provisioned wallets where one node holds all
//! shares) the wallet runs both rounds of FROST internally and aggregates the
//! resulting signature. The output is a standard 64-byte Ed25519 signature
//! that verifies under the wallet's group public key with
//! `tenzro_crypto::signatures::verify`.
//!
//! Distributed custody (one signer per node, exchanged commitments and
//! signature shares over the wire) is a follow-up — the FROST primitives in
//! `tenzro_crypto::frost` already expose `round1_commit` / `build_signing_package`
//! / `round2_sign` / `aggregate_signature` for that profile.

use crate::error::{Result, WalletError};
use crate::wallet::{KeyShare, MpcWallet};
use tenzro_crypto::Signature;
use tenzro_crypto::frost::{
    PublicKeyPackage, SignatureShare, SigningCommitments, SigningNonces, aggregate_signature,
    build_signing_package, round1_commit, round2_sign,
};
use tracing::{debug, info};

/// FROST signing coordinator for Tenzro Network wallets.
pub struct MpcSigner;

impl MpcSigner {
    /// Sign data using a FROST threshold wallet (in-process, all shares local).
    pub fn sign(wallet: &MpcWallet, data: &[u8]) -> Result<Signature> {
        if !wallet.can_sign() {
            return Err(WalletError::ThresholdNotMet {
                got: wallet.share_count(),
                need: wallet.threshold as usize,
            });
        }

        let pubkey_pkg = wallet.frost_pubkey_package()?;

        debug!(
            "FROST-signing with wallet {} ({}-of-{}) using {} shares",
            wallet.wallet_id,
            wallet.threshold,
            wallet.total_shares,
            wallet.share_count(),
        );

        // Use exactly `threshold` shares — FROST aggregation rejects extras
        // beyond the signing set committed to in round 1.
        let signing_set = &wallet.key_shares[..wallet.threshold as usize];
        let signature = run_frost_session(signing_set, pubkey_pkg, data)?;

        info!("Successfully FROST-signed with wallet {}", wallet.wallet_id);

        Ok(signature)
    }

    /// Sign with a caller-chosen subset of shares (must be ≥ `threshold`).
    /// Useful when the wallet holds more shares than required for signing
    /// (e.g. recovery scenarios).
    pub fn sign_with_shares(
        wallet: &MpcWallet,
        shares: &[KeyShare],
        threshold: usize,
        data: &[u8],
    ) -> Result<Signature> {
        if shares.len() < threshold {
            return Err(WalletError::ThresholdNotMet {
                got: shares.len(),
                need: threshold,
            });
        }

        let pubkey_pkg = wallet.frost_pubkey_package()?;
        let signing_set = &shares[..threshold];

        debug!(
            "FROST-signing with {} of {} provided shares",
            signing_set.len(),
            shares.len()
        );

        run_frost_session(signing_set, pubkey_pkg, data)
    }
}

/// Run a single FROST signing session: round 1 commit → build signing
/// package → round 2 sign → aggregate.
fn run_frost_session(
    signing_set: &[KeyShare],
    pubkey_pkg: &PublicKeyPackage,
    data: &[u8],
) -> Result<Signature> {
    // Round 1: each signer commits.
    let mut nonces: Vec<(u16, SigningNonces)> = Vec::with_capacity(signing_set.len());
    let mut commitments: Vec<SigningCommitments> = Vec::with_capacity(signing_set.len());
    for share in signing_set {
        let (n, c) = round1_commit(&share.secret_share)
            .map_err(|e| WalletError::SignatureFailed(format!("FROST round1: {}", e)))?;
        nonces.push((share.signer_index.0, n));
        commitments.push(c);
    }

    // Coordinator: build the signing package.
    let signing_pkg = build_signing_package(data, &commitments)
        .map_err(|e| WalletError::SignatureFailed(format!("FROST build_signing_package: {}", e)))?;

    // Round 2: each signer produces its signature share.
    let mut shares_out: Vec<SignatureShare> = Vec::with_capacity(signing_set.len());
    for share in signing_set {
        let n = nonces
            .iter()
            .find(|(idx, _)| *idx == share.signer_index.0)
            .map(|(_, n)| n)
            .ok_or_else(|| {
                WalletError::SignatureFailed(format!(
                    "missing round-1 nonces for signer {}",
                    share.signer_index.0
                ))
            })?;
        let sig_share = round2_sign(&signing_pkg, n, &share.secret_share)
            .map_err(|e| WalletError::SignatureFailed(format!("FROST round2: {}", e)))?;
        shares_out.push(sig_share);
    }

    // Aggregator: produce the final 64-byte Ed25519 signature.
    let signature = aggregate_signature(&signing_pkg, &shares_out, pubkey_pkg)
        .map_err(|e| WalletError::SignatureFailed(format!("FROST aggregate: {}", e)))?;

    Ok(signature)
}

/// Helper for signing transaction data with automatic verification.
pub struct TransactionSigner;

impl TransactionSigner {
    /// Sign transaction data with a FROST wallet and verify the signature.
    pub fn sign_transaction(wallet: &MpcWallet, tx_data: &[u8]) -> Result<Vec<u8>> {
        let signature = MpcSigner::sign(wallet, tx_data)?;
        Self::verify_signature(&wallet.public_key, tx_data, &signature)?;
        Ok(signature.to_bytes())
    }

    /// Sign a message with a FROST wallet and verify the signature.
    pub fn sign_message(wallet: &MpcWallet, message: &[u8]) -> Result<Vec<u8>> {
        let message_hash = tenzro_crypto::hash::sha256(message);
        let signature = MpcSigner::sign(wallet, message_hash.as_bytes())?;
        Self::verify_signature(&wallet.public_key, message_hash.as_bytes(), &signature)?;
        Ok(signature.to_bytes())
    }

    /// Sign raw bytes (for custom signing workflows) with verification.
    pub fn sign_raw(wallet: &MpcWallet, data: &[u8]) -> Result<Vec<u8>> {
        let signature = MpcSigner::sign(wallet, data)?;
        Self::verify_signature(&wallet.public_key, data, &signature)?;
        Ok(signature.to_bytes())
    }

    /// Verify a signature against a public key.
    pub fn verify_signature(
        public_key: &tenzro_crypto::PublicKey,
        data: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        tenzro_crypto::signatures::verify(public_key, data, signature)
            .map_err(|e| WalletError::SignatureVerificationFailed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provisioning::WalletProvisioner;
    use tenzro_crypto::KeyType;

    #[test]
    fn test_frost_signing_produces_valid_ed25519() {
        let provisioner = WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();

        let data = b"Tenzro Network transaction data";
        let signature = MpcSigner::sign(&wallet, data).unwrap();

        assert_eq!(signature.key_type(), KeyType::Ed25519);
        assert_eq!(signature.as_bytes().len(), 64);

        // Aggregated signature MUST verify under the group public key with
        // the standard Ed25519 verifier.
        tenzro_crypto::signatures::verify(&wallet.public_key, data, &signature)
            .expect("FROST signature must verify under group key");
    }

    #[test]
    fn test_threshold_signing_succeeds_with_min_set() {
        let provisioner = WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();

        let data = b"test data";
        let shares_to_use = wallet.key_shares[..2].to_vec();
        let sig = MpcSigner::sign_with_shares(&wallet, &shares_to_use, 2, data).unwrap();
        tenzro_crypto::signatures::verify(&wallet.public_key, data, &sig).unwrap();
    }

    #[test]
    fn test_insufficient_shares_rejected() {
        let provisioner = WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();

        let data = b"test data";
        let shares_to_use = wallet.key_shares[..1].to_vec();
        let result = MpcSigner::sign_with_shares(&wallet, &shares_to_use, 2, data);
        assert!(result.is_err());
    }

    #[test]
    fn test_transaction_signer_round_trips() {
        let provisioner = WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();

        let tx_data = b"transaction data";
        let sig_bytes = TransactionSigner::sign_transaction(&wallet, tx_data).unwrap();
        assert_eq!(sig_bytes.len(), 64);
    }

    #[test]
    fn test_message_signer_round_trips() {
        let provisioner = WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();

        let message = b"Hello, Tenzro Network!";
        let sig_bytes = TransactionSigner::sign_message(&wallet, message).unwrap();
        assert_eq!(sig_bytes.len(), 64);
    }

    #[test]
    fn test_signature_bound_to_message() {
        let provisioner = WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();

        let sig = MpcSigner::sign(&wallet, b"message A").unwrap();
        // Verifying against a different message MUST fail.
        let result = tenzro_crypto::signatures::verify(&wallet.public_key, b"message B", &sig);
        assert!(result.is_err());
    }
}
