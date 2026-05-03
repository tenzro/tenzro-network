//! Threshold signature operations for MPC wallets in Tenzro Network.
//!
//! This module handles the creation and combination of partial signatures
//! from MPC key shares.

use crate::error::{Result, WalletError};
use crate::wallet::{KeyShare, MpcWallet};
use tenzro_crypto::mpc::{
    combine_signatures_with_message, create_partial_signature,
    PartialSignature,
};
use tenzro_crypto::Signature;
use tracing::{debug, info};

/// MPC signing coordinator for Tenzro Network wallets.
///
/// Handles the multi-party signature generation process:
/// 1. Create partial signatures from each key share
/// 2. Collect threshold number of partial signatures
/// 3. Combine into a full signature
pub struct MpcSigner;

impl MpcSigner {
    /// Sign data using MPC wallet's key shares.
    ///
    /// This method:
    /// 1. Verifies we have enough shares to meet the threshold
    /// 2. Creates partial signatures from each share
    /// 3. Combines them into a full signature using real MPC key reconstruction
    pub fn sign(wallet: &MpcWallet, data: &[u8]) -> Result<Signature> {
        // Check if we have enough shares
        if !wallet.can_sign() {
            return Err(WalletError::ThresholdNotMet {
                got: wallet.share_count(),
                need: wallet.threshold,
            });
        }

        debug!(
            "Signing with MPC wallet {} using {} shares",
            wallet.wallet_id,
            wallet.share_count()
        );

        // Create partial signatures from each key share
        let partial_sigs = Self::create_partial_signatures(&wallet.key_shares, data)?;

        debug!(
            "Created {} partial signatures",
            partial_sigs.len()
        );

        // Combine partial signatures into a full signature using real MPC key reconstruction
        let signature = Self::combine_partial_signatures_with_shares(
            &wallet.key_shares,
            &partial_sigs,
            data,
        )?;

        info!(
            "Successfully signed data with wallet {}",
            wallet.wallet_id
        );

        Ok(signature)
    }

    /// Create partial signatures from key shares
    fn create_partial_signatures(
        shares: &[KeyShare],
        data: &[u8],
    ) -> Result<Vec<PartialSignature>> {
        let mut partial_sigs = Vec::new();

        for share in shares {
            let partial = create_partial_signature(&share.mpc_share, data)
                .map_err(|e| WalletError::SignatureFailed(e.to_string()))?;

            partial_sigs.push(partial);
        }

        Ok(partial_sigs)
    }

    /// Combine partial signatures into a full signature using real MPC key reconstruction
    fn combine_partial_signatures_with_shares(
        shares: &[KeyShare],
        partial_sigs: &[PartialSignature],
        message: &[u8],
    ) -> Result<Signature> {
        // Convert KeyShare references to MpcKeyShare references
        let mpc_shares: Vec<&tenzro_crypto::mpc::MpcKeyShare> =
            shares.iter().map(|s| &s.mpc_share).collect();

        let signature = combine_signatures_with_message(&mpc_shares, partial_sigs, message)
            .map_err(|e| WalletError::SignatureFailed(e.to_string()))?;

        Ok(signature)
    }

    /// Sign data using only a subset of shares (useful for threshold signing)
    pub fn sign_with_shares(
        shares: &[KeyShare],
        threshold: usize,
        data: &[u8],
        _key_type: tenzro_crypto::KeyType,
    ) -> Result<Signature> {
        if shares.len() < threshold {
            return Err(WalletError::ThresholdNotMet {
                got: shares.len(),
                need: threshold,
            });
        }

        // Use only threshold number of shares
        let shares_to_use = &shares[..threshold];

        debug!(
            "Signing with {} of {} shares",
            shares_to_use.len(),
            shares.len()
        );

        // Create partial signatures
        let partial_sigs = Self::create_partial_signatures(shares_to_use, data)?;

        // Combine signatures using real MPC key reconstruction
        let signature = Self::combine_partial_signatures_with_shares(shares_to_use, &partial_sigs, data)?;

        Ok(signature)
    }

    /// Verify that a partial signature is valid
    pub fn verify_partial_signature(partial_sig: &PartialSignature) -> bool {
        partial_sig.verify_commitment()
    }

    /// Collect partial signatures from multiple sources (for distributed MPC)
    pub fn collect_partial_signatures(
        local_shares: &[KeyShare],
        remote_partials: Vec<PartialSignature>,
        data: &[u8],
    ) -> Result<Vec<PartialSignature>> {
        let mut all_partials = Vec::new();

        // Create partials from local shares
        for share in local_shares {
            let partial = create_partial_signature(&share.mpc_share, data)
                .map_err(|e| WalletError::SignatureFailed(e.to_string()))?;
            all_partials.push(partial);
        }

        // Add remote partials
        all_partials.extend(remote_partials);

        // Verify all commitments
        for partial in &all_partials {
            if !Self::verify_partial_signature(partial) {
                return Err(WalletError::SignatureFailed(format!(
                    "Invalid commitment for share {}",
                    partial.share_id
                )));
            }
        }

        Ok(all_partials)
    }
}

/// Helper for signing transaction data with automatic verification.
pub struct TransactionSigner;

impl TransactionSigner {
    /// Sign transaction data with an MPC wallet and verify the signature.
    ///
    /// After producing the threshold signature, this method verifies it
    /// against the wallet's public key to ensure correctness before returning.
    pub fn sign_transaction(wallet: &MpcWallet, tx_data: &[u8]) -> Result<Vec<u8>> {
        let signature = MpcSigner::sign(wallet, tx_data)?;

        // Verify the signature against the wallet's public key
        Self::verify_signature(&wallet.public_key, tx_data, &signature)?;

        Ok(signature.to_bytes())
    }

    /// Sign a message with an MPC wallet and verify the signature.
    pub fn sign_message(wallet: &MpcWallet, message: &[u8]) -> Result<Vec<u8>> {
        // Hash the message first for standardization
        let message_hash = tenzro_crypto::hash::sha256(message);
        let signature = MpcSigner::sign(wallet, message_hash.as_bytes())?;

        // Verify the signature
        Self::verify_signature(&wallet.public_key, message_hash.as_bytes(), &signature)?;

        Ok(signature.to_bytes())
    }

    /// Sign raw bytes (for custom signing workflows) with verification.
    pub fn sign_raw(wallet: &MpcWallet, data: &[u8]) -> Result<Vec<u8>> {
        let signature = MpcSigner::sign(wallet, data)?;

        // Verify the signature
        Self::verify_signature(&wallet.public_key, data, &signature)?;

        Ok(signature.to_bytes())
    }

    /// Verify a signature against a public key.
    ///
    /// This is called automatically after signing but can also be used
    /// independently to verify externally-produced signatures.
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
    fn test_mpc_signing() {
        let provisioner = WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();

        let data = b"Tenzro Network transaction data";
        let signature = MpcSigner::sign(&wallet, data).unwrap();

        assert_eq!(signature.key_type(), KeyType::Ed25519);
        assert!(!signature.as_bytes().is_empty());
    }

    #[test]
    fn test_threshold_signing() {
        let provisioner = WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();

        // Should succeed with threshold (2) shares
        let data = b"test data";
        let shares_to_use = &wallet.key_shares[..2];
        let result = MpcSigner::sign_with_shares(shares_to_use, 2, data, wallet.key_type);
        assert!(result.is_ok());
    }

    #[test]
    fn test_insufficient_shares() {
        let provisioner = WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();

        // Should fail with only 1 share (threshold is 2)
        let data = b"test data";
        let shares_to_use = &wallet.key_shares[..1];
        let result = MpcSigner::sign_with_shares(shares_to_use, 2, data, wallet.key_type);
        assert!(result.is_err());
    }

    #[test]
    fn test_transaction_signer() {
        let provisioner = WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();

        let tx_data = b"transaction data";
        let sig_bytes = TransactionSigner::sign_transaction(&wallet, tx_data).unwrap();
        assert!(!sig_bytes.is_empty());
    }

    #[test]
    fn test_message_signer() {
        let provisioner = WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();

        let message = b"Hello, Tenzro Network!";
        let sig_bytes = TransactionSigner::sign_message(&wallet, message).unwrap();
        assert!(!sig_bytes.is_empty());
    }

    #[test]
    fn test_partial_signature_verification() {
        let provisioner = WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();

        let data = b"test";
        let share = &wallet.key_shares[0];
        let partial = create_partial_signature(&share.mpc_share, data).unwrap();

        assert!(MpcSigner::verify_partial_signature(&partial));
    }

    #[test]
    fn test_collect_partial_signatures() {
        let provisioner = WalletProvisioner::new();
        let wallet = provisioner.provision_wallet().unwrap();

        let data = b"test data";

        // Use first share locally, second share remotely
        let local_shares = &wallet.key_shares[..1];
        let remote_partial = create_partial_signature(&wallet.key_shares[1].mpc_share, data).unwrap();

        let collected = MpcSigner::collect_partial_signatures(
            local_shares,
            vec![remote_partial],
            data,
        ).unwrap();

        assert_eq!(collected.len(), 2);
    }
}
