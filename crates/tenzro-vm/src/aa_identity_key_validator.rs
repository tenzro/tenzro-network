//! Authenticates a smart account against the hardware key of the TDIP
//! identity that owns it.
//!
//! # What it checks
//!
//! A machine identity's key is its TPM or Secure Enclave P-256 key with the
//! hardware's ML-DSA-65 key beside it, and both legs are required. This
//! validator holds that composite key per account and verifies the
//! UserOperation's composite signature against the operation hash, so the only
//! party who can move a machine's account is the machine.
//!
//! # Why not one of the existing validators
//!
//! [`WebAuthnValidator`](crate::aa_webauthn_validator::WebAuthnValidator) is
//! P-256 over a WebAuthn ceremony, which is the right thing for a human with a
//! passkey and the wrong shape for a headless machine, whose hardware signs
//! the composite digest directly.

use std::sync::Arc;

use dashmap::DashMap;
use tenzro_crypto::{
    ClassicalProof, CompositePublicKey, CompositeSignature, PqPolicy, SignatureContext,
    verify_composite,
};

use crate::aa_validators::{
    ERC1271_FAILURE_VALUE, ERC1271_MAGIC_VALUE, IValidator, ValidationData, ValidatorError,
};
use crate::account_abstraction::UserOperation;

/// The module address every node installs this validator at: the trailing 20
/// bytes of `SHA-256("tenzro/aa/identity-key-validator")`.
pub fn module_address() -> [u8; 20] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(b"tenzro/aa/identity-key-validator");
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[12..32]);
    out
}

/// Verify `signature`, a bincode-encoded [`CompositeSignature`] whose P-256
/// leg is a raw hardware signature, against `key` over `hash` under `context`.
/// The ML-DSA-65 leg is required and verifies against the bound key.
fn verify(
    key: &CompositePublicKey,
    context: SignatureContext,
    hash: &[u8; 32],
    signature: &[u8],
) -> bool {
    let Ok(sig) = bincode::deserialize::<CompositeSignature>(signature) else {
        return false;
    };
    if !matches!(sig.classical, ClassicalProof::Raw { .. }) {
        return false;
    }
    verify_composite(key, context, hash, &sig, PqPolicy::Required).is_ok()
}

/// Per-account hardware-key authenticator for identity-owned smart accounts.
///
/// One instance serves every identity-owned account on the node, mapping each
/// account address to the composite key of the identity that owns it.
pub struct IdentityKeyValidator {
    address: [u8; 20],
    /// account address (20-byte EVM form) -> the identity's hardware key.
    keys: Arc<DashMap<Vec<u8>, CompositePublicKey>>,
}

impl IdentityKeyValidator {
    /// A validator at `address` with no accounts bound.
    pub fn new(address: [u8; 20]) -> Self {
        Self {
            address,
            keys: Arc::new(DashMap::new()),
        }
    }

    /// Bind `account` to the identity's hardware key: its 64-byte P-256
    /// `x || y` and its ML-DSA-65 key.
    ///
    /// A key that cannot verify anything is refused here: an account bound to
    /// it could never be moved again. A binding without an ML-DSA-65 key is
    /// such a key, since every signature must carry that leg.
    pub fn install_for(
        &self,
        account: Vec<u8>,
        p256_xy: &[u8],
        ml_dsa: Option<&[u8]>,
    ) -> Result<(), ValidatorError> {
        if ml_dsa.is_none() {
            return Err(ValidatorError::InvalidInput(
                "identity key has no ML-DSA-65 key; every signature must carry that leg"
                    .to_string(),
            ));
        }
        let key =
            CompositePublicKey::new(p256_xy.to_vec(), ml_dsa.map(<[u8]>::to_vec)).map_err(|e| {
                ValidatorError::InvalidInput(format!(
                    "identity key is not a hardware composite key: {e}"
                ))
            })?;
        self.keys.insert(account, key);
        Ok(())
    }

    /// Unbind `account`.
    pub fn uninstall(&self, account: &[u8]) {
        self.keys.remove(account);
    }

    /// The key bound to `account`, if any.
    pub fn key_for(&self, account: &[u8]) -> Option<CompositePublicKey> {
        self.keys.get(account).map(|e| e.value().clone())
    }
}

impl IValidator for IdentityKeyValidator {
    fn module_address(&self) -> [u8; 20] {
        self.address
    }

    fn validate_user_op(
        &self,
        op: &UserOperation,
        op_hash: &[u8; 32],
    ) -> Result<ValidationData, ValidatorError> {
        // An account with no key bound is an error rather than a failed
        // validation. Returning `failure()` would let an unconfigured account
        // look like a merely-unauthorized one, and the two want different
        // responses: one is a wiring bug on this node, the other is a rejected
        // request.
        let Some(key) = self.key_for(&op.sender) else {
            return Err(ValidatorError::InvalidInput(format!(
                "IdentityKeyValidator: no identity key installed for account 0x{}",
                hex::encode(&op.sender)
            )));
        };

        if verify(
            &key,
            SignatureContext::UserOperation,
            op_hash,
            &op.signature,
        ) {
            Ok(ValidationData::success())
        } else {
            Ok(ValidationData::failure())
        }
    }

    fn is_valid_signature_with_sender(
        &self,
        sender: &[u8],
        hash: &[u8; 32],
        signature: &[u8],
    ) -> [u8; 4] {
        match self.key_for(sender) {
            Some(key) if verify(&key, SignatureContext::SmartAccountMessage, hash, signature) => {
                ERC1271_MAGIC_VALUE
            }
            _ => ERC1271_FAILURE_VALUE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::HybridSigner as _;
    use tenzro_crypto::testing::TestHybridSigner;

    fn module_addr() -> [u8; 20] {
        [0x1du8; 20]
    }

    fn install(v: &IdentityKeyValidator, account: &[u8], signer: &TestHybridSigner) {
        let key = signer.public_key();
        v.install_for(account.to_vec(), &key.p256, key.pq.as_deref())
            .unwrap();
    }

    fn sign(signer: &TestHybridSigner, context: SignatureContext, hash: &[u8; 32]) -> Vec<u8> {
        bincode::serialize(&signer.sign(context, hash).unwrap()).unwrap()
    }

    fn user_op(sender: Vec<u8>, signature: Vec<u8>) -> UserOperation {
        UserOperation {
            sender,
            nonce: crate::account_abstraction::Nonce::from_seq(0).to_bytes(),
            factory: vec![],
            factory_data: vec![],
            call_data: vec![0x42; 4],
            call_gas_limit: 100_000,
            verification_gas_limit: 50_000,
            pre_verification_gas: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000,
            paymaster: vec![],
            paymaster_verification_gas_limit: 0,
            paymaster_post_op_gas_limit: 0,
            paymaster_data: vec![],
            paymaster_signature: vec![],
            signature,
        }
    }

    fn validates(v: &IdentityKeyValidator, account: &[u8], hash: &[u8; 32], sig: Vec<u8>) -> bool {
        !v.validate_user_op(&user_op(account.to_vec(), sig), hash)
            .unwrap()
            .is_failure()
    }

    /// The machine's own hybrid key authorizes its account.
    #[test]
    fn the_identitys_key_validates_its_operations() {
        let v = IdentityKeyValidator::new(module_addr());
        let op_hash = [0x42u8; 32];
        for (i, signer) in [TestHybridSigner::hybrid(7), TestHybridSigner::hybrid(8)]
            .iter()
            .enumerate()
        {
            let account = vec![0xA0u8 + i as u8; 20];
            install(&v, &account, signer);
            let sig = sign(signer, SignatureContext::UserOperation, &op_hash);
            assert!(
                validates(&v, &account, &op_hash, sig),
                "the owner's signature must validate"
            );
        }
    }

    /// A binding without an ML-DSA-65 key is refused: no signature could carry
    /// the leg it would be checked against.
    #[test]
    fn a_key_without_an_ml_dsa_key_cannot_be_bound() {
        let v = IdentityKeyValidator::new(module_addr());
        let key = TestHybridSigner::p256_only(7).public_key().clone();
        assert!(v.install_for(vec![0xACu8; 20], &key.p256, None).is_err());
        assert!(v.key_for(&[0xACu8; 20]).is_none());
    }

    /// The ML-DSA-65 leg is mandatory: stripping it fails.
    #[test]
    fn a_signature_stripped_of_its_ml_dsa_leg_is_rejected() {
        let v = IdentityKeyValidator::new(module_addr());
        let signer = TestHybridSigner::hybrid(9);
        let account = vec![0xABu8; 20];
        install(&v, &account, &signer);
        let op_hash = [0x42u8; 32];
        let mut sig = signer
            .sign(SignatureContext::UserOperation, &op_hash)
            .unwrap();
        sig.pq = None;
        assert!(!validates(
            &v,
            &account,
            &op_hash,
            bincode::serialize(&sig).unwrap()
        ));
    }

    /// Junk bytes never authorize an account.
    #[test]
    fn a_single_junk_byte_no_longer_authorizes_an_account() {
        let v = IdentityKeyValidator::new(module_addr());
        let account = vec![0xAAu8; 20];
        install(&v, &account, &TestHybridSigner::hybrid(7));
        assert!(!validates(&v, &account, &[0x42u8; 32], vec![0x01]));
        assert!(!validates(&v, &account, &[0x42u8; 32], vec![]));
    }

    #[test]
    fn another_keys_signature_does_not_authorize_this_account() {
        let v = IdentityKeyValidator::new(module_addr());
        let account = vec![0xAAu8; 20];
        install(&v, &account, &TestHybridSigner::hybrid(7));
        let op_hash = [0x42u8; 32];
        let sig = sign(
            &TestHybridSigner::hybrid(8),
            SignatureContext::UserOperation,
            &op_hash,
        );
        assert!(!validates(&v, &account, &op_hash, sig));
    }

    #[test]
    fn a_signature_over_a_different_operation_or_context_is_rejected() {
        let v = IdentityKeyValidator::new(module_addr());
        let signer = TestHybridSigner::hybrid(7);
        let account = vec![0xAAu8; 20];
        install(&v, &account, &signer);
        let sig = sign(&signer, SignatureContext::UserOperation, &[0x01u8; 32]);
        assert!(!validates(&v, &account, &[0x02u8; 32], sig));
        let other_ctx = sign(&signer, SignatureContext::Transaction, &[0x01u8; 32]);
        assert!(!validates(&v, &account, &[0x01u8; 32], other_ctx));
    }

    #[test]
    fn an_account_with_no_key_installed_is_an_error() {
        let v = IdentityKeyValidator::new(module_addr());
        let err = v.validate_user_op(&user_op(vec![0xAAu8; 20], vec![0u8; 64]), &[0u8; 32]);
        assert!(matches!(err, Err(ValidatorError::InvalidInput(_))));
    }

    /// A key that cannot verify anything is refused at install time.
    #[test]
    fn a_wrong_length_key_is_refused_rather_than_locking_the_account_out() {
        let v = IdentityKeyValidator::new(module_addr());
        assert!(v.install_for(vec![0xAAu8; 20], &[1u8; 32], None).is_err());
        assert!(v.install_for(vec![0xAAu8; 20], &[1u8; 65], None).is_err());
        assert!(v.install_for(vec![0xAAu8; 20], &[], None).is_err());
    }

    #[test]
    fn the_erc1271_path_agrees_with_user_op_validation() {
        let v = IdentityKeyValidator::new(module_addr());
        let signer = TestHybridSigner::hybrid(7);
        let account = vec![0xAAu8; 20];
        install(&v, &account, &signer);
        let hash = [0x33u8; 32];
        let good = sign(&signer, SignatureContext::SmartAccountMessage, &hash);
        assert_eq!(
            v.is_valid_signature_with_sender(&account, &hash, &good),
            ERC1271_MAGIC_VALUE
        );
        let wrong = sign(
            &TestHybridSigner::hybrid(8),
            SignatureContext::SmartAccountMessage,
            &hash,
        );
        assert_eq!(
            v.is_valid_signature_with_sender(&account, &hash, &wrong),
            ERC1271_FAILURE_VALUE
        );
        assert_eq!(
            v.is_valid_signature_with_sender(&[0xBBu8; 20], &hash, &good),
            ERC1271_FAILURE_VALUE
        );
    }

    #[test]
    fn uninstalling_a_binding_stops_it_validating() {
        let v = IdentityKeyValidator::new(module_addr());
        let account = vec![0xAAu8; 20];
        install(&v, &account, &TestHybridSigner::hybrid(7));
        v.uninstall(&account);
        assert!(v.key_for(&account).is_none());
    }
}
