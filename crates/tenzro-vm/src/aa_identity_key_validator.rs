//! Authenticates a smart account against the Ed25519 key of the TDIP identity
//! that owns it.
//!
//! # What this replaces
//!
//! Every machine identity registered through `tenzro_registerIdentity` gets a
//! [`DelegationScopeValidator`](crate::aa_delegation_validator::DelegationScopeValidator)
//! installed on its smart account, and that validator wraps an *inner*
//! authenticator which decides whether the operation was actually signed by
//! whoever owns the account. The inner authenticator was
//! [`NoOpValidator`](crate::aa_validators::NoOpValidator), whose own
//! documentation says it is "**not** intended for production use" — it accepts
//! any signature at all, provided the bytes are not empty.
//!
//! So the delegation scope was enforced and the *signature was not*. Anyone who
//! knew a machine's account address could submit a UserOperation on its behalf,
//! sign it with a single zero byte, and have it validate — bounded only by that
//! machine's spending scope rather than by possession of its key. The scope
//! check made this look protected while the thing the scope is supposed to
//! qualify — that the request came from the account's owner — was never checked.
//!
//! # What it checks
//!
//! A machine identity's `public_keys[0]` is its Ed25519 verifying key, and
//! since the hardware-binding work that key *is* the machine's TPM-sealed
//! validator key rather than one the registering caller chose. This validator
//! holds that key per account and verifies the UserOperation signature against
//! the operation hash, so the only party who can move a machine's account is
//! the machine.
//!
//! # Why not one of the existing validators
//!
//! [`WebAuthnValidator`](crate::aa_webauthn_validator::WebAuthnValidator) is
//! P-256 over a WebAuthn ceremony, which is the right thing for a human with a
//! passkey and the wrong shape for a headless machine.
//! [`TeeBoundValidator`](crate::aa_tee_bound_validator::TeeBoundValidator)
//! requires a TEE attestation, which a TPM-only host cannot produce.
//! `HardwareSignerValidator` is secp256k1 with its own separately-provisioned
//! co-signer config. None of them verify the identity's own Ed25519 key, which
//! is the credential a machine actually holds.

use std::sync::Arc;

use dashmap::DashMap;

use crate::aa_validators::{
    ERC1271_FAILURE_VALUE, ERC1271_MAGIC_VALUE, IValidator, ValidationData, ValidatorError,
};
use crate::account_abstraction::UserOperation;

/// Verify a raw 64-byte Ed25519 signature over `msg` against a 32-byte key.
///
/// Returns `false` on any decoding or verification failure rather than
/// surfacing an error: a malformed signature and a wrong signature are the same
/// answer to the only question being asked, and distinguishing them in a return
/// type invites a caller to treat one of them as non-fatal.
fn verify_ed25519(pubkey: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    use tenzro_crypto::keys::{KeyType, PublicKey};
    use tenzro_crypto::signatures::{Signature, verify};

    if sig.len() != 64 {
        return false;
    }
    let pk = PublicKey::new(KeyType::Ed25519, pubkey.to_vec());
    let signature = Signature::new(KeyType::Ed25519, sig.to_vec());
    verify(&pk, msg, &signature).is_ok()
}

/// Per-account Ed25519 authenticator for identity-owned smart accounts.
///
/// One registry serves every account on the node; [`install_for`] binds an
/// account address to the verifying key of the identity that owns it.
pub struct IdentityKeyValidator {
    address: [u8; 20],
    /// account address (20-byte EVM form) -> identity Ed25519 verifying key.
    keys: Arc<DashMap<Vec<u8>, [u8; 32]>>,
}

impl IdentityKeyValidator {
    /// A validator module at `address` with no accounts bound yet.
    pub fn new(address: [u8; 20]) -> Self {
        Self {
            address,
            keys: Arc::new(DashMap::new()),
        }
    }

    /// Bind `account` to the identity verifying key that may authorize it.
    ///
    /// # Errors
    ///
    /// Refuses a key that is not exactly 32 bytes. A short or long key can
    /// never verify anything, so accepting one would install an account that
    /// silently rejects every operation its owner makes — a lockout that
    /// presents as a signature bug.
    pub fn install_for(&self, account: Vec<u8>, verifying_key: &[u8]) -> Result<(), ValidatorError> {
        if verifying_key.len() != 32 {
            return Err(ValidatorError::InvalidInput(format!(
                "identity verifying key must be 32 bytes for Ed25519, got {}",
                verifying_key.len()
            )));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(verifying_key);
        self.keys.insert(account, key);
        Ok(())
    }

    /// Forget an account's binding, e.g. when its identity is revoked.
    pub fn uninstall(&self, account: &[u8]) {
        self.keys.remove(account);
    }

    /// The verifying key bound to `account`, if any.
    pub fn key_for(&self, account: &[u8]) -> Option<[u8; 32]> {
        self.keys.get(account).map(|e| *e.value())
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

        if verify_ed25519(&key, op_hash, &op.signature) {
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
            Some(key) if verify_ed25519(&key, hash, signature) => ERC1271_MAGIC_VALUE,
            _ => ERC1271_FAILURE_VALUE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as DalekSigner, SigningKey};

    fn module_addr() -> [u8; 20] {
        [0x1du8; 20]
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
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
            signature,
        }
    }

    /// The machine's own key authorizes its account.
    #[test]
    fn the_identitys_key_validates_its_operations() {
        let v = IdentityKeyValidator::new(module_addr());
        let sk = signing_key(7);
        let account = vec![0xAAu8; 20];
        v.install_for(account.clone(), sk.verifying_key().as_bytes())
            .unwrap();

        let op_hash = [0x42u8; 32];
        let sig = sk.sign(&op_hash).to_bytes().to_vec();
        let result = v
            .validate_user_op(&user_op(account, sig), &op_hash)
            .unwrap();
        assert!(!result.is_failure(), "the owner's signature must validate");
    }

    /// The hole this closes.
    ///
    /// `NoOpValidator` accepted any non-empty signature, so a single zero byte
    /// was enough to move a machine's account. This is the exact input that
    /// used to pass.
    #[test]
    fn a_single_junk_byte_no_longer_authorizes_an_account() {
        let v = IdentityKeyValidator::new(module_addr());
        let sk = signing_key(7);
        let account = vec![0xAAu8; 20];
        v.install_for(account.clone(), sk.verifying_key().as_bytes())
            .unwrap();

        let result = v
            .validate_user_op(&user_op(account, vec![0x00]), &[0x42u8; 32])
            .unwrap();
        assert!(
            result.is_failure(),
            "a non-empty but meaningless signature must not validate"
        );
    }

    /// Somebody else's valid signature is still somebody else's.
    #[test]
    fn another_keys_signature_does_not_authorize_this_account() {
        let v = IdentityKeyValidator::new(module_addr());
        let owner = signing_key(7);
        let stranger = signing_key(9);
        let account = vec![0xAAu8; 20];
        v.install_for(account.clone(), owner.verifying_key().as_bytes())
            .unwrap();

        let op_hash = [0x42u8; 32];
        let sig = stranger.sign(&op_hash).to_bytes().to_vec();
        let result = v
            .validate_user_op(&user_op(account, sig), &op_hash)
            .unwrap();
        assert!(result.is_failure(), "a stranger's signature must not validate");
    }

    /// A signature over a different operation must not carry over to this one.
    #[test]
    fn a_signature_over_a_different_operation_is_rejected() {
        let v = IdentityKeyValidator::new(module_addr());
        let sk = signing_key(7);
        let account = vec![0xAAu8; 20];
        v.install_for(account.clone(), sk.verifying_key().as_bytes())
            .unwrap();

        let signed_hash = [0x01u8; 32];
        let presented_hash = [0x02u8; 32];
        let sig = sk.sign(&signed_hash).to_bytes().to_vec();
        let result = v
            .validate_user_op(&user_op(account, sig), &presented_hash)
            .unwrap();
        assert!(result.is_failure(), "replaying a signature must not validate");
    }

    /// An unconfigured account is a wiring error, not a rejected request.
    #[test]
    fn an_account_with_no_key_installed_is_an_error() {
        let v = IdentityKeyValidator::new(module_addr());
        let err = v.validate_user_op(&user_op(vec![0xBBu8; 20], vec![1; 64]), &[0u8; 32]);
        assert!(matches!(err, Err(ValidatorError::InvalidInput(_))));
    }

    /// A key that cannot verify anything is refused at install time.
    #[test]
    fn a_wrong_length_key_is_refused_rather_than_locking_the_account_out() {
        let v = IdentityKeyValidator::new(module_addr());
        assert!(v.install_for(vec![0xAAu8; 20], &[1u8; 31]).is_err());
        assert!(v.install_for(vec![0xAAu8; 20], &[1u8; 33]).is_err());
        assert!(v.install_for(vec![0xAAu8; 20], &[]).is_err());
    }

    /// Empty signatures were the one thing the no-op did reject; keep that.
    #[test]
    fn an_empty_signature_is_rejected() {
        let v = IdentityKeyValidator::new(module_addr());
        let sk = signing_key(7);
        let account = vec![0xAAu8; 20];
        v.install_for(account.clone(), sk.verifying_key().as_bytes())
            .unwrap();
        let result = v
            .validate_user_op(&user_op(account, Vec::new()), &[0x42u8; 32])
            .unwrap();
        assert!(result.is_failure());
    }

    /// ERC-1271 answers agree with UserOp validation.
    #[test]
    fn the_erc1271_path_agrees_with_user_op_validation() {
        let v = IdentityKeyValidator::new(module_addr());
        let sk = signing_key(7);
        let account = vec![0xAAu8; 20];
        v.install_for(account.clone(), sk.verifying_key().as_bytes())
            .unwrap();

        let hash = [0x42u8; 32];
        let good = sk.sign(&hash).to_bytes().to_vec();
        assert_eq!(
            v.is_valid_signature_with_sender(&account, &hash, &good),
            ERC1271_MAGIC_VALUE
        );
        assert_eq!(
            v.is_valid_signature_with_sender(&account, &hash, &[0x00]),
            ERC1271_FAILURE_VALUE
        );
        assert_eq!(
            v.is_valid_signature_with_sender(&[0xBBu8; 20], &hash, &good),
            ERC1271_FAILURE_VALUE,
            "an unbound account must not validate"
        );
    }

    /// Revoking a binding stops the account validating.
    #[test]
    fn uninstalling_a_binding_stops_it_validating() {
        let v = IdentityKeyValidator::new(module_addr());
        let sk = signing_key(7);
        let account = vec![0xAAu8; 20];
        v.install_for(account.clone(), sk.verifying_key().as_bytes())
            .unwrap();
        v.uninstall(&account);
        assert!(v.key_for(&account).is_none());
    }
}
