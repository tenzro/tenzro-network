//! Passkey validator (ERC-7579 module).
//!
//! Authorises a `UserOperation` against an enrolled passkey (WebAuthn / FIDO2
//! P-256 credential). A passkey signs with P-256 alone. When the P-256 key has
//! a hardware ML-DSA-65 key enrolled in chain state (`AccountKeys` /
//! `EnrollPqKey`, see [`crate::account_keys`]), every signature must also
//! carry that ML-DSA-65 leg: dropping it is refused, so the P-256 key alone
//! cannot spend once the stronger key exists. The ML-DSA-65 key is read from
//! state on every check, never from the enrolment record or the signature.
//!
//! # Signature wire format
//!
//! `userOp.signature` is the bincode encoding of `Vec<PasskeySignature>`, one
//! entry per contributing credential:
//!
//! ```text
//! [PasskeySignature {
//!     credential_id: Vec<u8>,          // which enrolled passkey signed
//!     signature: CompositeSignature,   // WebAuthn P-256 leg + optional hardware ML-DSA-65 leg
//! }, ..]
//! ```
//!
//! The entry count must equal the account's [`SecondFactorPolicy`]
//! requirement exactly: one for the default
//! [`SecondFactorPolicy::SingleCredential`], two distinct credentials for
//! [`SecondFactorPolicy::TwoCredentials`].
//!
//! # Challenge binding
//!
//! Both legs sign the composite representative of the hash under a context:
//! [`SignatureContext::UserOperation`] for a UserOperation,
//! [`SignatureContext::SmartAccountMessage`] for an ERC-1271 signature. The
//! WebAuthn challenge is `base64url_no_pad(signing_digest(context, hash))`
//! ([`WebAuthnValidator::expected_challenge_for`]), and the assertion must
//! carry user verification.

use serde::{Deserialize, Serialize};
use std::sync::Arc;

use tenzro_crypto::composite::{
    ClassicalProof, CompositeSignature, PqPolicy, SignatureContext, verify_pq_component,
    webauthn_challenge,
};
use tenzro_crypto::webauthn::{
    WebAuthnAssertion, WebAuthnCeremonyType, WebAuthnRelyingParty,
    verify_webauthn_assertion_require_uv,
};

use crate::aa_validators::{
    ERC1271_FAILURE_VALUE, ERC1271_MAGIC_VALUE, IValidator, ValidationData, ValidatorError,
};
use crate::account_abstraction::UserOperation;

// -----------------------------------------------------------------------------
// Keystore
// -----------------------------------------------------------------------------

/// One linked passkey, as the account's keystore in consensus state holds it.
pub use tenzro_types::keystore::KeystoreCredential;
/// Independent roots of control an account needs before its passkeys may
/// spend from it.
pub use tenzro_types::keystore::SPEND_MIN_INDEPENDENT_ROOTS;
/// How many passkeys must co-sign, from the account's keystore.
pub use tenzro_types::keystore::SecondFactorPolicy;

// -----------------------------------------------------------------------------
// Wire-format signature
// -----------------------------------------------------------------------------

/// Wire-format `userOp.signature` entry consumed by [`WebAuthnValidator`]:
/// the passkey's assertion as the P-256 leg of a [`CompositeSignature`], the
/// hardware ML-DSA-65 leg when one is enrolled for that passkey, and the
/// `credential.id` naming which enrolled passkey signed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeySignature {
    /// Raw `credential.id` bytes (base64url-decoded). Identifies which
    /// enrolled credential on the sender's account this signature
    /// corresponds to. Required.
    pub credential_id: Vec<u8>,
    /// The P-256 leg in WebAuthn form, plus the ML-DSA-65 leg when the
    /// passkey has one enrolled.
    pub signature: CompositeSignature,
}

impl PasskeySignature {
    /// Encode a signature bundle for embedding in `userOp.signature`.
    /// One entry per contributing credential — the entry count must match
    /// the account's [`SecondFactorPolicy`] exactly. Uses bincode 1.x
    /// default config (fixint-encoded lengths, little-endian) — matches
    /// the workspace-pinned bincode version.
    pub fn encode_bundle(signatures: &[Self]) -> Result<Vec<u8>, ValidatorError> {
        bincode::serialize(signatures)
            .map_err(|e| ValidatorError::InvalidInput(format!("bincode encode: {}", e)))
    }

    /// Decode a signature bundle from `userOp.signature` bytes.
    pub fn decode_bundle(bytes: &[u8]) -> Result<Vec<Self>, ValidatorError> {
        bincode::deserialize::<Vec<Self>>(bytes)
            .map_err(|e| ValidatorError::InvalidInput(format!("bincode decode: {}", e)))
    }
}

// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
// WebAuthnValidator
// -----------------------------------------------------------------------------

/// ERC-7579 validator module that authorises UserOperations and custody
/// approvals against the passkeys an account's keystore links in consensus
/// state (see [`crate::keystore`]), each with the hardware ML-DSA-65 leg its
/// P-256 key has enrolled, if any.
///
/// It holds no credentials of its own: every check reads the keystore from
/// the chain state this node has committed, so a passkey linked through any
/// node verifies here, and one unlinked anywhere stops verifying here. Each
/// assertion is checked against the relying party the keystore records for
/// that passkey.
pub struct WebAuthnValidator {
    address: [u8; 20],
    relying_party: WebAuthnRelyingParty,
    clock_override: parking_lot::RwLock<Option<u64>>,
    storage: Option<Arc<dyn tenzro_storage::KvStore>>,
    memory_state: crate::StateAdapter,
}

impl WebAuthnValidator {
    /// A validator over an in-memory state, for tests.
    pub fn new(address: [u8; 20], relying_party: WebAuthnRelyingParty) -> Self {
        Self {
            address,
            relying_party,
            clock_override: parking_lot::RwLock::new(None),
            storage: None,
            memory_state: crate::StateAdapter::new(),
        }
    }

    /// A validator over the node's committed chain state.
    pub fn with_storage(
        address: [u8; 20],
        relying_party: WebAuthnRelyingParty,
        storage: Arc<dyn tenzro_storage::KvStore>,
    ) -> Self {
        Self {
            address,
            relying_party,
            clock_override: parking_lot::RwLock::new(None),
            storage: Some(storage),
            memory_state: crate::StateAdapter::new(),
        }
    }

    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// The chain state the keystores are read from.
    pub fn state(&self) -> crate::StateAdapter {
        match &self.storage {
            Some(storage) => crate::StateAdapter::with_storage(storage.clone()),
            None => self.memory_state.shared_reader(),
        }
    }

    /// The keystore of `account`, as consensus state holds it.
    pub fn keystore(&self, account: &[u8]) -> Option<tenzro_types::keystore::KeystoreRecord> {
        let account = crate::keystore::account20(account)?;
        crate::keystore::read_record(&self.state(), &account)
    }

    /// The keystore of `account`: the one on chain, or for an account with
    /// none yet, the genesis record of `anchor` when its passkey derives the
    /// account.
    pub fn keystore_or_genesis(
        &self,
        account: &[u8],
        anchor: Option<&tenzro_types::keystore::KeystoreAnchor>,
    ) -> Option<tenzro_types::keystore::KeystoreRecord> {
        if let Some(record) = self.keystore(account) {
            return Some(record);
        }
        let account = crate::keystore::account20(account)?;
        let genesis = tenzro_types::keystore::KeystoreRecord::genesis(anchor?);
        (genesis.account == account).then_some(genesis)
    }

    /// The account's [`SecondFactorPolicy`]; the default for an account
    /// with no keystore on chain.
    pub fn second_factor_policy(&self, account: &[u8]) -> SecondFactorPolicy {
        self.keystore(account).map(|r| r.policy).unwrap_or_default()
    }

    /// The relying party of the ceremony pages this node hosts (passkey
    /// sign-in and enrolment). Verification never uses it: every passkey is
    /// checked against the relying party its keystore records.
    pub fn relying_party(&self) -> &WebAuthnRelyingParty {
        &self.relying_party
    }

    /// The passkey `credential_id` linked to `account`.
    pub fn get_credential(
        &self,
        account: &[u8],
        credential_id: &[u8],
    ) -> Option<KeystoreCredential> {
        self.keystore(account)?
            .credential_by_id(credential_id)
            .cloned()
    }

    /// The credential ids linked to `account`.
    pub fn list_credentials(&self, account: &[u8]) -> Vec<Vec<u8>> {
        self.keystore(account)
            .map(|r| r.credentials.into_iter().map(|c| c.credential_id).collect())
            .unwrap_or_default()
    }

    /// How many independent roots of control the passkeys linked to
    /// `account` amount to now. A passkey still in its waiting period does
    /// not count yet.
    pub fn independent_roots(&self, account: &[u8]) -> usize {
        self.keystore(account)
            .map(|r| r.independent_roots_at(self.now().saturating_mul(1000)))
            .unwrap_or(0)
    }

    /// Pin the validator's clock (Unix seconds) for tests; `None` reads the
    /// wall clock.
    pub fn set_clock_override(&self, unix_secs: Option<u64>) {
        *self.clock_override.write() = unix_secs;
    }

    /// Unix seconds now, or the pinned test clock.
    pub fn now(&self) -> u64 {
        if let Some(ts) = *self.clock_override.read() {
            return ts;
        }
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Verify a signature bundle by the passkeys linked to `account` over
    /// `hash` under `context`, with no independence floor.
    ///
    /// For approving a custody change, where the caller decides how many
    /// independent roots the change needs. Spending goes through
    /// [`IValidator::validate_user_op`], which applies
    /// [`SPEND_MIN_INDEPENDENT_ROOTS`].
    pub fn verify_approval(
        &self,
        account: &[u8],
        signature: &[u8],
        context: SignatureContext,
        hash: &[u8; 32],
    ) -> bool {
        match self.keystore(account) {
            Some(record) => self.verify_approval_by(&record, signature, context, hash),
            None => false,
        }
    }

    /// [`Self::verify_approval`] against a given keystore, such as the
    /// genesis record of an account with no keystore on chain yet (see
    /// [`Self::keystore_or_genesis`]).
    pub fn verify_approval_by(
        &self,
        record: &tenzro_types::keystore::KeystoreRecord,
        signature: &[u8],
        context: SignatureContext,
        hash: &[u8; 32],
    ) -> bool {
        match PasskeySignature::decode_bundle(signature) {
            Ok(bundle) => self.verify_bundle(record, &bundle, context, hash),
            Err(_) => false,
        }
    }

    /// Whether `account` may spend: its passkeys must amount to at least
    /// [`SPEND_MIN_INDEPENDENT_ROOTS`] independent roots.
    pub fn may_spend(&self, account: &[u8]) -> bool {
        self.independent_roots(account) >= SPEND_MIN_INDEPENDENT_ROOTS
    }

    /// The WebAuthn challenge the relying party must issue for `hash` under
    /// `context`: `base64url_no_pad(signing_digest(context, hash))`.
    pub fn expected_challenge_for(context: SignatureContext, hash: &[u8; 32]) -> String {
        webauthn_challenge(context, hash)
    }

    /// The hardware ML-DSA-65 key enrolled in chain state for the passkey
    /// whose P-256 key is `p256_xy`.
    pub fn enrolled_pq_key(&self, p256_xy: &[u8]) -> Option<Vec<u8>> {
        crate::account_keys::enrolled_pq_key(&self.state(), p256_xy)
    }

    /// Verify a decoded signature bundle against `account` and `hash`.
    ///
    /// Fail-closed checks, in order:
    /// 1. bundle length must EXACTLY equal the account policy's
    ///    [`SecondFactorPolicy::required_signatures`];
    /// 2. every entry must address a *distinct* passkey;
    /// 3. per entry: the passkey must be linked to the account (no
    ///    fallback), the WebAuthn P-256 leg must verify with user
    ///    verification over the derived challenge, and the ML-DSA-65 leg
    ///    against the key enrolled in state: required when one is enrolled,
    ///    refused when none is.
    fn verify_bundle(
        &self,
        record: &tenzro_types::keystore::KeystoreRecord,
        bundle: &[PasskeySignature],
        context: SignatureContext,
        hash: &[u8; 32],
    ) -> bool {
        if bundle.len() != record.policy.required_signatures() {
            return false;
        }
        for i in 0..bundle.len() {
            for j in (i + 1)..bundle.len() {
                if bundle[i].credential_id == bundle[j].credential_id {
                    return false;
                }
            }
        }
        let state = self.state();
        let expected_challenge = Self::expected_challenge_for(context, hash);
        for entry in bundle {
            let Some(key) = record.credential_by_id(&entry.credential_id) else {
                return false;
            };
            let ClassicalProof::WebAuthn {
                authenticator_data,
                client_data_json,
                signature,
            } = &entry.signature.classical
            else {
                return false;
            };
            let assertion = WebAuthnAssertion {
                authenticator_data: authenticator_data.clone(),
                client_data_json: client_data_json.clone(),
                signature: signature.clone(),
                user_handle: None,
            };
            // Each passkey answers to the relying party its keystore
            // records: any wallet provider's domain, with no list of related
            // origins and nothing from this node's own configuration.
            let relying_party = WebAuthnRelyingParty::RegistrableDomain {
                rp_id: key.rp_id.clone(),
                related_origins: Vec::new(),
            };
            if verify_webauthn_assertion_require_uv(
                &assertion,
                &key.public_key,
                &expected_challenge,
                &relying_party,
                WebAuthnCeremonyType::Get,
            )
            .is_err()
            {
                return false;
            }
            if verify_pq_component(
                crate::account_keys::enrolled_pq_key(&state, &key.public_key).as_deref(),
                context,
                hash,
                entry.signature.pq.as_deref(),
                PqPolicy::Required,
            )
            .is_err()
            {
                return false;
            }
        }
        true
    }
}

impl IValidator for WebAuthnValidator {
    fn module_address(&self) -> [u8; 20] {
        self.address
    }

    fn validate_user_op(
        &self,
        op: &UserOperation,
        op_hash: &[u8; 32],
    ) -> Result<ValidationData, ValidatorError> {
        // Decode the signature bundle — one entry per contributing
        // credential — then run the policy-aware verification: exact
        // entry count per the account's SecondFactorPolicy, distinct
        // credential ids, the P-256 leg and any enrolled ML-DSA-65 leg.
        if !self.may_spend(&op.sender) {
            return Ok(ValidationData::failure());
        }
        let bundle = match PasskeySignature::decode_bundle(&op.signature) {
            Ok(b) => b,
            Err(_) => return Ok(ValidationData::failure()),
        };
        let Some(record) = self.keystore(&op.sender) else {
            return Ok(ValidationData::failure());
        };
        if self.verify_bundle(&record, &bundle, SignatureContext::UserOperation, op_hash) {
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
        // An ERC-1271 signature can authorize a token approval or a permit,
        // which is spending, so it carries the same floor.
        if !self.may_spend(sender) {
            return ERC1271_FAILURE_VALUE;
        }
        let Ok(bundle) = PasskeySignature::decode_bundle(signature) else {
            return ERC1271_FAILURE_VALUE;
        };
        let Some(record) = self.keystore(sender) else {
            return ERC1271_FAILURE_VALUE;
        };
        if self.verify_bundle(
            &record,
            &bundle,
            SignatureContext::SmartAccountMessage,
            hash,
        ) {
            ERC1271_MAGIC_VALUE
        } else {
            ERC1271_FAILURE_VALUE
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use tenzro_types::device_binding::CredentialProvenance;
    use tenzro_types::keystore::KeystoreRecord;

    /// A passkey as a test links it: its P-256 key, where its key lives and
    /// the Unix second it starts counting as a root.
    #[derive(Debug, Clone)]
    struct WebAuthnAccountKey {
        pubkey_x: [u8; 32],
        pubkey_y: [u8; 32],
        provenance: CredentialProvenance,
        counts_as_root_from: u64,
    }

    impl WebAuthnAccountKey {
        fn new(pubkey_x: [u8; 32], pubkey_y: [u8; 32], provenance: CredentialProvenance) -> Self {
            Self {
                pubkey_x,
                pubkey_y,
                provenance,
                counts_as_root_from: 0,
            }
        }
        fn counting_as_root_from(mut self, unix_secs: u64) -> Self {
            self.counts_as_root_from = unix_secs;
            self
        }
        fn p256_public_key_xy(&self) -> [u8; 64] {
            let mut out = [0u8; 64];
            out[..32].copy_from_slice(&self.pubkey_x);
            out[32..].copy_from_slice(&self.pubkey_y);
            out
        }
    }

    /// Writes into the validator's chain state what a keystore change would.
    impl WebAuthnValidator {
        fn edit(&self, account: &[u8], f: impl FnOnce(&mut KeystoreRecord)) {
            let mut state = self.memory_state.shared_reader();
            let previous = crate::keystore::read_record(&state, account);
            let mut next = previous.clone().unwrap_or(KeystoreRecord {
                account: account.to_vec(),
                owner_did: "did:tenzro:human:test".to_string(),
                salt: 0,
                version: 0,
                credentials: Vec::new(),
                policy: SecondFactorPolicy::SingleCredential,
                recovery_signers: Vec::new(),
                recovery_threshold: 0,
                pending_recovery: None,
                recovery_code: None,
            });
            f(&mut next);
            next.version += 1;
            crate::keystore::write_record(&mut state, previous.as_ref(), &next, &mut Vec::new())
                .unwrap();
        }

        fn enroll(
            &self,
            account: Vec<u8>,
            credential_id: Vec<u8>,
            key: WebAuthnAccountKey,
        ) -> Result<(), ValidatorError> {
            self.edit(&account, |r| {
                r.credentials.retain(|c| c.credential_id != credential_id);
                r.credentials.push(KeystoreCredential {
                    rp_id: RP.to_string(),
                    credential_id,
                    public_key: key.p256_public_key_xy().to_vec(),
                    aaguid: key.provenance.aaguid.0.to_vec(),
                    backup_eligible: key.provenance.backup_eligible,
                    backup_state: key.provenance.backup_state,
                    counts_as_root_from_ms: key.counts_as_root_from * 1000,
                    label: String::new(),
                    added_at_ms: 0,
                });
            });
            Ok(())
        }

        fn revoke_credential(
            &self,
            account: &[u8],
            credential_id: &[u8],
        ) -> Result<bool, ValidatorError> {
            let present = self.get_credential(account, credential_id).is_some();
            self.edit(account, |r| {
                r.credentials.retain(|c| c.credential_id != credential_id)
            });
            Ok(present)
        }

        fn set_second_factor_policy(
            &self,
            account: Vec<u8>,
            policy: SecondFactorPolicy,
        ) -> Result<(), ValidatorError> {
            self.edit(&account, |r| r.policy = policy);
            Ok(())
        }

        fn enrolled_credential_count(&self, account: &[u8]) -> usize {
            self.list_credentials(account).len()
        }

        fn pending_roots(&self, account: &[u8]) -> Vec<(Vec<u8>, u64)> {
            let now_ms = self.now() * 1000;
            self.keystore(account)
                .map(|r| {
                    r.credentials
                        .into_iter()
                        .filter(|c| !c.counts_at(now_ms))
                        .map(|c| (c.credential_id, c.counts_as_root_from_ms / 1000))
                        .collect()
                })
                .unwrap_or_default()
        }
    }
    use crate::aa_validators::{ModuleAttestation, ModuleType, NoOpValidator, ValidatorRegistry};
    use crate::account_abstraction::UserOperation;
    use sha2::{Digest, Sha256};
    use tenzro_crypto::composite::{LABEL_MLDSA65_P256, message_representative};
    use tenzro_crypto::p256::{P256KeyPair, P256Signer};
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_crypto::webauthn::webauthn_signed_hash;

    const ORIGIN: &str = "https://wallet.tenzro.com";
    const RP: &str = "tenzro.com";

    /// A device-bound credential: its own root of control.
    fn device_bound() -> CredentialProvenance {
        CredentialProvenance {
            aaguid: tenzro_types::device_binding::Aaguid([0xcb; 16]),
            backup_eligible: false,
            backup_state: false,
        }
    }

    /// A passkey synced by the provider `aaguid` names.
    fn synced(aaguid: u8) -> CredentialProvenance {
        CredentialProvenance {
            aaguid: tenzro_types::device_binding::Aaguid([aaguid; 16]),
            backup_eligible: true,
            backup_state: true,
        }
    }

    /// Enroll a second, device-bound credential on `account`, so an account
    /// whose test signs with one passkey clears the spending floor.
    fn add_second_root(validator: &WebAuthnValidator, account: &[u8]) {
        let key = WebAuthnAccountKey::new([0x5au8; 32], [0x5bu8; 32], device_bound());
        enroll_hybrid(&validator, account.to_vec(), b"second-root".to_vec(), key);
    }

    /// A passkey: its credential id, P-256 key and enrolment record.
    struct TestPasskey {
        credential_id: Vec<u8>,
        signer: P256Signer,
        enrollment: WebAuthnAccountKey,
    }

    impl TestPasskey {
        fn generate() -> Self {
            // A unique credential id per passkey; the authenticator picks it
            // in production.
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let d: [u8; 32] =
                Sha256::digest([b"cred:".as_slice(), &seq.to_le_bytes()].concat()).into();
            let p256 = P256KeyPair::generate();
            let xy = p256.public_key_bytes();
            let mut x = [0u8; 32];
            let mut y = [0u8; 32];
            x.copy_from_slice(&xy[..32]);
            y.copy_from_slice(&xy[32..]);
            Self {
                credential_id: d[..16].to_vec(),
                signer: P256Signer::from_keypair(&p256),
                enrollment: WebAuthnAccountKey::new(x, y, device_bound()),
            }
        }

        fn p256_xy(&self) -> [u8; 64] {
            self.enrollment.p256_public_key_xy()
        }

        /// The passkey's assertion over `hash` under `context`, user
        /// verified, from [`ORIGIN`].
        fn sign(&self, context: SignatureContext, hash: &[u8; 32]) -> PasskeySignature {
            let client_data_json = serde_json::json!({
                "type": "webauthn.get",
                "challenge": WebAuthnValidator::expected_challenge_for(context, hash),
                "origin": ORIGIN,
            })
            .to_string()
            .into_bytes();
            // rpIdHash (unchecked under an exact origin) + flags UP|UV + signCount.
            let mut authenticator_data = Sha256::digest(RP.as_bytes()).to_vec();
            authenticator_data.extend_from_slice(&[0x05, 0, 0, 0, 0]);
            let prehash = webauthn_signed_hash(&authenticator_data, &client_data_json);
            PasskeySignature {
                credential_id: self.credential_id.clone(),
                signature: CompositeSignature::classical(ClassicalProof::WebAuthn {
                    authenticator_data,
                    client_data_json,
                    signature: self.signer.sign_prehash(&prehash).as_bytes().to_vec(),
                }),
            }
        }
    }

    /// The ML-DSA-65 key a test passkey holds beside its P-256 key, derived
    /// from the P-256 key so a test can enroll and sign with it from the key
    /// alone.
    fn test_pq_key(p256_xy: &[u8]) -> MlDsaSigningKey {
        let seed: [u8; 32] =
            Sha256::digest([b"test-passkey-pq:".as_slice(), p256_xy].concat()).into();
        MlDsaSigningKey::from_seed(&seed).expect("seed")
    }

    /// Enroll a credential on `account` and record its ML-DSA-65 key as the
    /// one enrolled for its P-256 key.
    fn enroll_hybrid(
        validator: &WebAuthnValidator,
        account: Vec<u8>,
        credential_id: Vec<u8>,
        key: WebAuthnAccountKey,
    ) {
        let xy = key.p256_public_key_xy();
        validator.enroll(account, credential_id, key).unwrap();
        let mut state = validator.memory_state.shared_reader();
        crate::account_keys::set_enrolled_pq_key(
            &mut state,
            &xy,
            test_pq_key(&xy).verifying_key_bytes().to_vec(),
            &mut Vec::new(),
        );
    }

    /// Enroll `pq` in the validator's chain state as the hardware ML-DSA-65
    /// key of `passkey`.
    fn enroll_pq_key(validator: &WebAuthnValidator, passkey: &TestPasskey, pq: &MlDsaSigningKey) {
        // A handle onto the validator's own caches, so the write is visible to it.
        let mut state = validator.memory_state.shared_reader();
        crate::account_keys::set_enrolled_pq_key(
            &mut state,
            &passkey.p256_xy(),
            pq.verifying_key_bytes().to_vec(),
            &mut Vec::new(),
        );
    }

    /// The ML-DSA-65 leg by `pq` over `hash` under `context`.
    fn pq_leg(pq: &MlDsaSigningKey, context: SignatureContext, hash: &[u8; 32]) -> Vec<u8> {
        pq.sign(LABEL_MLDSA65_P256, &message_representative(context, hash))
    }

    impl TestPasskey {
        /// [`TestPasskey::sign`] with the ML-DSA-65 leg of the passkey's
        /// derived key.
        fn sign_hybrid(&self, context: SignatureContext, hash: &[u8; 32]) -> PasskeySignature {
            let mut leg = self.sign(context, hash);
            leg.signature.pq = Some(pq_leg(&test_pq_key(&self.p256_xy()), context, hash));
            leg
        }
    }

    /// Build an enrollment and its passkey's P-256 signature over `op_hash`.
    fn make_leg(op_hash: &[u8; 32]) -> (Vec<u8>, WebAuthnAccountKey, PasskeySignature) {
        let passkey = TestPasskey::generate();
        let leg = passkey.sign_hybrid(SignatureContext::UserOperation, op_hash);
        (
            passkey.credential_id.clone(),
            passkey.enrollment.clone(),
            leg,
        )
    }

    /// Single-credential convenience: leg wrapped as a one-entry bundle,
    /// already wire-encoded for `userOp.signature`.
    fn make_sig(op_hash: &[u8; 32]) -> (Vec<u8>, WebAuthnAccountKey, Vec<u8>) {
        let (credential_id, enrollment, leg) = make_leg(op_hash);
        let bytes = PasskeySignature::encode_bundle(std::slice::from_ref(&leg)).expect("encode");
        (credential_id, enrollment, bytes)
    }

    fn dummy_user_op(sender: Vec<u8>, sig: Vec<u8>) -> UserOperation {
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
            signature: sig,
        }
    }

    #[test]
    fn challenge_is_the_composite_digest_of_the_hash() {
        let op_hash = [0xABu8; 32];
        let challenge =
            WebAuthnValidator::expected_challenge_for(SignatureContext::UserOperation, &op_hash);
        assert_eq!(
            challenge,
            webauthn_challenge(SignatureContext::UserOperation, &op_hash)
        );
        assert_ne!(
            challenge,
            WebAuthnValidator::expected_challenge_for(
                SignatureContext::SmartAccountMessage,
                &op_hash
            )
        );
        // 32 bytes -> 43 chars in base64url no-pad.
        assert_eq!(challenge.len(), 43);
    }

    #[test]
    fn validate_succeeds_with_matching_hybrid_signature() {
        let op_hash = [0x42u8; 32];
        let (cred_id, enrollment, sig_bytes) = make_sig(&op_hash);

        let validator = WebAuthnValidator::new(
            [0xCCu8; 20],
            WebAuthnRelyingParty::Origin(ORIGIN.to_string()),
        );
        let account = vec![0x01; 20];
        enroll_hybrid(&validator, account.clone(), cred_id, enrollment);
        add_second_root(&validator, &account);

        let op = dummy_user_op(account, sig_bytes);
        let result = validator.validate_user_op(&op, &op_hash).unwrap();
        assert!(!result.is_failure(), "hybrid sig should validate");
    }

    #[test]
    fn validate_fails_when_account_not_enrolled() {
        let op_hash = [0x42u8; 32];
        let (_cred_id, _enrollment, sig_bytes) = make_sig(&op_hash);

        let validator = WebAuthnValidator::new(
            [0xCCu8; 20],
            WebAuthnRelyingParty::Origin(ORIGIN.to_string()),
        );
        let account = vec![0x01; 20];
        // Note: did NOT call validator.enroll().
        let op = dummy_user_op(account, sig_bytes);
        let result = validator.validate_user_op(&op, &op_hash).unwrap();
        assert!(result.is_failure(), "unenrolled account must fail closed");
    }

    #[test]
    fn validate_fails_when_op_hash_changes() {
        let op_hash = [0x42u8; 32];
        let (cred_id, enrollment, sig_bytes) = make_sig(&op_hash);

        let validator = WebAuthnValidator::new(
            [0xCCu8; 20],
            WebAuthnRelyingParty::Origin(ORIGIN.to_string()),
        );
        let account = vec![0x01; 20];
        enroll_hybrid(&validator, account.clone(), cred_id, enrollment);
        add_second_root(&validator, &account);

        // Change the challenge target: WebAuthn challenge mismatch + ML-DSA fails.
        let different_op_hash = [0x99u8; 32];
        let op = dummy_user_op(account, sig_bytes);
        let result = validator.validate_user_op(&op, &different_op_hash).unwrap();
        assert!(result.is_failure(), "tampered op_hash must fail");
    }

    /// A validator with one enrolled passkey on `account` (plus a second
    /// root, so it may spend) that has `pq` enrolled in chain state.
    fn hybrid_account(pq: &MlDsaSigningKey) -> (WebAuthnValidator, Vec<u8>, TestPasskey) {
        let validator = WebAuthnValidator::new(
            [0xCCu8; 20],
            WebAuthnRelyingParty::Origin(ORIGIN.to_string()),
        );
        let account = vec![0x01; 20];
        let passkey = TestPasskey::generate();
        enroll_hybrid(
            &validator,
            account.clone(),
            passkey.credential_id.clone(),
            passkey.enrollment.clone(),
        );
        add_second_root(&validator, &account);
        enroll_pq_key(&validator, &passkey, pq);
        (validator, account, passkey)
    }

    #[test]
    fn an_enrolled_ml_dsa_key_signs_alongside_the_passkey() {
        let op_hash = [0x42u8; 32];
        let pq = MlDsaSigningKey::generate();
        let (validator, account, passkey) = hybrid_account(&pq);
        let mut leg = passkey.sign(SignatureContext::UserOperation, &op_hash);
        leg.signature.pq = Some(pq_leg(&pq, SignatureContext::UserOperation, &op_hash));
        let op = dummy_user_op(account, PasskeySignature::encode_bundle(&[leg]).unwrap());
        assert!(
            !validator
                .validate_user_op(&op, &op_hash)
                .unwrap()
                .is_failure()
        );
    }

    #[test]
    fn the_ml_dsa_leg_cannot_be_stripped_once_enrolled() {
        let op_hash = [0x42u8; 32];
        let pq = MlDsaSigningKey::generate();
        let (validator, account, passkey) = hybrid_account(&pq);
        let leg = passkey.sign(SignatureContext::UserOperation, &op_hash);
        let op = dummy_user_op(account, PasskeySignature::encode_bundle(&[leg]).unwrap());
        assert!(
            validator
                .validate_user_op(&op, &op_hash)
                .unwrap()
                .is_failure(),
            "the P-256 leg alone must not spend once an ML-DSA-65 key is enrolled"
        );
    }

    #[test]
    fn validate_fails_when_ml_dsa_signature_tampered() {
        let op_hash = [0x42u8; 32];
        let pq = MlDsaSigningKey::generate();
        let (validator, account, passkey) = hybrid_account(&pq);
        let mut leg = passkey.sign(SignatureContext::UserOperation, &op_hash);
        let mut pq_sig = pq_leg(&pq, SignatureContext::UserOperation, &op_hash);
        pq_sig[100] ^= 0x01;
        leg.signature.pq = Some(pq_sig);
        let op = dummy_user_op(account, PasskeySignature::encode_bundle(&[leg]).unwrap());
        assert!(
            validator
                .validate_user_op(&op, &op_hash)
                .unwrap()
                .is_failure()
        );
    }

    #[test]
    fn an_ml_dsa_key_that_is_not_enrolled_is_refused() {
        let op_hash = [0x42u8; 32];
        let (cred_id, enrollment, mut leg) = make_leg(&op_hash);
        let other = MlDsaSigningKey::generate();
        leg.signature.pq = Some(pq_leg(&other, SignatureContext::UserOperation, &op_hash));
        let validator = WebAuthnValidator::new(
            [0xCCu8; 20],
            WebAuthnRelyingParty::Origin(ORIGIN.to_string()),
        );
        let account = vec![0x01; 20];
        enroll_hybrid(&validator, account.clone(), cred_id, enrollment);
        add_second_root(&validator, &account);
        let op = dummy_user_op(account, PasskeySignature::encode_bundle(&[leg]).unwrap());
        assert!(
            validator
                .validate_user_op(&op, &op_hash)
                .unwrap()
                .is_failure()
        );
    }

    #[test]
    fn an_ml_dsa_leg_from_another_key_is_refused() {
        let op_hash = [0x42u8; 32];
        let pq = MlDsaSigningKey::generate();
        let (validator, account, passkey) = hybrid_account(&pq);
        let mut leg = passkey.sign(SignatureContext::UserOperation, &op_hash);
        leg.signature.pq = Some(pq_leg(
            &MlDsaSigningKey::generate(),
            SignatureContext::UserOperation,
            &op_hash,
        ));
        let op = dummy_user_op(account, PasskeySignature::encode_bundle(&[leg]).unwrap());
        assert!(
            validator
                .validate_user_op(&op, &op_hash)
                .unwrap()
                .is_failure()
        );
    }

    #[test]
    fn a_raw_p256_signature_is_not_a_passkey_assertion() {
        let op_hash = [0x42u8; 32];
        let passkey = TestPasskey::generate();
        let digest =
            tenzro_crypto::composite::signing_digest(SignatureContext::UserOperation, &op_hash);
        let leg = PasskeySignature {
            credential_id: passkey.credential_id.clone(),
            signature: CompositeSignature::classical(ClassicalProof::Raw {
                signature: passkey.signer.sign_prehash(&digest).as_bytes().to_vec(),
            }),
        };
        let validator = WebAuthnValidator::new(
            [0xCCu8; 20],
            WebAuthnRelyingParty::Origin(ORIGIN.to_string()),
        );
        let account = vec![0x01; 20];
        enroll_hybrid(
            &validator,
            account.clone(),
            passkey.credential_id.clone(),
            passkey.enrollment.clone(),
        );
        add_second_root(&validator, &account);
        let op = dummy_user_op(account, PasskeySignature::encode_bundle(&[leg]).unwrap());
        assert!(
            validator
                .validate_user_op(&op, &op_hash)
                .unwrap()
                .is_failure()
        );
    }

    #[test]
    fn validate_fails_when_origin_mismatch() {
        let op_hash = [0x42u8; 32];
        let (cred_id, enrollment, sig_bytes) = make_sig(&op_hash);

        // The keystore records the passkey under another relying party, so
        // an assertion made for tenzro.com does not verify for it.
        let validator = WebAuthnValidator::new(
            [0xCCu8; 20],
            WebAuthnRelyingParty::Origin(ORIGIN.to_string()),
        );
        let account = vec![0x01; 20];
        enroll_hybrid(&validator, account.clone(), cred_id.clone(), enrollment);
        add_second_root(&validator, &account);
        validator.edit(&account, |r| {
            for c in r
                .credentials
                .iter_mut()
                .filter(|c| c.credential_id == cred_id)
            {
                c.rp_id = "example.org".to_string();
            }
        });

        let op = dummy_user_op(account, sig_bytes);
        let result = validator.validate_user_op(&op, &op_hash).unwrap();
        assert!(result.is_failure(), "origin mismatch must fail");
    }

    #[test]
    fn erc1271_returns_magic_on_success_and_failure_otherwise() {
        let op_hash = [0x42u8; 32];
        let passkey = TestPasskey::generate();
        let (cred_id, enrollment) = (passkey.credential_id.clone(), passkey.enrollment.clone());
        let sig_bytes = PasskeySignature::encode_bundle(&[
            passkey.sign_hybrid(SignatureContext::SmartAccountMessage, &op_hash)
        ])
        .unwrap();

        let validator = WebAuthnValidator::new(
            [0xCCu8; 20],
            WebAuthnRelyingParty::Origin(ORIGIN.to_string()),
        );
        let account = vec![0x01; 20];
        enroll_hybrid(&validator, account.clone(), cred_id, enrollment);
        add_second_root(&validator, &account);

        let magic = validator.is_valid_signature_with_sender(&account, &op_hash, &sig_bytes);
        assert_eq!(magic, ERC1271_MAGIC_VALUE);

        // Unenrolled sender → failure.
        let other = vec![0x02; 20];
        let fail = validator.is_valid_signature_with_sender(&other, &op_hash, &sig_bytes);
        assert_eq!(fail, ERC1271_FAILURE_VALUE);
    }

    /// One passkey is one root: it may approve a custody change, and it may
    /// not spend.
    #[test]
    fn a_single_root_cannot_spend_but_can_approve() {
        let op_hash = [0x42u8; 32];
        let (cred_id, enrollment, sig_bytes) = make_sig(&op_hash);
        let validator = WebAuthnValidator::new(
            [0xCCu8; 20],
            WebAuthnRelyingParty::Origin(ORIGIN.to_string()),
        );
        let account = vec![0x01; 20];
        enroll_hybrid(&validator, account.clone(), cred_id, enrollment);
        assert_eq!(validator.independent_roots(&account), 1);

        let op = dummy_user_op(account.clone(), sig_bytes.clone());
        assert!(
            validator
                .validate_user_op(&op, &op_hash)
                .unwrap()
                .is_failure()
        );
        assert_eq!(
            validator.is_valid_signature_with_sender(&account, &op_hash, &sig_bytes),
            ERC1271_FAILURE_VALUE
        );
        assert!(validator.verify_approval(
            &account,
            &sig_bytes,
            SignatureContext::UserOperation,
            &op_hash
        ));

        add_second_root(&validator, &account);
        assert!(
            !validator
                .validate_user_op(&op, &op_hash)
                .unwrap()
                .is_failure()
        );
    }

    /// A passkey in its waiting period signs but does not count as a root, so
    /// the account cannot spend on it until the wait is over.
    #[test]
    fn a_waiting_passkey_counts_as_a_root_only_after_its_wait() {
        let op_hash = [0x44u8; 32];
        let (cred_id, mut first, sig_bytes) = make_sig(&op_hash);
        first.provenance = synced(0x01);
        let validator = WebAuthnValidator::new(
            [0xCCu8; 20],
            WebAuthnRelyingParty::Origin(ORIGIN.to_string()),
        );
        validator.set_clock_override(Some(1_000));
        let account = vec![0x03; 20];
        enroll_hybrid(&validator, account.clone(), cred_id, first);

        let (cred_new, mut added, _) = make_sig(&op_hash);
        added.provenance = synced(0x02);
        let added = added.counting_as_root_from(1_000 + 3_600);
        enroll_hybrid(&validator, account.clone(), cred_new.clone(), added);

        assert_eq!(validator.independent_roots(&account), 1);
        assert_eq!(validator.pending_roots(&account), vec![(cred_new, 4_600)]);
        let op = dummy_user_op(account.clone(), sig_bytes);
        assert!(
            validator
                .validate_user_op(&op, &op_hash)
                .unwrap()
                .is_failure()
        );

        validator.set_clock_override(Some(4_600));
        assert_eq!(validator.independent_roots(&account), 2);
        assert!(validator.pending_roots(&account).is_empty());
        assert!(
            !validator
                .validate_user_op(&op, &op_hash)
                .unwrap()
                .is_failure()
        );
    }

    /// Two passkeys one provider syncs are one root; a passkey from a second
    /// provider makes two.
    #[test]
    fn synced_passkeys_spend_only_across_two_providers() {
        let op_hash = [0x43u8; 32];
        let (cred_id, mut enrollment, sig_bytes) = make_sig(&op_hash);
        enrollment.provenance = synced(0x01);
        let validator = WebAuthnValidator::new(
            [0xCCu8; 20],
            WebAuthnRelyingParty::Origin(ORIGIN.to_string()),
        );
        let account = vec![0x02; 20];
        enroll_hybrid(&validator, account.clone(), cred_id, enrollment);
        let (cred_same, mut same_provider, _) = make_sig(&op_hash);
        same_provider.provenance = synced(0x01);
        enroll_hybrid(&validator, account.clone(), cred_same, same_provider);
        assert_eq!(validator.independent_roots(&account), 1);
        let op = dummy_user_op(account.clone(), sig_bytes);
        assert!(
            validator
                .validate_user_op(&op, &op_hash)
                .unwrap()
                .is_failure()
        );

        let (cred_other, mut other_provider, _) = make_sig(&op_hash);
        other_provider.provenance = synced(0x02);
        enroll_hybrid(&validator, account.clone(), cred_other, other_provider);
        assert_eq!(validator.independent_roots(&account), 2);
        assert!(
            !validator
                .validate_user_op(&op, &op_hash)
                .unwrap()
                .is_failure()
        );
    }

    #[test]
    fn integrates_with_validator_registry() {
        // Install WebAuthnValidator into a ValidatorRegistry and route a
        // UserOp through it.
        let op_hash = [0x42u8; 32];
        let (cred_id, enrollment, sig_bytes) = make_sig(&op_hash);

        let module_addr = [0x77u8; 20];
        let validator = WebAuthnValidator::new(
            module_addr,
            WebAuthnRelyingParty::Origin(ORIGIN.to_string()),
        );
        let account = vec![0x01; 20];
        enroll_hybrid(&validator, account.clone(), cred_id, enrollment);
        add_second_root(&validator, &account);

        let registry = ValidatorRegistry::new();
        // Attest the module so ERC-7484 install gate passes.
        registry.attestations().attest(ModuleAttestation {
            module_address: module_addr,
            module_type: ModuleType::Validator,
            registry: *registry.trusted_registry(),
            attester: [0xAA; 20],
            attestation_data: b"webauthn-audit-pass".to_vec(),
            revoked: false,
        });
        let module: Arc<dyn IValidator> = Arc::new(validator);
        registry
            .install(account.clone(), ModuleType::Validator, module, 100, vec![])
            .unwrap();

        let op = dummy_user_op(account, sig_bytes);
        let result = registry.validate_user_op(&op, &op_hash).unwrap();
        assert!(!result.is_failure());
    }

    #[test]
    fn multi_credential_per_account_dispatches_correctly() {
        // Enroll TWO credentials on the SAME account. Each produces a
        // distinct signature. The validator must accept either when
        // presented under its own credential_id and reject one when
        // presented under the other's credential_id.
        let op_hash_a = [0xA1u8; 32];
        let (cred_id_a, key_a, sig_a) = make_sig(&op_hash_a);
        let op_hash_b = [0xB2u8; 32];
        let (cred_id_b, key_b, sig_b) = make_sig(&op_hash_b);
        assert_ne!(cred_id_a, cred_id_b);

        let validator = WebAuthnValidator::new(
            [0xCCu8; 20],
            WebAuthnRelyingParty::Origin(ORIGIN.to_string()),
        );
        let account = vec![0x01; 20];
        enroll_hybrid(&validator, account.clone(), cred_id_a.clone(), key_a);
        enroll_hybrid(&validator, account.clone(), cred_id_b.clone(), key_b);
        assert_eq!(validator.enrolled_credential_count(&account), 2);
        assert_eq!(validator.list_credentials(&account).len(), 2);

        // Each signature validates against its own op_hash.
        let op_a = dummy_user_op(account.clone(), sig_a.clone());
        assert!(
            !validator
                .validate_user_op(&op_a, &op_hash_a)
                .unwrap()
                .is_failure()
        );
        let op_b = dummy_user_op(account.clone(), sig_b);
        assert!(
            !validator
                .validate_user_op(&op_b, &op_hash_b)
                .unwrap()
                .is_failure()
        );

        // Revoking credential A: signature A no longer validates, but
        // credential B is unaffected — the account is still usable.
        assert!(validator.revoke_credential(&account, &cred_id_a).unwrap());
        let op_a_again = dummy_user_op(account.clone(), sig_a);
        assert!(
            validator
                .validate_user_op(&op_a_again, &op_hash_a)
                .unwrap()
                .is_failure(),
            "revoked credential A must no longer validate"
        );
        // B still works.
        assert_eq!(validator.enrolled_credential_count(&account), 1);
    }

    #[test]
    fn two_credential_policy_requires_both_signatures() {
        let op_hash = [0x42u8; 32];
        let (cred_a, key_a, leg_a) = make_leg(&op_hash);
        let (cred_b, key_b, leg_b) = make_leg(&op_hash);
        assert_ne!(cred_a, cred_b);

        let validator = WebAuthnValidator::new(
            [0xCCu8; 20],
            WebAuthnRelyingParty::Origin(ORIGIN.to_string()),
        );
        let account = vec![0x01; 20];
        enroll_hybrid(&validator, account.clone(), cred_a, key_a);
        enroll_hybrid(&validator, account.clone(), cred_b, key_b);
        validator
            .set_second_factor_policy(account.clone(), SecondFactorPolicy::TwoCredentials)
            .unwrap();
        assert_eq!(
            validator.second_factor_policy(&account),
            SecondFactorPolicy::TwoCredentials
        );

        // Both credentials signing the same op hash → success.
        let both = PasskeySignature::encode_bundle(&[leg_a.clone(), leg_b.clone()]).unwrap();
        let op = dummy_user_op(account.clone(), both);
        assert!(
            !validator
                .validate_user_op(&op, &op_hash)
                .unwrap()
                .is_failure()
        );

        // A single credential no longer satisfies the policy.
        let single = PasskeySignature::encode_bundle(std::slice::from_ref(&leg_a)).unwrap();
        let op_single = dummy_user_op(account.clone(), single);
        assert!(
            validator
                .validate_user_op(&op_single, &op_hash)
                .unwrap()
                .is_failure(),
            "one signature must not satisfy a two-credential policy"
        );

        // The same credential twice is not two factors.
        let duplicated = PasskeySignature::encode_bundle(&[leg_a.clone(), leg_a]).unwrap();
        let op_dup = dummy_user_op(account.clone(), duplicated);
        assert!(
            validator
                .validate_user_op(&op_dup, &op_hash)
                .unwrap()
                .is_failure(),
            "duplicate credential ids must fail"
        );

        // Over-supplying against the default single-credential policy also
        // fails: exact count is enforced both ways.
        let other_account = vec![0x02; 20];
        let (cred_c, key_c, leg_c) = make_leg(&op_hash);
        let (cred_d, key_d, leg_d) = make_leg(&op_hash);
        enroll_hybrid(&validator, other_account.clone(), cred_c, key_c);
        enroll_hybrid(&validator, other_account.clone(), cred_d, key_d);
        let two_on_single = PasskeySignature::encode_bundle(&[leg_c, leg_d]).unwrap();
        let op_two = dummy_user_op(other_account, two_on_single);
        assert!(
            validator
                .validate_user_op(&op_two, &op_hash)
                .unwrap()
                .is_failure(),
            "two signatures must not satisfy a single-credential policy"
        );
    }

    #[test]
    fn no_op_validator_does_not_collide() {
        let _ = NoOpValidator::new([0; 20]);
    }
}
