//! Hardware-held signatures for accounts, guardians and machine identities.
//!
//! Every signature is made by a key that never leaves hardware:
//!
//! - The classical leg is ECDSA over P-256, from a TPM, the Secure Enclave or
//!   a passkey. It arrives in one of two forms ([`ClassicalProof`]): raw
//!   `r || s` from a TPM or Secure Enclave, or a WebAuthn assertion from a
//!   passkey.
//! - The post-quantum leg is ML-DSA-65 held in hardware (the Secure Enclave
//!   where the OS provides it, or a TPM that implements ML-DSA). It is
//!   optional: an account without hardware ML-DSA signs with P-256 alone, and
//!   a key added later by rotation does not change the account address.
//!
//! Both legs sign the same message representative
//!
//! ```text
//! M' = Prefix || Label || len(ctx) || ctx || SHA-512(M)
//! ```
//!
//! with `Label = COMPSIG-MLDSA65-ECDSA-P256-SHA512`. The P-256 leg is ECDSA
//! with SHA-256 over `M'` (raw form), or a WebAuthn assertion whose challenge
//! is `base64url(SHA-256(M'))` (passkey form). The ML-DSA leg is ML-DSA-65
//! over `M'` with the label as its FIPS 204 context, so it never verifies as a
//! standalone ML-DSA signature or as a leg of another protocol.
//!
//! Whether the ML-DSA leg must be present is the verifier's decision
//! ([`PqPolicy`]): chain policy can require it for chosen classes of
//! operation. When it is present it is always checked.

use crate::error::{CryptoError, Result};
use crate::keys::Address;
use crate::p256::{P256Signature, P256Verifier};
use crate::pq::ML_DSA_65_VK_LEN;
use crate::webauthn::{
    WebAuthnAssertion, WebAuthnCeremonyType, WebAuthnRelyingParty,
    verify_webauthn_assertion_require_uv,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};

/// Fixed prefix of every composite message representative.
pub const COMPOSITE_PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";

/// Label for ML-DSA-65 paired with ECDSA over P-256, SHA-512 pre-hash
/// (id-MLDSA65-ECDSA-P256-SHA512). Also the FIPS 204 context of the ML-DSA
/// leg.
pub const LABEL_MLDSA65_P256: &[u8] = b"COMPSIG-MLDSA65-ECDSA-P256-SHA512";

/// The protocol a composite signature is minted for.
///
/// The context string is bound into the message representative, so a
/// signature produced under one context never verifies under another. Every
/// protocol that verifies composite signatures names its own variant; there is
/// deliberately no "generic" context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureContext {
    /// A ledger transaction (`Transaction::hash()` is the message).
    Transaction,
    /// A signed revocation entry (identity, HTTP signing key, or shared
    /// payment token) broadcast on the revocation topic.
    IdentityRevocation,
    /// A W3C verifiable-credential proof.
    Credential,
    /// An agent-to-agent message.
    AgentMessage,
    /// An x402 `tenzro-hybrid` payment authorization.
    X402Payment,
    /// An x402 `upto` authorization of a maximum amount.
    X402Upto,
    /// An x402 batch-settlement channel voucher.
    X402BatchVoucher,
    /// An MPP payment credential.
    MppPayment,
    /// A cumulative voucher inside an MPP streaming session.
    MppVoucher,
    /// An ERC-4337 user operation validated by the hybrid ERC-7579 validator.
    UserOperation,
    /// An ERC-1271 message hash approved on behalf of a smart account.
    SmartAccountMessage,
    /// A TEE-produced ZK proof commitment.
    TeeZkCommitment,
    /// An arbitrary message signed by a wallet
    /// (checked by `tenzro_verifySignature`).
    SignedMessage,
    /// Proof that the caller owns an account, for RPCs that act on the
    /// account's behalf without a ledger transaction.
    AccountOwner,
    /// A payer's authorization of an HTTP-402 payment, settled on the ledger.
    PaymentAuthorization,
    /// A seller's signed x402 payment offer.
    X402Offer,
    /// A meter's signed usage record.
    UsageRecord,
    /// A seller's signed sealed delivery.
    DvpDelivery,
    /// A committee member's vote on an inference challenge.
    ChallengeVote,
    /// A guardian's approval of an account recovery.
    RecoveryApproval,
    /// A payer's cumulative voucher against an on-chain escrow.
    EscrowVoucher,
    /// A meter's consent to the account that posts its bond.
    MeterBondConsent,
    /// Proof of possession of an ML-DSA-65 key an account enrolls.
    PqKeyEnrollment,
    /// A controller key's signature over an identity registration.
    IdentityRegistration,
    /// An attestor's signature over a reserve attestation.
    ReserveAttestation,
    /// A device's signature over a sensor reading it measured.
    SensorReading,
    /// The sealing owner's signature over a sealed model's manifest.
    SealedModelManifest,
    /// A DID envelope authorizing one protocol method call.
    DidEnvelope,
    /// A node identity's certificate over an in-memory session key.
    SessionCertificate,
    /// The Merkle root of a batch of messages, signed by the hardware identity key.
    BatchRoot,
    /// An operator's receipt key binding itself to the operator's DID.
    ReceiptKeyBinding,
    /// A node identity's checkpoint over the head of its administrative
    /// audit log.
    AdminAuditCheckpoint,
}

impl SignatureContext {
    /// The context string placed in the message representative.
    pub const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Transaction => b"tenzro/tx",
            Self::IdentityRevocation => b"tenzro/identity/revocation",
            Self::Credential => b"tenzro/credential",
            Self::AgentMessage => b"tenzro/agent/message",
            Self::X402Payment => b"tenzro/x402",
            Self::X402Upto => b"tenzro/x402/upto",
            Self::X402BatchVoucher => b"tenzro/x402/batch-voucher",
            Self::MppPayment => b"tenzro/mpp",
            Self::MppVoucher => b"tenzro/mpp/voucher",
            Self::UserOperation => b"tenzro/aa/userop",
            Self::SmartAccountMessage => b"tenzro/aa/erc1271",
            Self::TeeZkCommitment => b"tenzro/tee-zk",
            Self::SignedMessage => b"tenzro/signed-message",
            Self::AccountOwner => b"tenzro/rpc/account-owner",
            Self::PaymentAuthorization => b"tenzro/payment/authorization",
            Self::X402Offer => b"tenzro/x402/offer",
            Self::UsageRecord => b"tenzro/metering/usage-record",
            Self::DvpDelivery => b"tenzro/dvp/delivery",
            Self::ChallengeVote => b"tenzro/inference/challenge-vote",
            Self::RecoveryApproval => b"tenzro/identity/recovery-approval",
            Self::EscrowVoucher => b"tenzro/escrow/voucher",
            Self::MeterBondConsent => b"tenzro/metering/bond-consent",
            Self::PqKeyEnrollment => b"tenzro/account/pq-key-enrollment",
            Self::IdentityRegistration => b"tenzro/identity/registration",
            Self::ReserveAttestation => b"tenzro/token/reserve-attestation",
            Self::SensorReading => b"tenzro/dispute/sensor-reading",
            Self::SealedModelManifest => b"tenzro/model/sealed-manifest",
            Self::DidEnvelope => b"tenzro/did-envelope",
            Self::SessionCertificate => b"tenzro/session/certificate",
            Self::BatchRoot => b"tenzro/session/batch-root",
            Self::ReceiptKeyBinding => b"tenzro/trust/receipt-key-binding",
            Self::AdminAuditCheckpoint => b"tenzro/node/admin-audit-checkpoint",
        }
    }
}

/// Builds the message representative `M'` that both legs sign.
pub fn message_representative(context: SignatureContext, message: &[u8]) -> Vec<u8> {
    message_representative_for(
        tenzro_types::signature_scheme::SignatureScheme::default(),
        context,
        message,
    )
}

/// [`message_representative`] under `scheme`'s label.
pub fn message_representative_for(
    scheme: tenzro_types::signature_scheme::SignatureScheme,
    context: SignatureContext,
    message: &[u8],
) -> Vec<u8> {
    let label = scheme.label();
    let ctx = context.as_bytes();
    let ph = Sha512::digest(message);
    let mut out =
        Vec::with_capacity(COMPOSITE_PREFIX.len() + label.len() + 1 + ctx.len() + ph.len());
    out.extend_from_slice(COMPOSITE_PREFIX);
    out.extend_from_slice(label);
    // Context strings are compile-time constants well under 255 bytes.
    out.push(ctx.len() as u8);
    out.extend_from_slice(ctx);
    out.extend_from_slice(&ph);
    out
}

/// The 32-byte digest the P-256 leg signs: `SHA-256(M')`. A TPM or Secure
/// Enclave signs it as a prehash; a passkey receives it as its challenge.
pub fn signing_digest(context: SignatureContext, message: &[u8]) -> [u8; 32] {
    Sha256::digest(message_representative(context, message)).into()
}

/// The WebAuthn challenge a passkey signs for `message` under `context`:
/// `base64url(SHA-256(M'))` without padding.
pub fn webauthn_challenge(context: SignatureContext, message: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signing_digest(context, message))
}

pub use tenzro_types::account_signature::{ClassicalProof, CompositeSignature};

/// The public keys of an account, guardian or machine identity: the P-256 key
/// that names it and, once enrolled, its hardware ML-DSA-65 key.
///
/// JSON carries hex fields and omits an absent ML-DSA-65 key; binary
/// encodings (bincode) carry the raw bytes and always both fields, since a
/// skipped field cannot be decoded there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompositePublicKey {
    /// Uncompressed P-256 point `x || y` (64 bytes).
    pub p256: Vec<u8>,
    /// ML-DSA-65 verifying key (1952 bytes), when enrolled.
    pub pq: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct CompositePublicKeyText {
    #[serde(with = "hex_bytes")]
    p256: Vec<u8>,
    #[serde(
        default,
        with = "opt_hex_bytes",
        skip_serializing_if = "Option::is_none"
    )]
    pq: Option<Vec<u8>>,
}

impl Serialize for CompositePublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            CompositePublicKeyText {
                p256: self.p256.clone(),
                pq: self.pq.clone(),
            }
            .serialize(s)
        } else {
            (&self.p256, &self.pq).serialize(s)
        }
    }
}

impl<'de> Deserialize<'de> for CompositePublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let (p256, pq) = if d.is_human_readable() {
            let t = CompositePublicKeyText::deserialize(d)?;
            (t.p256, t.pq)
        } else {
            <(Vec<u8>, Option<Vec<u8>>)>::deserialize(d)?
        };
        Ok(Self { p256, pq })
    }
}

impl CompositePublicKey {
    /// Validates the encodings: a 64-byte P-256 point on the curve and, if
    /// given, a 1952-byte ML-DSA-65 key.
    pub fn new(p256: Vec<u8>, pq: Option<Vec<u8>>) -> Result<Self> {
        P256Verifier::from_public_key_bytes(&p256)?;
        if let Some(vk) = pq.as_ref()
            && vk.len() != ML_DSA_65_VK_LEN
        {
            return Err(CryptoError::InvalidPublicKey(format!(
                "ML-DSA-65 verifying key must be {ML_DSA_65_VK_LEN} bytes, got {}",
                vk.len()
            )));
        }
        Ok(Self { p256, pq })
    }

    /// The ledger account this key names. See [`account_address`].
    pub fn account_address(&self) -> Address {
        account_address(&self.p256)
    }

    /// [`Self::account_address`] in the 32-byte account slot.
    pub fn account_slot(&self) -> [u8; 32] {
        account_slot(&self.p256)
    }
}

/// Domain string of ledger account address derivation.
const ACCOUNT_ADDRESS_DOMAIN: &[u8] = b"tenzro/account";

/// Key type tag of a P-256 account key in the address preimage.
const ACCOUNT_KEY_P256: u8 = 2;

/// The ledger account address of a P-256 key:
///
/// ```text
/// SHA-256("tenzro/account" || 0x02 || 0x40 || x || y)[..20]
/// ```
///
/// The address commits to the P-256 key only, so enrolling or rotating the
/// ML-DSA-65 key never moves an account.
pub fn account_address(p256_xy: &[u8]) -> Address {
    let mut h = Sha256::new();
    h.update(ACCOUNT_ADDRESS_DOMAIN);
    h.update([ACCOUNT_KEY_P256]);
    h.update([p256_xy.len() as u8]);
    h.update(p256_xy);
    let digest = h.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[..20]);
    Address::new(out)
}

/// [`account_address`] in the ledger's 32-byte account slot: the 20-byte
/// address followed by 12 zero bytes.
pub fn account_slot(p256_xy: &[u8]) -> [u8; 32] {
    let mut slot = [0u8; 32];
    slot[..20].copy_from_slice(account_address(p256_xy).as_bytes());
    slot
}

/// Whether `from` names the account of `p256_xy`, as a 20-byte address or as
/// the 32-byte account slot. Constant time in the key material.
pub fn controls_account(p256_xy: &[u8], from: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    let slot = account_slot(p256_xy);
    match from.len() {
        20 => bool::from(slot[..20].ct_eq(from)),
        32 => bool::from(slot.ct_eq(from)),
        _ => false,
    }
}

/// Whether the verifier demands the ML-DSA-65 leg. The default is
/// [`PqPolicy::Required`]: an account's signature is accepted only with its
/// ML-DSA-65 leg, verified against the key the account enrolled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PqPolicy {
    /// The ML-DSA-65 leg is required exactly when the key has one enrolled; a
    /// key with only P-256 signs with P-256 alone. For keys that are not
    /// accounts holding value (machine records, attestor and session keys).
    WhenPresent,
    /// Must be present and verify against the enrolled ML-DSA-65 key.
    #[default]
    Required,
}

/// Which legs a verified signature carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedLegs {
    /// The ML-DSA-65 leg was present and verified.
    pub pq: bool,
}

/// Verifies the P-256 leg on its own, for records whose wire format carries
/// only that leg. No relying party is fixed for the network: a passkey
/// assertion is checked against the relying party it names (see
/// [`crate::webauthn::verify_webauthn_assertion_for_asserted_rp`]); a passkey a keystore records under a
/// relying party is checked with [`verify_classical_component_for`].
pub fn verify_classical_component(
    p256_xy: &[u8],
    context: SignatureContext,
    message: &[u8],
    proof: &ClassicalProof,
) -> Result<()> {
    verify_classical_with(None, p256_xy, context, message, proof)
}

/// [`verify_classical_component`] for a passkey registered on `rp_id`: the
/// assertion's `rpIdHash` must be `SHA-256(rp_id)` and its origin `rp_id` or
/// a subdomain of it, over https. No list of related origins applies, so no
/// site has to vouch for another.
pub fn verify_classical_component_for(
    rp_id: &str,
    p256_xy: &[u8],
    context: SignatureContext,
    message: &[u8],
    proof: &ClassicalProof,
) -> Result<()> {
    let relying_party = WebAuthnRelyingParty::RegistrableDomain {
        rp_id: rp_id.to_string(),
        related_origins: Vec::new(),
    };
    verify_classical_with(Some(&relying_party), p256_xy, context, message, proof)
}

/// `relying_party` is `None` for a passkey no record pins to one.
fn verify_classical_with(
    relying_party: Option<&WebAuthnRelyingParty>,
    p256_xy: &[u8],
    context: SignatureContext,
    message: &[u8],
    proof: &ClassicalProof,
) -> Result<()> {
    let digest = signing_digest(context, message);
    match proof {
        ClassicalProof::Raw { signature } => {
            let sig = if signature.len() == 64 {
                P256Signature::from_slice(signature)?
            } else {
                P256Signature::from_bytes(crate::webauthn::unwrap_der_signature(signature)?)
            };
            P256Verifier::from_public_key_bytes(p256_xy)?.verify_prehash(&digest, &sig)
        }
        ClassicalProof::WebAuthn {
            authenticator_data,
            client_data_json,
            signature,
        } => {
            use base64::Engine as _;
            let assertion = WebAuthnAssertion {
                authenticator_data: authenticator_data.clone(),
                client_data_json: client_data_json.clone(),
                signature: signature.clone(),
                user_handle: None,
            };
            let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
            match relying_party {
                Some(rp) => verify_webauthn_assertion_require_uv(
                    &assertion,
                    p256_xy,
                    &challenge,
                    rp,
                    WebAuthnCeremonyType::Get,
                ),
                None => crate::webauthn::verify_webauthn_assertion_for_asserted_rp(
                    &assertion,
                    p256_xy,
                    &challenge,
                    WebAuthnCeremonyType::Get,
                ),
            }
        }
    }
}

/// Verifies a signature against the keys of an account, guardian or machine
/// identity.
///
/// The P-256 leg always verifies. An ML-DSA-65 leg, when present, verifies
/// against the enrolled ML-DSA-65 key (a leg with no enrolled key is refused).
/// Once a key has an ML-DSA-65 key enrolled, the hybrid is mandatory for it: a
/// signature without the ML-DSA-65 leg is refused whatever the policy, so a
/// forger of the P-256 leg cannot strip the other one. Removing or replacing
/// the enrolled key therefore takes a hybrid-signed rotation. Under
/// [`PqPolicy::Required`] a key with no ML-DSA-65 key enrolled is refused.
pub fn verify_composite(
    public_key: &CompositePublicKey,
    context: SignatureContext,
    message: &[u8],
    sig: &CompositeSignature,
    policy: PqPolicy,
) -> Result<VerifiedLegs> {
    verify_classical_component(&public_key.p256, context, message, &sig.classical)?;
    verify_pq_component(
        public_key.pq.as_deref(),
        context,
        message,
        sig.pq.as_deref(),
        policy,
    )
}

/// [`verify_composite`] with a passkey leg checked against `rp_id`, the
/// relying party a keystore records the passkey under (see
/// [`verify_classical_component_for`]).
pub fn verify_composite_for(
    rp_id: &str,
    public_key: &CompositePublicKey,
    context: SignatureContext,
    message: &[u8],
    sig: &CompositeSignature,
    policy: PqPolicy,
) -> Result<VerifiedLegs> {
    verify_classical_component_for(rp_id, &public_key.p256, context, message, &sig.classical)?;
    verify_pq_component(
        public_key.pq.as_deref(),
        context,
        message,
        sig.pq.as_deref(),
        policy,
    )
}

/// Verifies the ML-DSA-65 leg on its own against the key enrolled for the
/// signer (`None` when it has none), for a verifier that checked the P-256
/// leg separately. The rules are those of [`verify_composite`]: an enrolled
/// key makes the leg mandatory, and a leg with no enrolled key is refused.
pub fn verify_pq_component(
    enrolled: Option<&[u8]>,
    context: SignatureContext,
    message: &[u8],
    pq_sig: Option<&[u8]>,
    policy: PqPolicy,
) -> Result<VerifiedLegs> {
    match (pq_sig, enrolled) {
        (Some(pq_sig), Some(vk)) => {
            use tenzro_types::signature_scheme::SignatureScheme;
            let (scheme, key) = SignatureScheme::split_public_key(vk).ok_or_else(|| {
                CryptoError::InvalidPublicKey(
                    "the enrolled ML-DSA key names no known scheme".to_string(),
                )
            })?;
            let (signed_as, sig) = SignatureScheme::split_signature(pq_sig).ok_or_else(|| {
                CryptoError::InvalidSignature("the ML-DSA leg names no known scheme".to_string())
            })?;
            if signed_as != scheme {
                return Err(CryptoError::InvalidSignature(
                    "the ML-DSA leg is of another scheme than the enrolled key".to_string(),
                ));
            }
            // An account's classical leg is P-256, so its ML-DSA leg is the
            // ML-DSA-65 half of the ML-DSA-65 / P-256 composite.
            if scheme != SignatureScheme::default() {
                return Err(CryptoError::InvalidSignature(
                    "an account's ML-DSA key is ML-DSA-65".to_string(),
                ));
            }
            let m_prime = message_representative_for(scheme, context, message);
            crate::pq::ml_dsa_verify_scheme(scheme, key, scheme.label(), &m_prime, sig)?;
            Ok(VerifiedLegs { pq: true })
        }
        (Some(_), None) => Err(CryptoError::InvalidSignature(
            "ML-DSA-65 leg present for a key with no ML-DSA-65 key enrolled".to_string(),
        )),
        (None, Some(_)) => Err(CryptoError::InvalidSignature(
            "this key has an ML-DSA-65 key enrolled, so every signature must carry the ML-DSA-65 leg"
                .to_string(),
        )),
        (None, None) if policy == PqPolicy::Required => Err(CryptoError::InvalidSignature(
            "this operation requires the hardware ML-DSA-65 leg".to_string(),
        )),
        (None, None) => Ok(VerifiedLegs { pq: false }),
    }
}

/// A hardware signer: produces the P-256 leg and, where the hardware holds
/// one, the ML-DSA-65 leg. Implemented over a TPM, the Secure Enclave or a
/// passkey; there is no software implementation outside tests.
pub trait HybridSigner: Send + Sync {
    /// Signs `msg` for `context`.
    fn sign(&self, context: SignatureContext, msg: &[u8]) -> Result<CompositeSignature>;
    /// The signer's public keys.
    fn public_key(&self) -> &CompositePublicKey;
    /// A plain P-256 (ES256) signature over `SHA-256(data)`, `r || s`, for
    /// external protocols that verify their own canonical bytes (HTTP message
    /// signatures, JWS). Implementations refuse `data` that begins with
    /// [`COMPOSITE_PREFIX`], so the result can never stand in for the P-256
    /// leg of a composite signature.
    fn sign_external(&self, data: &[u8]) -> Result<Vec<u8>>;
}

/// Refuses external signing input that could pass for a composite message
/// representative.
pub fn check_external_input(data: &[u8]) -> Result<[u8; 32]> {
    if data.starts_with(COMPOSITE_PREFIX) {
        return Err(CryptoError::InvalidSignature(
            "external signing input may not begin with the composite prefix".to_string(),
        ));
    }
    Ok(Sha256::digest(data).into())
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s.trim_start_matches("0x")).map_err(serde::de::Error::custom)
    }
}

mod opt_hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match b {
            Some(b) => s.serialize_str(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| hex::decode(s.trim_start_matches("0x")).map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// An in-memory signer for other crates' tests. Built only with the
/// `test-keys` feature, which is enabled from `[dev-dependencies]` alone.
#[cfg(any(test, feature = "test-keys"))]
pub mod testing {
    use super::*;
    use crate::p256::{P256KeyPair, P256Signer};
    use crate::pq::MlDsaSigningKey;

    /// A P-256 key and, optionally, an ML-DSA-65 key, both in memory.
    pub struct TestHybridSigner {
        p256: P256Signer,
        pq: Option<MlDsaSigningKey>,
        public: CompositePublicKey,
    }

    impl TestHybridSigner {
        /// A P-256-only signer from a fixed seed.
        pub fn p256_only(seed: u8) -> Self {
            Self::build(seed, false)
        }

        /// A hybrid signer from a fixed seed.
        pub fn hybrid(seed: u8) -> Self {
            Self::build(seed, true)
        }

        /// A fresh random P-256-only signer.
        pub fn random() -> Self {
            let kp = P256KeyPair::generate();
            Self::from_parts(&kp, None)
        }

        fn build(seed: u8, with_pq: bool) -> Self {
            // Hashed, so every seed gives a scalar below the group order.
            let secret: [u8; 32] =
                sha2::Sha256::digest([b"tenzro/test-signer/".as_slice(), &[seed]].concat()).into();
            let kp = P256KeyPair::from_secret_bytes(&secret).expect("valid test scalar");
            let pq = with_pq.then(|| MlDsaSigningKey::from_seed(&[seed; 32]).expect("seed"));
            Self::from_parts(&kp, pq)
        }

        fn from_parts(kp: &P256KeyPair, pq: Option<MlDsaSigningKey>) -> Self {
            let public = CompositePublicKey::new(
                kp.public_key_bytes().to_vec(),
                pq.as_ref().map(|k| k.verifying_key_bytes().to_vec()),
            )
            .expect("valid test keys");
            Self {
                p256: P256Signer::from_keypair(kp),
                pq,
                public,
            }
        }

        /// The ML-DSA-65 key that [`TestHybridSigner::hybrid`] pairs with
        /// `p256_xy`, for tests that model it as the account's enrolled key.
        /// Seeds `1..=255`; a `p256_only` signer of the same seed shares the
        /// P-256 key, so tests that enroll by seed use `hybrid` signers.
        pub fn hybrid_pq_key(p256_xy: &[u8]) -> Option<Vec<u8>> {
            use std::collections::HashMap;
            use std::sync::OnceLock;
            static BY_P256: OnceLock<HashMap<Vec<u8>, Vec<u8>>> = OnceLock::new();
            BY_P256
                .get_or_init(|| {
                    (1..=255u8)
                        .map(|seed| {
                            let s = Self::hybrid(seed);
                            (s.public.p256.clone(), s.public.pq.clone().expect("hybrid"))
                        })
                        .collect()
                })
                .get(p256_xy)
                .cloned()
        }

        /// The ledger account this signer controls, in its 32-byte slot.
        pub fn address(&self) -> tenzro_types::primitives::Address {
            tenzro_types::primitives::Address::new(self.public.account_slot())
        }

        /// The P-256 leg alone, in raw form.
        pub fn sign_classical(&self, context: SignatureContext, msg: &[u8]) -> ClassicalProof {
            ClassicalProof::Raw {
                signature: self
                    .p256
                    .sign_prehash(&signing_digest(context, msg))
                    .as_bytes()
                    .to_vec(),
            }
        }

        /// The P-256 leg as a passkey assertion registered on `tenzro.com`
        /// and made at `https://tenzro.com`, with the given
        /// `authenticatorData` flags byte.
        pub fn sign_passkey(
            &self,
            flags: u8,
            context: SignatureContext,
            msg: &[u8],
        ) -> ClassicalProof {
            self.sign_passkey_at("tenzro.com", "https://tenzro.com", flags, context, msg)
        }

        /// A passkey assertion on `tenzro.com` as the P-256 leg and, when the
        /// signer holds an ML-DSA-65 key, that key's signature as the second
        /// leg, as an enrolled passkey signs.
        pub fn sign_passkey_composite(
            &self,
            flags: u8,
            context: SignatureContext,
            msg: &[u8],
        ) -> CompositeSignature {
            let classical = self.sign_passkey(flags, context, msg);
            match &self.pq {
                Some(k) => CompositeSignature::hybrid(
                    classical,
                    k.sign(LABEL_MLDSA65_P256, &message_representative(context, msg)),
                ),
                None => CompositeSignature::classical(classical),
            }
        }

        /// The P-256 leg as a passkey assertion for the relying party
        /// `rp_id`, made at `origin`.
        pub fn sign_passkey_at(
            &self,
            rp_id: &str,
            origin: &str,
            flags: u8,
            context: SignatureContext,
            msg: &[u8],
        ) -> ClassicalProof {
            let mut authenticator_data = Sha256::digest(rp_id.as_bytes()).to_vec();
            authenticator_data.push(flags);
            authenticator_data.extend_from_slice(&[0, 0, 0, 1]);
            let client_data_json = format!(
                r#"{{"type":"webauthn.get","challenge":"{}","origin":"{origin}"}}"#,
                webauthn_challenge(context, msg)
            )
            .into_bytes();
            let hash =
                crate::webauthn::webauthn_signed_hash(&authenticator_data, &client_data_json);
            ClassicalProof::WebAuthn {
                authenticator_data,
                client_data_json,
                signature: self.p256.sign_prehash(&hash).as_bytes().to_vec(),
            }
        }
    }

    impl HybridSigner for TestHybridSigner {
        fn sign(&self, context: SignatureContext, msg: &[u8]) -> Result<CompositeSignature> {
            let classical = self.sign_classical(context, msg);
            Ok(match &self.pq {
                Some(k) => CompositeSignature::hybrid(
                    classical,
                    k.sign(LABEL_MLDSA65_P256, &message_representative(context, msg)),
                ),
                None => CompositeSignature::classical(classical),
            })
        }

        fn public_key(&self) -> &CompositePublicKey {
            &self.public
        }

        fn sign_external(&self, data: &[u8]) -> Result<Vec<u8>> {
            let digest = check_external_input(data)?;
            Ok(self.p256.sign_prehash(&digest).as_bytes().to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p256::{P256KeyPair, P256Signer};
    use crate::pq::MlDsaSigningKey;

    fn device() -> (P256KeyPair, P256Signer) {
        let kp = P256KeyPair::from_secret_bytes(&[7u8; 32]).unwrap();
        let signer = P256Signer::from_keypair(&kp);
        (kp, signer)
    }

    fn raw_sign(signer: &P256Signer, ctx: SignatureContext, msg: &[u8]) -> ClassicalProof {
        let sig = signer.sign_prehash(&signing_digest(ctx, msg));
        ClassicalProof::Raw {
            signature: sig.as_bytes().to_vec(),
        }
    }

    fn passkey_sign(
        signer: &P256Signer,
        rp_id: &str,
        origin: &str,
        flags: u8,
        ctx: SignatureContext,
        msg: &[u8],
    ) -> ClassicalProof {
        let mut authenticator_data = Sha256::digest(rp_id.as_bytes()).to_vec();
        authenticator_data.push(flags);
        authenticator_data.extend_from_slice(&[0, 0, 0, 1]);
        let client_data_json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{origin}"}}"#,
            webauthn_challenge(ctx, msg)
        )
        .into_bytes();
        let hash = crate::webauthn::webauthn_signed_hash(&authenticator_data, &client_data_json);
        let sig = signer.sign_prehash(&hash);
        ClassicalProof::WebAuthn {
            authenticator_data,
            client_data_json,
            signature: sig.as_bytes().to_vec(),
        }
    }

    const MSG: &[u8] = b"hwsign vector";

    #[test]
    fn address_and_digest_vectors() {
        let (kp, _) = device();
        let xy = kp.public_key_bytes();
        assert_eq!(
            hex::encode(xy),
            "1e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896e\
             a46c311c4e2ff40dd96a3653e6e45445d32dfe486eced75c7a90c6a18881c0a3"
        );
        assert_eq!(
            hex::encode(account_address(&xy).as_bytes()),
            "3cfe813c221f615a46e3030aead890806ce7a885"
        );
        assert_eq!(
            hex::encode(signing_digest(SignatureContext::Transaction, MSG)),
            "b6342001c4304ec6271cc325ae27f467347bed003b95a9fd04202ddf6fa7ebbe"
        );
    }

    #[test]
    fn enrolling_ml_dsa_does_not_move_the_account() {
        let (kp, _) = device();
        let pq = MlDsaSigningKey::from_seed(&[9u8; 32]).unwrap();
        let bare = CompositePublicKey::new(kp.public_key_bytes().to_vec(), None).unwrap();
        let hybrid = CompositePublicKey::new(
            kp.public_key_bytes().to_vec(),
            Some(pq.verifying_key_bytes().to_vec()),
        )
        .unwrap();
        assert_eq!(bare.account_address(), hybrid.account_address());
        assert!(controls_account(
            &kp.public_key_bytes(),
            &hybrid.account_slot()
        ));
        assert!(controls_account(
            &kp.public_key_bytes(),
            hybrid.account_address().as_bytes()
        ));
    }

    #[test]
    fn raw_p256_only() {
        let (kp, signer) = device();
        let pk = CompositePublicKey::new(kp.public_key_bytes().to_vec(), None).unwrap();
        let sig =
            CompositeSignature::classical(raw_sign(&signer, SignatureContext::Transaction, MSG));
        let legs = verify_composite(
            &pk,
            SignatureContext::Transaction,
            MSG,
            &sig,
            PqPolicy::WhenPresent,
        )
        .unwrap();
        assert!(!legs.pq);
        assert!(
            verify_composite(
                &pk,
                SignatureContext::Transaction,
                MSG,
                &sig,
                PqPolicy::Required
            )
            .is_err()
        );
        assert!(
            verify_composite(
                &pk,
                SignatureContext::Transaction,
                b"other",
                &sig,
                PqPolicy::WhenPresent
            )
            .is_err()
        );
        assert!(
            verify_composite(
                &pk,
                SignatureContext::SignedMessage,
                MSG,
                &sig,
                PqPolicy::WhenPresent
            )
            .is_err()
        );
    }

    #[test]
    fn passkey_form_scoped_to_the_rp_with_user_verification() {
        let (kp, signer) = device();
        let pk = CompositePublicKey::new(kp.public_key_bytes().to_vec(), None).unwrap();
        let key = kp.public_key_bytes();
        let tx = SignatureContext::Transaction;
        // No relying party is fixed for the network: a passkey no record pins
        // verifies on whichever provider's domain it was registered on.
        for (rp, origin) in [
            ("tenzro.com", "https://tenzro.com"),
            ("example.org", "https://example.org"),
            ("example.org", "https://wallet.example.org"),
        ] {
            let ok = passkey_sign(&signer, rp, origin, 0x05, tx, MSG);
            verify_composite(
                &pk,
                tx,
                MSG,
                &CompositeSignature::classical(ok),
                PqPolicy::WhenPresent,
            )
            .unwrap();
        }
        let no_uv = passkey_sign(&signer, "tenzro.com", "https://tenzro.com", 0x01, tx, MSG);
        assert!(verify_classical_component(&key, tx, MSG, &no_uv).is_err());
        // The authenticator's rpIdHash must name the origin or a parent of it.
        let foreign = passkey_sign(&signer, "tenzro.com", "https://example.com", 0x05, tx, MSG);
        assert!(verify_classical_component(&key, tx, MSG, &foreign).is_err());
        let bare_suffix = passkey_sign(&signer, "org", "https://example.org", 0x05, tx, MSG);
        assert!(verify_classical_component(&key, tx, MSG, &bare_suffix).is_err());
        let plain_http = passkey_sign(&signer, "example.org", "http://example.org", 0x05, tx, MSG);
        assert!(verify_classical_component(&key, tx, MSG, &plain_http).is_err());
        // A recorded relying party admits only itself.
        let other = passkey_sign(&signer, "example.org", "https://example.org", 0x05, tx, MSG);
        verify_classical_component_for("example.org", &key, tx, MSG, &other).unwrap();
        assert!(verify_classical_component_for("tenzro.com", &key, tx, MSG, &other).is_err());
    }

    #[test]
    fn hybrid_legs() {
        let (kp, signer) = device();
        let pq = MlDsaSigningKey::from_seed(&[9u8; 32]).unwrap();
        let pk = CompositePublicKey::new(
            kp.public_key_bytes().to_vec(),
            Some(pq.verifying_key_bytes().to_vec()),
        )
        .unwrap();
        let ctx = SignatureContext::RecoveryApproval;
        let m_prime = message_representative(ctx, MSG);
        let pq_sig = pq.sign(LABEL_MLDSA65_P256, &m_prime);
        let sig = CompositeSignature::hybrid(raw_sign(&signer, ctx, MSG), pq_sig.clone());
        assert!(
            verify_composite(&pk, ctx, MSG, &sig, PqPolicy::Required)
                .unwrap()
                .pq
        );

        // A tampered ML-DSA leg fails even where it is optional.
        let mut bad = pq_sig.clone();
        bad[10] ^= 1;
        let tampered = CompositeSignature::hybrid(raw_sign(&signer, ctx, MSG), bad);
        assert!(verify_composite(&pk, ctx, MSG, &tampered, PqPolicy::WhenPresent).is_err());

        // The ML-DSA leg is not a standalone ML-DSA signature over M'.
        assert!(
            crate::pq::ml_dsa_verify(pq.verifying_key_bytes(), b"", &m_prime, &pq_sig).is_err()
        );

        // A leg for a key that never enrolled ML-DSA is refused.
        let bare = CompositePublicKey::new(kp.public_key_bytes().to_vec(), None).unwrap();
        assert!(verify_composite(&bare, ctx, MSG, &sig, PqPolicy::WhenPresent).is_err());

        // Once ML-DSA is enrolled, stripping its leg is refused under every policy.
        let stripped = CompositeSignature::classical(raw_sign(&signer, ctx, MSG));
        assert!(verify_composite(&pk, ctx, MSG, &stripped, PqPolicy::WhenPresent).is_err());
        assert!(verify_composite(&pk, ctx, MSG, &stripped, PqPolicy::Required).is_err());
    }

    #[test]
    fn rejects_bad_key_encodings() {
        assert!(CompositePublicKey::new(vec![1u8; 64], None).is_err());
        let (kp, _) = device();
        assert!(
            CompositePublicKey::new(kp.public_key_bytes().to_vec(), Some(vec![0u8; 10])).is_err()
        );
    }

    #[test]
    fn wire_form_round_trips() {
        let (_, signer) = device();
        let sig =
            CompositeSignature::classical(raw_sign(&signer, SignatureContext::Transaction, MSG));
        let json = serde_json::to_string(&sig).unwrap();
        assert!(json.contains(r#""form":"raw""#));
        assert_eq!(
            serde_json::from_str::<CompositeSignature>(&json).unwrap(),
            sig
        );
    }
}

#[cfg(test)]
mod fixture_tests {
    use super::*;

    #[derive(Deserialize)]
    struct Case {
        context: String,
        message_hex: String,
        m_prime_hex: String,
        signing_digest_hex: String,
        raw_signature_hex: String,
    }
    #[derive(Deserialize)]
    struct Vectors {
        p256_public_key_xy_hex: String,
        account_address_hex: String,
        cases: Vec<Case>,
    }

    fn context_named(name: &str) -> SignatureContext {
        [
            SignatureContext::Transaction,
            SignatureContext::RecoveryApproval,
            SignatureContext::SignedMessage,
        ]
        .into_iter()
        .find(|c| c.as_bytes() == name.as_bytes())
        .expect("context in the fixture")
    }

    /// The SDK fixture, signed by an independent implementation, verifies here.
    #[test]
    fn sdk_fixture_verifies() {
        let v: Vectors =
            serde_json::from_str(include_str!("../../../sdk/fixtures/hwsign/vectors.json"))
                .unwrap();
        let xy = hex::decode(&v.p256_public_key_xy_hex).unwrap();
        assert_eq!(
            hex::encode(account_address(&xy).as_bytes()),
            v.account_address_hex
        );
        let pk = CompositePublicKey::new(xy, None).unwrap();
        for c in v.cases {
            let ctx = context_named(&c.context);
            let msg = hex::decode(&c.message_hex).unwrap();
            assert_eq!(
                hex::encode(message_representative(ctx, &msg)),
                c.m_prime_hex
            );
            assert_eq!(hex::encode(signing_digest(ctx, &msg)), c.signing_digest_hex);
            let sig = CompositeSignature::classical(ClassicalProof::Raw {
                signature: hex::decode(&c.raw_signature_hex).unwrap(),
            });
            verify_composite(&pk, ctx, &msg, &sig, PqPolicy::WhenPresent).unwrap();
        }
    }
}
